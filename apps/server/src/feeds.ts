/**
 * Feed Ingestion Engine
 * Polls CISA KEV, URLhaus, and ThreatFox threat intelligence feeds
 * and upserts IOCs into the local SQLite database.
 */

import type { FeedName } from './types';
import { getSeverityFromConfidence } from './types';
import {
  upsertFeed,
  updateFeedStatus,
  upsertIOC,
  rebuildFTS,
  getFeeds,
  getStats,
} from './db';

// ---------------------------------------------------------------------------
// Feed configuration
// ---------------------------------------------------------------------------

const FEED_CONFIGS = [
  {
    name: 'cisa_kev' as FeedName,
    url:
      process.env.CISA_KEV_URL ||
      'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
  },
  {
    name: 'urlhaus' as FeedName,
    url: process.env.URLHAUS_URL || 'https://urlhaus-api.abuse.ch/v1/urls/recent/',
  },
  {
    name: 'threatfox' as FeedName,
    url: process.env.THREATFOX_URL || 'https://threatfox-api.abuse.ch/api/v1/',
  },
];

const POLL_INTERVAL_MS = parseInt(process.env.POLL_INTERVAL_MS || '3600000'); // 1 hour default

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Returns true when the value looks like a bare IPv4 address. */
function isIPAddress(host: string): boolean {
  return /^\d+\.\d+\.\d+\.\d+$/.test(host);
}

/** abuse.ch Auth-Key — register free at https://auth.abuse.ch/ */
const ABUSE_CH_AUTH_KEY = process.env.ABUSE_CH_AUTH_KEY || '';

/** Fetch with a 30-second timeout via AbortController. */
async function fetchWithTimeout(url: string, options: RequestInit = {}): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 30_000);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

// ---------------------------------------------------------------------------
// CISA Known Exploited Vulnerabilities (KEV) poller
// ---------------------------------------------------------------------------

async function pollCisaKev(feedId: number, url: string): Promise<number> {
  console.log('[feeds] Polling CISA KEV...');

  const response = await fetchWithTimeout(url);
  if (!response.ok) {
    throw new Error(`CISA KEV returned HTTP ${response.status}`);
  }

  const json = (await response.json()) as any;
  const vulnerabilities: any[] = json.vulnerabilities ?? [];

  let count = 0;

  for (const vuln of vulnerabilities) {
    const cveId: string = vuln.cveID ?? '';
    if (!cveId) continue;

    const severity = vuln.knownRansomwareCampaignUse === 'Known' ? 'critical' : 'high';
    const dateAdded = vuln.dateAdded ? new Date(vuln.dateAdded).getTime() : Date.now();

    const tags: string[] = [];
    if (vuln.vendorProject) tags.push(vuln.vendorProject);
    if (vuln.product) tags.push(vuln.product);

    upsertIOC(feedId, {
      ioc_type: 'cve',
      value: cveId,
      severity,
      title: vuln.vulnerabilityName ?? cveId,
      description: vuln.shortDescription ?? undefined,
      source_ref: `https://nvd.nist.gov/vuln/detail/${cveId}`,
      tags,
      first_seen: dateAdded,
      last_seen: dateAdded,
    });

    count++;
  }

  return count;
}

// ---------------------------------------------------------------------------
// URLhaus poller
// ---------------------------------------------------------------------------

async function pollUrlhaus(feedId: number, url: string): Promise<number> {
  console.log('[feeds] Polling URLhaus...');
  if (!ABUSE_CH_AUTH_KEY) {
    throw new Error('ABUSE_CH_AUTH_KEY not set — register free at https://auth.abuse.ch/');
  }

  const response = await fetchWithTimeout(url, {
    headers: { 'Auth-Key': ABUSE_CH_AUTH_KEY },
  });
  if (!response.ok) {
    throw new Error(`URLhaus returned HTTP ${response.status}`);
  }

  const json = (await response.json()) as any;
  const urls: any[] = json.urls ?? [];

  let count = 0;

  for (const entry of urls) {
    const urlValue: string = entry.url ?? '';
    if (!urlValue) continue;

    const threatType: string = entry.threat ?? '';
    const severity = threatType === 'malware_download' ? 'high' : 'medium';
    const tags: string[] = [];
    if (entry.url_status) tags.push(entry.url_status);
    if (threatType) tags.push(threatType);

    const dateAdded = entry.date_added ? new Date(entry.date_added).getTime() : Date.now();

    // Upsert the URL IOC
    upsertIOC(feedId, {
      ioc_type: 'url',
      value: urlValue,
      severity,
      tags,
      first_seen: dateAdded,
      last_seen: dateAdded,
    });
    count++;

    // Extract the host; if it is not a bare IP, also upsert a domain IOC
    try {
      const parsed = new URL(urlValue);
      const host = parsed.hostname;
      if (host && !isIPAddress(host)) {
        upsertIOC(feedId, {
          ioc_type: 'domain',
          value: host,
          severity,
          tags,
          first_seen: dateAdded,
          last_seen: dateAdded,
        });
        count++;
      }
    } catch {
      // Malformed URL — skip domain extraction
    }
  }

  return count;
}

// ---------------------------------------------------------------------------
// ThreatFox poller
// ---------------------------------------------------------------------------

async function pollThreatfox(feedId: number, url: string): Promise<number> {
  console.log('[feeds] Polling ThreatFox...');
  if (!ABUSE_CH_AUTH_KEY) {
    throw new Error('ABUSE_CH_AUTH_KEY not set — register free at https://auth.abuse.ch/');
  }

  const response = await fetchWithTimeout(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Auth-Key': ABUSE_CH_AUTH_KEY },
    body: JSON.stringify({ query: 'get_iocs', days: 7 }),
  });

  if (!response.ok) {
    throw new Error(`ThreatFox returned HTTP ${response.status}`);
  }

  const json = (await response.json()) as any;
  if (json.query_status !== 'ok') {
    throw new Error(`ThreatFox query_status: ${json.query_status}`);
  }

  const entries: any[] = json.data ?? [];
  let count = 0;

  for (const entry of entries) {
    const rawType: string = entry.ioc_type ?? '';
    const rawValue: string = entry.ioc ?? '';
    if (!rawValue) continue;

    // Map ThreatFox ioc_type to our IOCType
    let iocType: 'ip' | 'domain' | 'url' | 'hash' | 'email';
    let value = rawValue;

    switch (rawType) {
      case 'ip:port':
        iocType = 'ip';
        value = rawValue.split(':')[0]; // strip port
        break;
      case 'domain':
        iocType = 'domain';
        break;
      case 'url':
        iocType = 'url';
        break;
      case 'md5_hash':
      case 'sha256_hash':
        iocType = 'hash';
        break;
      case 'email':
        iocType = 'email';
        break;
      default:
        // Skip unknown types
        continue;
    }

    const confidence: number = entry.confidence_level ?? 0;
    const severity = getSeverityFromConfidence(confidence);

    const tags: string[] = [];
    if (entry.malware) tags.push(entry.malware);
    if (Array.isArray(entry.tags)) tags.push(...entry.tags);

    const firstSeen = entry.first_seen ? new Date(entry.first_seen).getTime() : Date.now();
    const lastSeen = entry.last_seen ? new Date(entry.last_seen).getTime() : firstSeen;

    upsertIOC(feedId, {
      ioc_type: iocType,
      value,
      severity,
      tags,
      first_seen: firstSeen,
      last_seen: lastSeen,
    });
    count++;
  }

  return count;
}

// ---------------------------------------------------------------------------
// Poll orchestration
// ---------------------------------------------------------------------------

/**
 * Ensure all feed config rows exist in the database.
 */
function initFeeds(): void {
  for (const cfg of FEED_CONFIGS) {
    upsertFeed(cfg.name, cfg.url);
  }
}

/**
 * Poll all three feeds concurrently, then rebuild the full-text search index.
 */
export async function pollAllFeeds(): Promise<void> {
  const start = Date.now();
  console.log(`[feeds] Starting poll cycle at ${new Date(start).toISOString()}`);

  // Build a map from feed name → database row id
  const feedRows = getFeeds();
  const feedIdByName: Record<string, number> = {};
  for (const row of feedRows) {
    feedIdByName[row.name] = row.id;
  }

  const pollers: Array<{ name: FeedName; fn: () => Promise<number> }> = [
    {
      name: 'cisa_kev',
      fn: () => {
        const cfg = FEED_CONFIGS.find((c) => c.name === 'cisa_kev')!;
        return pollCisaKev(feedIdByName['cisa_kev'], cfg.url);
      },
    },
    {
      name: 'urlhaus',
      fn: () => {
        const cfg = FEED_CONFIGS.find((c) => c.name === 'urlhaus')!;
        return pollUrlhaus(feedIdByName['urlhaus'], cfg.url);
      },
    },
    {
      name: 'threatfox',
      fn: () => {
        const cfg = FEED_CONFIGS.find((c) => c.name === 'threatfox')!;
        return pollThreatfox(feedIdByName['threatfox'], cfg.url);
      },
    },
  ];

  const results = await Promise.allSettled(
    pollers.map(async ({ name, fn }) => {
      try {
        const iocCount = await fn();
        updateFeedStatus(name, 'ok', { lastCount: iocCount });
        console.log(`[feeds] ${name}: ingested ${iocCount} IOCs`);
        return iocCount;
      } catch (err: any) {
        const msg = err instanceof Error ? err.message : String(err);
        console.error(`[feeds] ${name} failed: ${msg}`);
        updateFeedStatus(name, 'error', { errorMsg: msg });
        throw err;
      }
    }),
  );

  // Rebuild FTS index after all feeds have settled
  try {
    rebuildFTS();
    console.log('[feeds] FTS index rebuilt');
  } catch (err) {
    console.error('[feeds] FTS rebuild failed:', err);
  }

  const elapsed = ((Date.now() - start) / 1000).toFixed(1);
  const succeeded = results.filter((r) => r.status === 'fulfilled').length;
  const total = results
    .filter((r): r is PromiseFulfilledResult<number> => r.status === 'fulfilled')
    .reduce((sum, r) => sum + r.value, 0);

  const stats = getStats();
  console.log(
    `[feeds] Poll cycle complete in ${elapsed}s — ${succeeded}/${pollers.length} feeds OK, ` +
      `${total} IOCs this cycle, ${stats.totalIOCs} total in DB`,
  );
}

/**
 * Initialize feeds and start the polling scheduler.
 * Fires an immediate poll if any feed has never been polled or is stale.
 */
export function startFeedScheduler(): void {
  initFeeds();

  const now = Date.now();
  const feeds = getFeeds();
  const needsImmediatePoll = feeds.some((f) => {
    return !f.last_poll || now - f.last_poll > POLL_INTERVAL_MS;
  });

  if (needsImmediatePoll) {
    console.log('[feeds] Stale or unpopulated feeds detected — firing immediate poll');
    pollAllFeeds().catch((err) => console.error('[feeds] Immediate poll error:', err));
  }

  setInterval(() => {
    pollAllFeeds().catch((err) => console.error('[feeds] Scheduled poll error:', err));
  }, POLL_INTERVAL_MS);

  console.log(`[feeds] Scheduler started — polling every ${POLL_INTERVAL_MS / 60_000} minutes`);
}

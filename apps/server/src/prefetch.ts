/**
 * Deterministic IOC context gathering, done by Harbinger — not by the model.
 *
 * Why this exists
 * ---------------
 * The Claude CLI analysis path (see analysis-provider.ts) runs with every tool
 * disallowed, so the model cannot call `search_iocs` or the cve-mcp enrichment
 * tools the way the old Anthropic tool-use loop did. Specter hit the same wall
 * and solved it the same way: run the lookups in app code and inject the
 * results into the prompt. See Specter's alert-history.ts for the full
 * rationale, including the 2026-09-22 test where a scoped Bash grant let the
 * model list private key filenames on the Studio.
 *
 * Running the lookups here is strictly better than granting tools:
 *   - deterministic: enrichment always happens, never dependent on the model
 *     deciding to ask (this matters for unattended cron briefs)
 *   - zero added attack surface: no model-controlled command execution
 *   - cheaper: a fixed set of calls instead of an agent loop
 *   - the privacy rule becomes ENFORCED rather than merely requested
 *
 * That last point is the important one. Under the tool-use loop, "do not
 * enrich RFC1918 / internal IOCs" was a sentence in the system prompt that the
 * model was trusted to obey. Here it is isPrivateIndicator(), applied before
 * any third-party API is touched. A prompt instruction is a request; this is a
 * control.
 */

import type { IOC } from './types';
import { queryIOCs } from './db';
import { callCveMcpTool } from './mcp-client';
import { lookupCveExposure, formatCveExposure, isWazuhConfigured } from './wazuh-client';
import { getExploitSignals, formatExploitSignal } from './exploit-signal';

/** Max IOCs enriched per request. Keeps third-party API usage bounded. */
const MAX_ENRICHED_IOCS = 5;

/** Max related IOCs pulled from the local DB for context. */
const MAX_RELATED_IOCS = 25;

/** Per-tool timeout. A slow vendor must not hang the whole analysis. */
const ENRICH_TIMEOUT_MS = 20_000;

// ---------------------------------------------------------------------------
// Privacy filter — enforced in code, not requested in a prompt
// ---------------------------------------------------------------------------

const INTERNAL_TLDS = [
  '.corp', '.local', '.lan', '.internal', '.home', '.intranet', '.private',
];

/**
 * Additional internal suffixes on PUBLIC registrable domains.
 *
 * The homelab runs everything behind `*.home.carbeneai.com`, which ends in a
 * real TLD, so the INTERNAL_TLDS suffix check above does NOT catch it. Without
 * this list an internal hostname like harbinger.home.carbeneai.com would be
 * shipped to VirusTotal/URLScan as if it were a public IOC.
 *
 * Operators can extend this with INTERNAL_DOMAIN_SUFFIXES (comma-separated).
 */
const BUILTIN_INTERNAL_SUFFIXES = ['.home.carbeneai.com'];

function internalSuffixes(): string[] {
  const extra = (process.env.INTERNAL_DOMAIN_SUFFIXES ?? '')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  return [...BUILTIN_INTERNAL_SUFFIXES, ...extra];
}

/**
 * True when an indicator must never be sent to a third-party enrichment API.
 *
 * Covers RFC1918, loopback, link-local, CGNAT, IPv6 ULA/loopback, and internal
 * hostname suffixes. Conservative by design: when in doubt, treat as private
 * and skip enrichment. A missed enrichment is a smaller failure than leaking
 * internal infrastructure to VirusTotal.
 */
export function isPrivateIndicator(value: string): boolean {
  const v = value.trim().toLowerCase();
  if (!v) return true;

  // Strip scheme and path so a URL is judged on its host.
  const host = v
    .replace(/^[a-z][a-z0-9+.-]*:\/\//, '')
    .split(/[/?#]/)[0]
    .replace(/:\d+$/, '')
    .replace(/\[|\]/g, '');

  // IPv4
  const m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const [a, b] = [Number(m[1]), Number(m[2])];
    if (a === 10) return true;                          // 10.0.0.0/8
    if (a === 127) return true;                         // loopback
    if (a === 0) return true;                           // this-network
    if (a === 172 && b >= 16 && b <= 31) return true;   // 172.16.0.0/12
    if (a === 192 && b === 168) return true;            // 192.168.0.0/16
    if (a === 169 && b === 254) return true;            // link-local
    if (a === 100 && b >= 64 && b <= 127) return true;  // CGNAT 100.64.0.0/10
    if (a >= 224) return true;                          // multicast / reserved
    return false;
  }

  // IPv6 loopback / unspecified / ULA / link-local
  if (host === '::1' || host === '::') return true;
  if (/^f[cd][0-9a-f]{2}:/.test(host)) return true;     // fc00::/7 ULA
  if (/^fe80:/.test(host)) return true;                 // link-local

  // Internal hostnames
  if (host === 'localhost') return true;
  if (!host.includes('.')) return true;                 // bare hostname
  if (INTERNAL_TLDS.some((tld) => host.endsWith(tld))) return true;
  if (internalSuffixes().some((sfx) => host.endsWith(sfx))) return true;

  return false;
}

// ---------------------------------------------------------------------------
// Enrichment
// ---------------------------------------------------------------------------

/** Which cve-mcp tools apply to each IOC type.
 *
 * CVEs are deliberately absent: they are handled by Wazuh (environment
 * exposure) plus KEV/EPSS (exploitation signal), which need no Python server
 * and answer a better question than the generic NVD lookup did.
 */
function toolsForIOC(ioc: IOC): Array<{ tool: string; args: Record<string, unknown> }> {
  switch (ioc.ioc_type) {
    case 'ip':
      return [
        { tool: 'check_ip_reputation', args: { ip: ioc.value } },
        { tool: 'shodan_host_lookup',  args: { ip: ioc.value } },
      ];
    case 'domain':
      return [{ tool: 'get_domain_intel',  args: { domain: ioc.value } }];
    case 'url':
      return [{ tool: 'check_url_safety',  args: { url_or_domain: ioc.value } }];
    case 'hash':
      return [{ tool: 'lookup_file_hash',  args: { hash_str: ioc.value } }];
    default:
      return [];
  }
}

/** Call one tool with a timeout. Never throws — failures degrade to a note. */
async function callWithTimeout(
  tool: string,
  args: Record<string, unknown>,
): Promise<string> {
  try {
    const result = await Promise.race([
      callCveMcpTool(tool, args),
      new Promise<string>((_, reject) =>
        setTimeout(() => reject(new Error('timeout')), ENRICH_TIMEOUT_MS),
      ),
    ]);
    return result;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`[prefetch] ${tool} failed:`, msg);
    return `(enrichment unavailable: ${msg})`;
  }
}

/**
 * Enrich the supplied IOCs via cve-mcp, skipping anything private.
 *
 * Returns a markdown block, or '' when there is nothing to report. Failures are
 * surfaced in the text rather than thrown, so the model can see that a lookup
 * failed and must not imply it succeeded.
 */
export async function buildEnrichmentBlock(iocs: IOC[]): Promise<string> {
  if (!iocs || iocs.length === 0) return '';

  const candidates = iocs.slice(0, MAX_ENRICHED_IOCS);
  const sections: string[] = [];
  const skipped: string[] = [];

  for (const ioc of candidates) {
    if (isPrivateIndicator(ioc.value)) {
      skipped.push(ioc.value);
      continue;
    }

    const tools = toolsForIOC(ioc);
    if (tools.length === 0) continue;

    const results = await Promise.all(
      tools.map(async ({ tool, args }) => {
        const text = await callWithTimeout(tool, args);
        return `#### ${tool}\n\n${text}\n`;
      }),
    );

    sections.push(
      `### Enrichment: ${ioc.ioc_type.toUpperCase()} ${ioc.value}\n\n${results.join('\n')}`,
    );
  }

  if (sections.length === 0 && skipped.length === 0) return '';

  const lines = ['\n## Third-Party Enrichment (fetched by Harbinger)\n'];
  if (sections.length > 0) lines.push(...sections);
  if (skipped.length > 0) {
    lines.push(
      `\n_Skipped enrichment for ${skipped.length} internal/private indicator(s) ` +
        `(RFC1918, loopback, or internal hostname): ${skipped.join(', ')}. ` +
        `These were NOT sent to any third-party API._\n`,
    );
  }
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Local IOC search
// ---------------------------------------------------------------------------

/**
 * Quote a term for SQLite FTS5.
 *
 * FTS5 treats `.`, `-`, `:` and friends as syntax, so a raw CVE ID
 * ("CVE-2021-44228") or domain ("evil.com") is a syntax error, not a search.
 * Wrapping in double quotes makes it a literal phrase; internal double quotes
 * are escaped by doubling per the FTS5 grammar.
 */
function quoteFtsTerm(term: string): string {
  return `"${term.replace(/"/g, '""')}"`;
}

/**
 * Pull related IOCs from the local database using terms drawn from the user's
 * question and the selected IOCs. Replaces the model's autonomous
 * `search_iocs` calls with one deterministic query.
 */
export function buildRelatedIOCBlock(
  userMessage: string,
  iocContext?: IOC[],
): string {
  // Prefer searching on the selected IOCs' own tags/values; fall back to the
  // user's own words when nothing is selected.
  const terms = new Set<string>();

  for (const ioc of iocContext ?? []) {
    // The IOC value itself is the strongest correlation key (a CVE ID, a
    // domain, a hash). Tags broaden it to the campaign.
    if (ioc.value) terms.add(ioc.value);
    if (ioc.tags) for (const t of ioc.tags.slice(0, 3)) terms.add(t);
  }

  if (terms.size === 0) {
    // Crude but effective: keep words long enough to be meaningful.
    for (const word of userMessage.split(/\s+/)) {
      const w = word.replace(/[^a-zA-Z0-9.\-_]/g, '');
      if (w.length >= 5) terms.add(w);
      if (terms.size >= 3) break;
    }
  }

  if (terms.size === 0) return '';

  const selectedValues = new Set((iocContext ?? []).map((i) => i.value));
  const seen = new Set<string>();
  const found: IOC[] = [];

  for (const term of Array.from(terms).slice(0, 3)) {
    try {
      const { iocs } = queryIOCs({ search: quoteFtsTerm(term), limit: MAX_RELATED_IOCS });
      for (const ioc of iocs) {
        if (selectedValues.has(ioc.value)) continue;  // already in context
        if (seen.has(ioc.value)) continue;
        seen.add(ioc.value);
        found.push(ioc);
      }
    } catch (err) {
      console.error('[prefetch] related IOC search failed:', err);
    }
  }

  if (found.length === 0) return '';

  const lines = [
    `\n## Related IOCs from the local database (${found.length}, fetched by Harbinger)\n`,
  ];
  for (const ioc of found.slice(0, MAX_RELATED_IOCS)) {
    lines.push(
      `- [${ioc.severity.toUpperCase()}] ${ioc.ioc_type.toUpperCase()}: ${ioc.value}` +
        (ioc.title ? ` — ${ioc.title}` : '') +
        (ioc.tags?.length ? ` (${ioc.tags.slice(0, 3).join(', ')})` : ''),
    );
  }
  return lines.join('\n');
}

/**
 * CVE enrichment: environment exposure (Wazuh) + exploitation signal (KEV/EPSS).
 *
 * This is the pairing that makes a brief actionable. Wazuh answers "do I have
 * it"; KEV/EPSS answer "is anyone exploiting it". Present AND exploited is the
 * top of the patch queue; absent but exploited is watch-only.
 *
 * CVE IDs are public identifiers, so the privacy filter does not apply here —
 * nothing host-specific leaves the network. The Wazuh query is to your own
 * LAN appliance; only the CVE ID goes to CISA/FIRST.
 */
async function buildCveBlock(iocs: IOC[]): Promise<string> {
  const cves = iocs
    .filter((i) => i.ioc_type === 'cve')
    .map((i) => i.value.trim().toUpperCase())
    .filter((v) => /^CVE-\d{4}-\d{4,}$/.test(v));

  if (cves.length === 0) return '';

  const unique = Array.from(new Set(cves)).slice(0, MAX_ENRICHED_IOCS);

  const [signals, exposures] = await Promise.all([
    getExploitSignals(unique),
    isWazuhConfigured()
      ? Promise.all(unique.map((c) => lookupCveExposure(c)))
      : Promise.resolve(null),
  ]);

  const sections: string[] = ['\n## CVE Analysis (fetched by Harbinger)\n'];

  for (const [idx, cve] of unique.entries()) {
    sections.push(`### ${cve}\n`);

    const exposure = exposures?.[idx];
    if (exposure) {
      sections.push(formatCveExposure(exposure));
    } else {
      sections.push(
        '_Environment exposure NOT CHECKED — Wazuh is not configured. Do not ' +
          'state whether this CVE is present in the environment._',
      );
    }

    const sig = signals.get(cve);
    sections.push('', sig ? formatExploitSignal(sig) : 'Exploitation signal: unavailable.');

    // The prioritisation call, stated explicitly so the model does not have to
    // infer it (and cannot get it backwards).
    if (exposure?.present && sig?.inKev) {
      sections.push(
        '', '> **PRIORITY: PATCH NOW.** Present in the environment AND in CISA KEV ' +
          '(confirmed exploitation in the wild).',
      );
    } else if (exposure?.present) {
      sections.push(
        '', '> **Present in the environment.** Not in KEV, so schedule rather than ' +
          'emergency-patch, weighted by the EPSS score above.',
      );
    } else if (exposure && !exposure.present && sig?.inKev) {
      sections.push(
        '', '> **Not in the environment.** In KEV, so worth a detection rule and ' +
          'a watch, but there is nothing here to patch.',
      );
    }
    sections.push('');
  }

  return sections.join('\n');
}

/**
 * Build the full pre-fetched context block for a chat request: related local
 * IOCs, CVE exposure/exploitation, and third-party enrichment. Safe to call
 * with no IOC context.
 */
export async function buildPrefetchedContext(
  userMessage: string,
  iocContext?: IOC[],
): Promise<string> {
  const related = buildRelatedIOCBlock(userMessage, iocContext);
  const [cveBlock, enrichment] = await Promise.all([
    buildCveBlock(iocContext ?? []),
    buildEnrichmentBlock(iocContext ?? []),
  ]);

  const combined = [related, cveBlock, enrichment].filter(Boolean).join('\n');
  if (!combined) return '';

  return (
    combined +
    '\n\n_The data above was gathered by Harbinger before this prompt was sent. ' +
    'You have no live tools in this session: do not claim to have searched or ' +
    'looked anything up yourself, and do not imply data exists beyond what is ' +
    'shown here. If something needed is missing, say so plainly._\n'
  );
}

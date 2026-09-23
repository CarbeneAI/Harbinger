/**
 * Wazuh vulnerability-state client — "do I actually have this CVE?"
 *
 * Why this exists
 * ---------------
 * Harbinger's feeds tell you what the world is being attacked with. Wazuh's
 * vulnerability detector tells you what is actually installed on your hosts.
 * The second question is the operationally useful one: "CVE-2024-6345 is on 6
 * of your machines via setuptools 65.5.0, fix is 70.0.0" beats any amount of
 * generic CVE description.
 *
 * This replaces the cve-mcp Python server for CVE enrichment. cve-mcp was
 * never installed on the app host (srv-apps) after Harbinger moved there, so
 * every enrichment call was failing. This path needs no Python, no API keys,
 * and no extra daemon — just an HTTPS call to the Wazuh dashboard proxy that
 * the homelab already runs.
 *
 * Read-only by construction: only _search and _count against the
 * wazuh-states-vulnerabilities* index, via the dashboard console proxy. The
 * raw indexer port 9200 is localhost-only on the Wazuh box; the proxy is the
 * approved path (see the wazuh-siem skill).
 *
 * Fails open everywhere. If Wazuh is unreachable the brief still ships, with
 * text saying the lookup failed, so the model cannot imply it checked.
 */

/** One affected installation of a CVE on one host. */
export interface WazuhCveInstance {
  agentName: string;
  packageName: string;
  packageVersion: string;
  osName?: string;
  condition?: string;     // e.g. "Package less than 70.0.0" — the fix
}

/** Environment exposure for a single CVE. */
export interface WazuhCveExposure {
  cveId: string;
  present: boolean;
  instanceCount: number;
  hosts: string[];
  severity?: string;
  baseScore?: number;
  instances: WazuhCveInstance[];
  /** Set when the lookup itself failed (distinct from "not present"). */
  error?: string;
}

const VULN_INDEX = 'wazuh-states-vulnerabilities*';
const DEFAULT_TIMEOUT_MS = 20_000;
const MAX_INSTANCES = 12;

function config() {
  const url = process.env.WAZUH_DASHBOARD_URL;
  const user = process.env.WAZUH_DASHBOARD_USER ?? 'admin';
  const password = process.env.WAZUH_DASHBOARD_PASSWORD;
  return { url, user, password };
}

export function isWazuhConfigured(): boolean {
  const { url, password } = config();
  return Boolean(url && password);
}

/**
 * POST a search to the Wazuh dashboard console proxy.
 *
 * The dashboard uses a self-signed cert on the LAN, so verification is
 * disabled for this host only. That is acceptable for a LAN appliance and is
 * the same thing every other tool in the homelab does; it is NOT a pattern to
 * copy for internet hosts.
 */
async function search(body: unknown, timeoutMs: number): Promise<any> {
  const { url, user, password } = config();
  if (!url || !password) {
    throw new Error(
      'Wazuh not configured — set WAZUH_DASHBOARD_URL and WAZUH_DASHBOARD_PASSWORD.',
    );
  }

  const endpoint =
    `${url.replace(/\/$/, '')}/api/console/proxy` +
    `?path=${encodeURIComponent(`${VULN_INDEX}/_search`)}&method=POST`;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'osd-xsrf': 'true',
        Authorization: `Basic ${Buffer.from(`${user}:${password}`).toString('base64')}`,
      },
      body: JSON.stringify(body),
      signal: controller.signal,
      // Self-signed cert on the LAN dashboard.
      tls: { rejectUnauthorized: false },
    } as RequestInit & { tls: { rejectUnauthorized: boolean } });

    if (!res.ok) {
      throw new Error(`Wazuh returned HTTP ${res.status}`);
    }
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Look up one CVE against the live environment inventory.
 *
 * Never throws: a failed lookup returns { present: false, error }, so callers
 * can distinguish "you do not have this" from "we could not check".
 */
export async function lookupCveExposure(
  cveId: string,
  timeoutMs = DEFAULT_TIMEOUT_MS,
): Promise<WazuhCveExposure> {
  const base: WazuhCveExposure = {
    cveId,
    present: false,
    instanceCount: 0,
    hosts: [],
    instances: [],
  };

  try {
    const data = await search(
      {
        size: MAX_INSTANCES,
        query: { term: { 'vulnerability.id': cveId } },
        aggs: { hosts: { terms: { field: 'agent.name', size: 50 } } },
        _source: [
          'agent.name', 'package.name', 'package.version',
          'host.os.name', 'vulnerability.severity',
          'vulnerability.score.base', 'vulnerability.scanner.condition',
        ],
      },
      timeoutMs,
    );

    const total: number = data?.hits?.total?.value ?? 0;
    const hits: any[] = data?.hits?.hits ?? [];
    if (total === 0) return base;

    const instances: WazuhCveInstance[] = hits.map((h) => {
      const s = h._source ?? {};
      return {
        agentName: s.agent?.name ?? 'unknown',
        packageName: s.package?.name ?? 'unknown',
        packageVersion: s.package?.version ?? 'unknown',
        osName: s.host?.os?.name,
        condition: s.vulnerability?.scanner?.condition,
      };
    });

    const hosts: string[] = (data?.aggregations?.hosts?.buckets ?? []).map(
      (b: any) => b.key as string,
    );

    const first = hits[0]?._source ?? {};
    return {
      cveId,
      present: true,
      instanceCount: total,
      hosts,
      severity: first.vulnerability?.severity,
      baseScore: first.vulnerability?.score?.base,
      instances,
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`[wazuh-client] CVE lookup failed for ${cveId}:`, msg);
    return { ...base, error: msg };
  }
}

/** Render one exposure as markdown for the analyst prompt. */
export function formatCveExposure(e: WazuhCveExposure): string {
  if (e.error) {
    return (
      `**${e.cveId} — environment exposure: LOOKUP FAILED** (${e.error}). ` +
      `Do not state whether this CVE is present; the check did not run.`
    );
  }

  if (!e.present) {
    return (
      `**${e.cveId} — NOT FOUND in the environment.** Wazuh's vulnerability ` +
      `inventory has no affected package on any monitored host. Treat this as ` +
      `external threat intel, not an active exposure.`
    );
  }

  const lines = [
    `**${e.cveId} — PRESENT IN THE ENVIRONMENT.**`,
    `- Affected installations: ${e.instanceCount}`,
    `- Hosts (${e.hosts.length}): ${e.hosts.join(', ')}`,
  ];
  if (e.severity) lines.push(`- Wazuh severity: ${e.severity}`);
  if (e.baseScore !== undefined) lines.push(`- CVSS base: ${e.baseScore}`);

  lines.push('', 'Affected packages:');
  const seen = new Set<string>();
  for (const i of e.instances) {
    const key = `${i.agentName}|${i.packageName}|${i.packageVersion}`;
    if (seen.has(key)) continue;
    seen.add(key);
    lines.push(
      `- \`${i.packageName} ${i.packageVersion}\` on **${i.agentName}**` +
        (i.osName ? ` (${i.osName})` : '') +
        (i.condition ? ` — fix: ${i.condition}` : ''),
    );
  }
  if (e.instanceCount > e.instances.length) {
    lines.push(`- _...and ${e.instanceCount - e.instances.length} more installation(s)._`);
  }
  return lines.join('\n');
}

/** Health of the Wazuh environment-exposure lookup. */
export async function getWazuhStatus(): Promise<{
  configured: boolean;
  connected: boolean;
  distinctCves?: number;
  criticalHigh?: number;
  hosts?: number;
  lastError?: string;
}> {
  if (!isWazuhConfigured()) {
    return { configured: false, connected: false };
  }
  try {
    const data = await search(
      {
        size: 0,
        aggs: {
          cves: { cardinality: { field: 'vulnerability.id' } },
          hosts: { cardinality: { field: 'agent.name' } },
          crit: {
            filter: { terms: { 'vulnerability.severity': ['Critical', 'High'] } },
            aggs: { n: { cardinality: { field: 'vulnerability.id' } } },
          },
        },
      },
      10_000,
    );
    const a = data?.aggregations;
    return {
      configured: true,
      connected: true,
      distinctCves: a?.cves?.value,
      criticalHigh: a?.crit?.n?.value,
      hosts: a?.hosts?.value,
    };
  } catch (err) {
    return {
      configured: true,
      connected: false,
      lastError: err instanceof Error ? err.message : String(err),
    };
  }
}

/**
 * Top Critical/High CVEs actually present in the environment.
 * Used to ground the briefs in real exposure rather than generic feed volume.
 */
export async function getEnvironmentExposureSummary(
  limit = 15,
  timeoutMs = DEFAULT_TIMEOUT_MS,
): Promise<string> {
  try {
    const data = await search(
      {
        size: 0,
        query: { terms: { 'vulnerability.severity': ['Critical', 'High'] } },
        aggs: {
          total: { cardinality: { field: 'vulnerability.id' } },
          by_sev: { terms: { field: 'vulnerability.severity', size: 5 } },
          cves: {
            terms: { field: 'vulnerability.id', size: limit },
            aggs: {
              hosts: { cardinality: { field: 'agent.name' } },
              pkg: { terms: { field: 'package.name', size: 1 } },
              top: {
                top_hits: {
                  size: 1,
                  _source: [
                    'vulnerability.severity', 'vulnerability.score.base',
                    'vulnerability.scanner.condition',
                  ],
                },
              },
            },
          },
        },
      },
      timeoutMs,
    );

    const aggs = data?.aggregations;
    if (!aggs) return '';

    const distinct = aggs.total?.value ?? 0;
    const sev: string = (aggs.by_sev?.buckets ?? [])
      .map((b: any) => `${b.key} ${b.doc_count}`)
      .join(' | ');

    const lines = [
      '\n## Environment Exposure (live Wazuh vulnerability inventory)\n',
      `Distinct Critical/High CVEs present on monitored hosts: **${distinct}**`,
      sev ? `Installations by severity: ${sev}` : '',
      '',
      'Most widespread Critical/High CVEs in YOUR environment:',
    ];

    for (const b of aggs.cves?.buckets ?? []) {
      const src = b.top?.hits?.hits?.[0]?._source ?? {};
      const pkg = b.pkg?.buckets?.[0]?.key;
      const cond = src.vulnerability?.scanner?.condition;
      const score = src.vulnerability?.score?.base;
      lines.push(
        `- **${b.key}** — ${b.hosts.value} host(s), ${b.doc_count} installation(s)` +
          (pkg ? `, package \`${pkg}\`` : '') +
          (score !== undefined ? `, CVSS ${score}` : '') +
          (cond ? ` — fix: ${cond}` : ''),
      );
    }

    lines.push(
      '',
      '_This is real inventory from the Wazuh vulnerability detector, not feed ' +
        'data. A CVE listed here is installed on a host you own. Prioritise ' +
        'these over feed CVEs that are absent from the environment._',
    );
    return lines.filter((l) => l !== '').join('\n');
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error('[wazuh-client] exposure summary failed:', msg);
    return (
      `\n## Environment Exposure\n\n_Wazuh inventory lookup FAILED (${msg}). ` +
      `Do not claim anything about what is or is not present in the ` +
      `environment in this brief._\n`
    );
  }
}

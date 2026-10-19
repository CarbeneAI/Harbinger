import { afterEach, beforeEach, describe, expect, it, mock, spyOn } from 'bun:test';
import { formatCveExposure, getEnvironmentExposureSummary, getWazuhStatus, lookupCveExposure } from './wazuh-client';

const cve = 'CVE-2021-44228';
const configuration = ['WAZUH_DASHBOARD_URL', 'WAZUH_DASHBOARD_USER', 'WAZUH_DASHBOARD_PASSWORD'] as const;
let original: (string | undefined)[];
let response: unknown;

function successfulSearch(total: number | { value: number; relation: string } = { value: 0, relation: 'eq' }): any {
  return {
    timed_out: false,
    _shards: { total: 2, successful: 2, skipped: 0, failed: 0 },
    hits: { total, hits: [] },
    aggregations: { hosts: { buckets: [] } },
  };
}

describe('Wazuh inventory response validation', () => {
  beforeEach(() => {
    original = configuration.map(key => process.env[key]);
    process.env.WAZUH_DASHBOARD_URL = 'https://wazuh.invalid';
    process.env.WAZUH_DASHBOARD_USER = 'fixture-user';
    process.env.WAZUH_DASHBOARD_PASSWORD = 'fixture-password';
    response = successfulSearch();
    // Only transport is replaced: parsing, lookup, and formatting stay real.
    spyOn(globalThis, 'fetch').mockImplementation(
      Object.assign(async () => Response.json(response), {
        preconnect: () => { throw new Error('Unexpected preconnect in an offline fixture'); },
      }),
    );
    spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    mock.restore();
    configuration.forEach((key, index) => {
      if (original[index] === undefined) delete process.env[key];
      else process.env[key] = original[index];
    });
  });

  it('confirms absence only after a complete exact zero-result search', async () => {
    const exposure = await lookupCveExposure(cve);
    expect(exposure.error).toBeUndefined();
    expect(exposure.present).toBe(false);
    expect(formatCveExposure(exposure)).toContain('NOT FOUND');
    expect(globalThis.fetch).toHaveBeenCalledTimes(1);
    const [url, request] = (globalThis.fetch as any).mock.calls[0];
    expect(new URL(url).hostname).toBe('wazuh.invalid');
    expect(JSON.parse(request.body).track_total_hits).toBe(true);
  });

  it('accepts legacy exact numeric totals', async () => {
    response = successfulSearch(0);
    expect((await lookupCveExposure(cve)).error).toBeUndefined();
  });

  it('preserves positive exposure when the returned sample is smaller than the total', async () => {
    const data = successfulSearch({ value: 25, relation: 'eq' });
    data.hits.hits = [{ _source: {
      agent: { name: 'fixture-host' }, package: { name: 'log4j', version: '2.14.1' },
      vulnerability: { severity: 'Critical', score: { base: 10 } },
    } }];
    data.aggregations.hosts.buckets = [{ key: 'fixture-host', doc_count: 25 }];
    response = data;
    const exposure = await lookupCveExposure(cve);
    expect(exposure.error).toBeUndefined();
    expect(exposure.present).toBe(true);
    expect(exposure.instanceCount).toBe(25);
    expect(exposure.hosts).toEqual(['fixture-host']);
    expect(exposure.instances[0].packageName).toBe('log4j');
    expect(formatCveExposure(exposure)).toContain('24 more installation(s)');
  });

  const invalid: [string, () => unknown][] = [
    ['an HTTP 200 error document', () => ({ error: { reason: 'fixture failure' } })],
    ['a null document', () => null],
    ['an array document', () => []],
    ['a timed-out search', () => ({ ...successfulSearch(), timed_out: true })],
    ['missing completion metadata', () => ({ ...successfulSearch(), timed_out: undefined })],
    ['an early-terminated search', () => ({ ...successfulSearch(), terminated_early: true })],
    ['failed shards', () => ({ ...successfulSearch(), _shards: { total: 2, successful: 1, failed: 1 } })],
    ['unavailable shards', () => ({ ...successfulSearch(), _shards: { total: 2, successful: 1, failed: 0 } })],
    ['no searched shards', () => ({ ...successfulSearch(), _shards: { total: 0, successful: 0, failed: 0 } })],
    ['missing shard metadata', () => ({ ...successfulSearch(), _shards: undefined })],
    ['missing totals', () => ({ ...successfulSearch(), hits: { hits: [] } })],
    ['negative totals', () => successfulSearch(-1)],
    ['fractional totals', () => successfulSearch(0.5)],
    ['lower-bound totals', () => successfulSearch({ value: 0, relation: 'gte' })],
    ['invalid hit arrays', () => ({ ...successfulSearch(), hits: { total: 0, hits: {} } })],
    ['positive totals without evidence', () => successfulSearch(1)],
    ['zero totals with contradictory evidence', () => ({ ...successfulSearch(), hits: { total: 0, hits: [{ _source: {} }] } })],
    ['invalid source records', () => ({ ...successfulSearch(), hits: { total: 1, hits: [null] } })],
    ['missing host aggregation', () => ({ ...successfulSearch(), aggregations: {} })],
    ['hosts contradicting a zero total', () => ({ ...successfulSearch(), aggregations: { hosts: { buckets: [{ key: 'fixture-host', doc_count: 1 }] } } })],
  ];

  for (const [name, build] of invalid) {
    it(`keeps exposure unknown for ${name}`, async () => {
      response = build();
      const exposure = await lookupCveExposure(cve);
      expect(exposure.error).toBeTruthy();
      expect(formatCveExposure(exposure)).toContain('LOOKUP FAILED');
      expect(formatCveExposure(exposure)).not.toContain('NOT FOUND');
    });
  }

  it('keeps invalid JSON and HTTP errors unknown', async () => {
    for (const result of [new Response('{'), new Response('unavailable', { status: 503 })]) {
      spyOn(globalThis, 'fetch').mockResolvedValueOnce(result);
      expect((await lookupCveExposure(cve)).error).toBeTruthy();
    }
  });

  it('keeps transport errors unknown', async () => {
    spyOn(globalThis, 'fetch').mockRejectedValueOnce(new Error('fixture connection failure'));
    expect((await lookupCveExposure(cve)).error).toContain('fixture connection failure');
  });

  it('rejects partial searches in health and summary paths too', async () => {
    response = { ...successfulSearch(), timed_out: true };
    expect(await getWazuhStatus()).toMatchObject({ connected: false });
    expect(await getEnvironmentExposureSummary()).toContain('lookup FAILED');
  });

  it('does not report healthy connectivity for malformed aggregation responses', async () => {
    response = successfulSearch();
    expect(await getWazuhStatus()).toMatchObject({ configured: true, connected: false });
  });

  it('reports valid health metrics, including zero counts', async () => {
    // size:0 requests legitimately have no hit samples even when total > 0.
    response = { ...successfulSearch(42), aggregations: { cves: { value: 0 }, hosts: { value: 0 }, crit: { n: { value: 0 } } } };
    expect(await getWazuhStatus()).toEqual({ configured: true, connected: true, distinctCves: 0, hosts: 0, criticalHigh: 0 });
  });

  it('keeps missing summary evidence unknown instead of inventing zero exposure', async () => {
    response = { ...successfulSearch(), aggregations: {} };
    const summary = await getEnvironmentExposureSummary();
    expect(summary).toContain('lookup FAILED');
    expect(summary).not.toContain('**0**');
  });

  it('renders a complete empty summary as zero exposure', async () => {
    response = { ...successfulSearch(), aggregations: { total: { value: 0 }, by_sev: { buckets: [] }, cves: { buckets: [] } } };
    expect(await getEnvironmentExposureSummary()).toContain('**0**');
  });

  it('preserves populated summaries and rejects missing nested evidence', async () => {
    const data = { ...successfulSearch(2), aggregations: {
      total: { value: 1 }, by_sev: { buckets: [{ key: 'Critical', doc_count: 2 }] },
      cves: { buckets: [{ key: cve, doc_count: 2, hosts: { value: 2 },
        pkg: { buckets: [{ key: 'log4j', doc_count: 2 }] },
        top: { hits: { hits: [{ _source: { vulnerability: { score: { base: 10 } } } }] } },
      }] },
    } };
    response = data;
    const summary = await getEnvironmentExposureSummary();
    expect(summary).toContain('**1**');
    expect(summary).toContain('2 host(s), 2 installation(s), package `log4j`, CVSS 10');
    (data.aggregations.cves.buckets[0] as any).hosts = undefined;
    expect(await getEnvironmentExposureSummary()).toContain('lookup FAILED');
  });

  it('rejects contradictory summary counts and absent samples for affected CVEs', async () => {
    const affected = { key: cve, doc_count: 1, hosts: { value: 1 },
      pkg: { buckets: [] }, top: { hits: { hits: [{ _source: {} }] } } };
    for (const [count, buckets] of [[0, [affected]], [1, []],
      [1, [{ ...affected, top: { hits: { hits: [] } } }]]] as const) {
      response = { ...successfulSearch(), aggregations: {
        total: { value: count }, by_sev: { buckets: [] }, cves: { buckets },
      } };
      expect(await getEnvironmentExposureSummary()).toContain('lookup FAILED');
    }
  });
});

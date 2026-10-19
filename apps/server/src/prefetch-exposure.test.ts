import { afterEach, beforeEach, describe, expect, it, mock, spyOn } from 'bun:test';
import * as db from './db';
import * as exploitSignal from './exploit-signal';
import { buildPrefetchedContext } from './prefetch';
import type { IOC } from './types';
import * as wazuh from './wazuh-client';

const cve = 'CVE-2021-44228';
const ioc: IOC = {
  id: 1,
  feed_id: 1,
  ioc_type: 'cve',
  value: cve,
  severity: 'critical',
  first_seen: 0,
  last_seen: 0,
};

describe('CVE exposure recommendations', () => {
  beforeEach(() => {
    // Keep the context builder and formatters real; isolate its data sources.
    spyOn(db, 'queryIOCs').mockReturnValue({ iocs: [], total: 0 });
    spyOn(wazuh, 'isWazuhConfigured').mockReturnValue(true);
    spyOn(wazuh, 'lookupCveExposure').mockResolvedValue({
      cveId: cve,
      present: false,
      instanceCount: 0,
      hosts: [],
      instances: [],
    });
    spyOn(exploitSignal, 'getExploitSignals').mockResolvedValue(new Map([
      [cve, { cveId: cve, kevState: 'available', inKev: true, kev: { cveId: cve, dateAdded: '2021-12-10' } }],
    ]));
    spyOn(globalThis, 'fetch').mockRejectedValue(new Error('Unexpected network request'));
  });

  afterEach(() => {
    try {
      expect(globalThis.fetch).not.toHaveBeenCalled();
    } finally {
      mock.restore();
    }
  });

  it('keeps exposure unknown when Wazuh fails for a CVE in KEV', async () => {
    spyOn(wazuh, 'lookupCveExposure').mockResolvedValue({
      cveId: cve,
      present: false,
      instanceCount: 0,
      hosts: [],
      instances: [],
      error: 'Wazuh returned HTTP 503',
    });

    const context = await buildPrefetchedContext('Analyze this CVE', [ioc]);

    expect(wazuh.lookupCveExposure).toHaveBeenCalledWith(cve);
    expect(context).toContain('environment exposure: LOOKUP FAILED');
    expect(context).toContain('Do not state whether this CVE is present');
    expect(context).toContain('CISA KEV: YES');
    expect(context).not.toContain('Not in the environment');
    expect(context).not.toContain('nothing here to patch');
    expect(context).not.toContain('PRIORITY: PATCH NOW');
  });

  it('retains the watch-only recommendation after a successful absent result', async () => {
    const context = await buildPrefetchedContext('Analyze this CVE', [ioc]);

    expect(context).toContain('NOT FOUND in the environment');
    expect(context).toContain('Not in the environment');
    expect(context).toContain('nothing here to patch');
    expect(context).not.toContain('LOOKUP FAILED');
  });

  it('retains patch priority when Wazuh confirms a CVE in KEV is present', async () => {
    spyOn(wazuh, 'lookupCveExposure').mockResolvedValue({
      cveId: cve,
      present: true,
      instanceCount: 1,
      hosts: ['test-host'],
      instances: [{ agentName: 'test-host', packageName: 'log4j', packageVersion: '2.14.1' }],
    });

    const context = await buildPrefetchedContext('Analyze this CVE', [ioc]);

    expect(context).toContain('PRESENT IN THE ENVIRONMENT');
    expect(context).toContain('PRIORITY: PATCH NOW');
    expect(context).not.toContain('nothing here to patch');
  });

  it('does not infer absence when Wazuh is not configured', async () => {
    spyOn(wazuh, 'isWazuhConfigured').mockReturnValue(false);

    const context = await buildPrefetchedContext('Analyze this CVE', [ioc]);

    expect(wazuh.lookupCveExposure).not.toHaveBeenCalled();
    expect(context).toContain('Environment exposure NOT CHECKED');
    expect(context).not.toContain('Not in the environment');
    expect(context).not.toContain('nothing here to patch');
  });
});

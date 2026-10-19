import { afterEach, describe, expect, it, mock, spyOn } from 'bun:test';
import * as db from './db';
import * as signalModule from './exploit-signal';
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
const row = {
  cveID: cve,
  dateAdded: '2021-12-10',
  dueDate: '2021-12-24',
  vendorProject: 'Synthetic',
  product: 'Fixture',
};
const catalog = (listed: boolean) => ({
  catalogVersion: 'fixture',
  dateReleased: '2026-10-19T00:00:00Z',
  count: listed ? 1 : 0,
  vulnerabilities: listed ? [row] : [],
});
let sequence = 0;
afterEach(() => mock.restore());

describe('actual KEV producer through analyst context', () => {
  for (const exposure of ['present', 'absent', 'error', 'unconfigured'] as const) {
    for (const state of [
      'positive',
      'negative',
      'stale-positive',
      'stale-negative',
      'unavailable',
    ] as const) {
      it(`${exposure} Wazuh with ${state} KEV`, async () => {
        // Rebind the production producer to an isolated module cache, not a fabricated signal.
        const api = (await import(
          `./exploit-signal.ts?prefetch=${sequence++}`
        )) as typeof signalModule;
        spyOn(signalModule, 'getExploitSignals').mockImplementation(api.getExploitSignals);
        spyOn(db, 'queryIOCs').mockReturnValue({ iocs: [], total: 0 });
        spyOn(wazuh, 'isWazuhConfigured').mockReturnValue(exposure !== 'unconfigured');
        spyOn(wazuh, 'lookupCveExposure').mockResolvedValue({
          cveId: cve,
          present: exposure === 'present',
          instanceCount: exposure === 'present' ? 1 : 0,
          hosts: [],
          instances: [],
          ...(exposure === 'error' ? { error: 'Fixture lookup failed' } : {}),
        });
        const clock = spyOn(Date, 'now').mockReturnValue(1_800_000_000_000);
        let fail = state === 'unavailable';
        const fetch = spyOn(globalThis, 'fetch').mockImplementation((async (input) => {
          const url = String(input);
          if (
            url ===
            'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
          ) {
            return fail
              ? new Response('PRIVATE_CANARY', { status: 503 })
              : Response.json(catalog(state.endsWith('positive')));
          }
          if (url === `https://api.first.org/data/v1/epss?cve=${cve}`)
            return Response.json({ data: [] });
          throw new Error('Unexpected fixture destination');
        }) as typeof globalThis.fetch);
        if (state.startsWith('stale')) {
          await api.getExploitSignals([cve]);
          clock.mockReturnValue(1_800_000_000_000 + 6 * 60 * 60 * 1000);
          fail = true;
        }
        const context = await buildPrefetchedContext('Analyze this CVE', [ioc]);
        expect(fetch).toHaveBeenCalled();
        expect(context.includes('PRIORITY: PATCH NOW')).toBe(
          exposure === 'present' && state === 'positive',
        );
        expect(context.includes('nothing here to patch')).toBe(
          exposure === 'absent' && state === 'positive',
        );
        expect(context.includes('CISA KEV: YES')).toBe(state === 'positive');
        expect(context.toLowerCase().includes('not listed')).toBe(state === 'negative');
        expect(context).not.toContain('schedule rather than');
        expect(context).not.toContain('PRIVATE_CANARY');
        if (state.startsWith('stale')) expect(context).toContain('CISA KEV: stale');
        if (state === 'unavailable') expect(context).toContain('CISA KEV: unavailable');
        if (exposure === 'error') {
          expect(context).toContain('environment exposure: LOOKUP FAILED');
          expect(context).not.toContain('Not in the environment');
        }
        if (exposure === 'unconfigured')
          expect(context).toContain('Environment exposure NOT CHECKED');
        if (exposure === 'present') expect(context).toContain('PRESENT IN THE ENVIRONMENT');
      });
    }
  }

  for (const kevState of [undefined, 'unexpected']) {
    it(`treats runtime ${String(kevState)} state as unavailable`, async () => {
      spyOn(db, 'queryIOCs').mockReturnValue({ iocs: [], total: 0 });
      spyOn(wazuh, 'isWazuhConfigured').mockReturnValue(true);
      spyOn(wazuh, 'lookupCveExposure').mockResolvedValue({
        cveId: cve,
        present: true,
        instanceCount: 1,
        hosts: [],
        instances: [],
      });
      // Exercise old/untyped callers that bypass the required TypeScript union.
      spyOn(signalModule, 'getExploitSignals').mockResolvedValue(
        new Map([
          [
            cve,
            {
              cveId: cve,
              inKev: true,
              kevState,
              kev: { cveId: cve, dateAdded: '2021-12-10' },
            } as signalModule.ExploitSignal,
          ],
        ]),
      );
      const fetch = spyOn(globalThis, 'fetch').mockRejectedValue(new Error('Unexpected network'));
      const context = await buildPrefetchedContext('Analyze this CVE', [ioc]);
      expect(context).toContain('CISA KEV: unavailable');
      expect(context).toContain('PRESENT IN THE ENVIRONMENT');
      expect(context).not.toContain('PRIORITY: PATCH NOW');
      expect(context).not.toContain('not listed');
      expect(fetch).not.toHaveBeenCalled();
    });
  }
});

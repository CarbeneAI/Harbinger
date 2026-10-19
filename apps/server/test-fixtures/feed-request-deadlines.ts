import assert from 'node:assert/strict';
import { join } from 'node:path';
import type { FeedName } from '../src/types';

const scenario = process.argv[2]!;
const root = process.argv[3]!;
// The optional joined check is run only in the composition with cycle coordination.
const joined = process.argv[4] === 'joined';
const names: FeedName[] = ['cisa_kev', 'urlhaus', 'threatfox'];
const target = names.find(name => scenario.endsWith(`-${name}`)) ?? 'cisa_kev';
const counts = { cisa_kev: 1, urlhaus: 2, threatfox: 1 };
const originalTimeout = globalThis.setTimeout;
const originalNativeTimeout = AbortSignal.timeout;
const originalFetch = globalThis.fetch;
const originalLog = console.log;
const originalError = console.error;
const errors: string[] = [];
let requestCount = 0;
let targetRequests = 0;
let deadlines = 0;
let serverCancelled = false;
let rescued = false;
let phase = 1;
let stream: ReadableStreamDefaultController<Uint8Array> | undefined;
let releaseHeaders!: () => void;
const headersGate = new Promise<void>(resolve => { releaseHeaders = resolve; });
let receivedHeaders = false;
let rescue: ReturnType<typeof setTimeout> | undefined;
let reset: ReturnType<typeof setTimeout> | undefined;
const start = performance.now();
const encoder = new TextEncoder();
function payload(name: FeedName): object {
  if (name === 'cisa_kev') return {
    catalogVersion: '2026.10.01', dateReleased: '2026-10-01T00:00:00Z', count: 1,
    vulnerabilities: [{ cveID: 'CVE-2026-12345', vendorProject: 'Synthetic', product: 'Fixture',
      vulnerabilityName: 'Fixture vulnerability', shortDescription: 'Offline evidence', dateAdded: '2026-10-01' }],
  };
  if (name === 'urlhaus') return { query_status: 'ok', urls: [{
    url: 'http://malware.example.invalid/payload', url_status: 'offline', threat: 'malware_download',
    date_added: '2026-10-01 01:02:03 UTC',
  }] };
  return { query_status: 'ok', data: [{ ioc_type: 'domain', ioc: 'c2.example.invalid',
    confidence_level: 80, malware: 'synthetic.family', tags: ['synthetic'],
    first_seen: '2026-10-01 01:02:03 UTC', last_seen: null }] };
}
async function until(predicate: () => boolean) {
  const end = performance.now() + 3000;
  while (!predicate()) {
    assert.ok(performance.now() < end, 'fixture state did not settle');
    await Bun.sleep(5);
  }
}
function rescueHeld() {
  rescued = true;
  releaseHeaders();
  if (stream && !serverCancelled) {
    stream.enqueue(encoder.encode('}'));
    stream.close();
  }
}
const server = Bun.serve({
  hostname: '127.0.0.1', port: 0,
  async fetch(request) {
    const name = new URL(request.url).pathname.slice(1) as FeedName;
    assert.ok(names.includes(name));
    requestCount++;
    if (name !== 'cisa_kev') assert.equal(request.headers.get('Auth-Key'), 'synthetic-loopback-key');
    if (name === 'threatfox') {
      assert.equal(request.method, 'POST');
      assert.equal(request.headers.get('Content-Type'), 'application/json');
      assert.deepEqual(await request.json(), { query: 'get_iocs', days: 7 });
    } else assert.equal(request.method, 'GET');
    if (name === target) targetRequests++;
    if (name !== target || phase > 1 || scenario === 'success-native-deadline') return Response.json(payload(name));
    if (scenario === 'headers') {
      await headersGate;
      return Response.json(payload(name));
    }
    if (scenario === 'malformed-json') return new Response('{invalid', { headers: { 'Content-Type': 'application/json' } });
    return new Response(new ReadableStream<Uint8Array>({
      start(controller) {
        stream = controller;
        // Headers and some bytes arrive, while the remainder stays on the server.
        controller.enqueue(encoder.encode('{"held":'));
      },
      cancel() { serverCancelled = true; },
    }), { status: scenario.startsWith('http-error-') ? 503 : 200,
      headers: { 'Content-Type': 'application/json' } });
  },
});
const origin = `http://127.0.0.1:${server.port}`;
process.env.DB_PATH = join(root, 'fixture.db');
process.env.ABUSE_CH_AUTH_KEY = 'synthetic-loopback-key';
process.env.CISA_KEV_URL = `${origin}/cisa_kev`;
process.env.URLHAUS_URL = `${origin}/urlhaus`;
process.env.THREATFOX_URL = `${origin}/threatfox`;
for (const key of ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy',
  'WAZUH_DASHBOARD_URL', 'WAZUH_DASHBOARD_PASSWORD', 'WAZUH_CA_FILE', 'WAZUH_INSECURE_TLS']) delete process.env[key];
console.log = () => {};
console.error = (...args: unknown[]) => { errors.push(args.map(String).join(' ')); };
// Shorten only the existing policy clock. No configurable product deadline is added.
const testDelay = scenario.startsWith('http-error-') ? 1500 : 180;
AbortSignal.timeout = ((delay: number) => {
  assert.equal(delay, 30_000);
  deadlines++;
  return originalNativeTimeout(scenario === 'success-native-deadline' ? delay : testDelay);
}) as typeof AbortSignal.timeout;
globalThis.setTimeout = ((callback: (...args: any[]) => void, delay?: number, ...args: any[]) => {
  if (delay === 30_000) {
    deadlines++;
    return originalTimeout(callback, scenario === 'success-native-deadline' ? delay : testDelay, ...args);
  }
  return originalTimeout(callback, delay, ...args);
}) as typeof setTimeout;
globalThis.fetch = (async (input: string | URL | Request, options?: RequestInit) => {
  const url = new URL(input instanceof Request ? input.url : String(input));
  assert.equal(url.origin, origin, 'fixture must not contact external services');
  const response = await originalFetch(input, options);
  if (url.pathname === `/${target}` && phase === 1) {
    receivedHeaders = true;
    if (scenario === 'reset-body') reset = originalTimeout(() => stream?.error(new Error('synthetic stream reset')), 20);
  }
  return response;
}) as typeof fetch;
const database = await import('../src/db');
const db = database.initDB();
for (const name of names) database.upsertFeed(name, `${origin}/${name}`);
const targetId = database.getFeeds().find(feed => feed.name === target)!.id;
database.upsertIOC(targetId, { ioc_type: 'domain', value: 'historical.example.invalid', severity: 'low', first_seen: 1, last_seen: 1 });
database.updateFeedStatus(target, 'ok', { lastCount: 9 });
db.exec('CREATE TABLE fixture_effects(feed_id INTEGER, kind TEXT);');
db.exec(`CREATE TRIGGER count_insert AFTER INSERT ON iocs BEGIN INSERT INTO fixture_effects VALUES (NEW.feed_id, 'ioc'); END;`);
db.exec(`CREATE TRIGGER count_update AFTER UPDATE ON iocs BEGIN INSERT INTO fixture_effects VALUES (NEW.feed_id, 'ioc'); END;`);
db.exec(`CREATE TRIGGER count_ok AFTER UPDATE ON feeds WHEN NEW.status = 'ok' BEGIN INSERT INTO fixture_effects VALUES (NEW.id, 'ok'); END;`);
const effects = (kind: string) => (db.query('SELECT COUNT(*) AS n FROM fixture_effects WHERE feed_id = ? AND kind = ?').get(targetId, kind) as { n: number }).n;
const status = () => database.getFeeds().find(feed => feed.name === target)!;
const { pollAllFeeds } = await import('../src/feeds');
try {
  if (scenario !== 'success-native-deadline' && scenario !== 'malformed-json') rescue = originalTimeout(rescueHeld, 1400);
  const active = pollAllFeeds();
  if (joined) {
    await until(() => receivedHeaders);
    const other = pollAllFeeds();
    assert.equal(other, active, 'a held body must retain the active cycle');
    assert.equal(targetRequests, 1);
  }
  await active;
  assert.equal(requestCount, 3);
  assert.equal(deadlines, 3);
  assert.equal(rescued, false, 'the request must settle without fixture rescue');
  for (const peer of database.getFeeds().filter(feed => feed.name !== target)) assert.equal(peer.status, 'ok');
  if (scenario === 'success-native-deadline') {
    assert.equal(status().status, 'ok');
    assert.equal(status().last_count, counts[target]);
    assert.equal(effects('ioc'), counts[target]);
    assert.equal(errors.length, 0);
  } else {
    assert.equal(status().status, 'error');
    assert.equal(status().last_count, 9, 'failed body must preserve historical count');
    assert.equal(effects('ioc'), 0, 'failed body must not import any target IOC');
    assert.equal(effects('ok'), 0);
    assert.equal(errors.length, 1);
    if (scenario === 'headers') assert.equal(receivedHeaders, false);
    else assert.equal(receivedHeaders, true);
    if (scenario.startsWith('body-') || scenario.startsWith('http-error-')) {
      await until(() => serverCancelled);
      assert.throws(() => stream!.enqueue(encoder.encode('null}')), TypeError, 'canceled stream must reject a late body write');
      if (scenario.startsWith('http-error-')) {
        assert.ok(performance.now() - start < 1000, 'HTTP rejection must cancel before its native 1500ms deadline');
        const label = { cisa_kev: 'CISA KEV', urlhaus: 'URLhaus', threatfox: 'ThreatFox' }[target];
        assert.ok(status().error_msg?.includes(`${label} returned HTTP 503`), 'preserve caller status diagnostic');
      }
    }
    clearTimeout(rescue);
    releaseHeaders();
    const before = effects('ioc');
    await Bun.sleep(25);
    assert.equal(effects('ioc'), before, 'a late old response must not import');
    phase = 2;
    await pollAllFeeds();
    assert.equal(requestCount, 6);
    assert.equal(deadlines, 6);
    assert.equal(status().status, 'ok');
    assert.equal(status().error_msg, null);
    assert.equal(status().last_count, counts[target]);
    assert.equal(effects('ioc'), counts[target]);
    assert.equal(effects('ok'), 1);
  }
  originalLog(JSON.stringify({ scenario, joined, elapsed_ms: Math.round(performance.now() - start), serverCancelled, requests: requestCount }));
} finally {
  clearTimeout(rescue);
  clearTimeout(reset);
  releaseHeaders();
  server.stop(true);
  db.close();
  globalThis.fetch = originalFetch;
  globalThis.setTimeout = originalTimeout;
  AbortSignal.timeout = originalNativeTimeout;
  console.log = originalLog;
  console.error = originalError;
}
// No process.exit: a completed request's native deadline must not hold the child open.

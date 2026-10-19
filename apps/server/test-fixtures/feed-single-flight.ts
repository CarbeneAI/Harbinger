import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { envelope, feeds, row } from './feed-cases';
import type { FeedName } from '../src/types';

const scenario = process.argv[2]!;
const root = mkdtempSync(join(tmpdir(), 'harbinger-feed-single-flight-'));
const now = 1_792_411_200_000;
process.env.DB_PATH = join(root, 'fixture.db');
process.env.ABUSE_CH_AUTH_KEY = 'synthetic-offline-key';
process.env.POLL_INTERVAL_MS = '123456';
process.env.PORT = '0';
process.env.HARBINGER_API_HOST = '127.0.0.1';
process.env.CORS_ALLOWED_ORIGIN = 'http://127.0.0.1:5174';
delete process.env.HARBINGER_ALLOWED_HOSTS;
delete process.env.WAZUH_DASHBOARD_URL;
delete process.env.WAZUH_DASHBOARD_PASSWORD;
delete process.env.WAZUH_CA_FILE;
delete process.env.WAZUH_INSECURE_TLS;
for (const [key, name] of [['CISA_KEV_URL', 'cisa_kev'], ['URLHAUS_URL', 'urlhaus'], ['THREATFOX_URL', 'threatfox']]) {
  process.env[key] = `https://feed-single-flight.invalid/${name}`;
}
const database = await import('../src/db');
const db = database.initDB();
for (const name of feeds) database.upsertFeed(name, `https://feed-single-flight.invalid/${name}`);
db.exec('CREATE TABLE fixture_effects(kind TEXT);');
db.exec(`CREATE TRIGGER count_insert AFTER INSERT ON iocs BEGIN INSERT INTO fixture_effects VALUES ('ioc'); END;`);
db.exec(`CREATE TRIGGER count_update AFTER UPDATE ON iocs BEGIN INSERT INTO fixture_effects VALUES ('ioc'); END;`);
db.exec(`CREATE TRIGGER count_status AFTER UPDATE ON feeds WHEN NEW.status = 'ok' BEGIN INSERT INTO fixture_effects VALUES ('status'); END;`);
const count = (kind: string) => (db.query('SELECT COUNT(*) AS n FROM fixture_effects WHERE kind = ?').get(kind) as { n: number }).n;
const ftsSchema = (db.query("SELECT sql FROM sqlite_master WHERE name = 'iocs_fts'").get() as { sql: string }).sql;
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(yes => { resolve = yes; });
  return { promise, resolve };
}
const heldFetch = deferred<Response>();
const heldJson = deferred<unknown>();
const turn = () => new Promise<void>(resolve => setImmediate(resolve));
async function until(predicate: () => boolean) {
  const deadline = originalNow() + 2000;
  while (!predicate()) {
    assert.ok(originalNow() < deadline, 'fixture state did not settle');
    await Bun.sleep(5);
  }
}
const originalFetch = globalThis.fetch;
const originalInterval = globalThis.setInterval;
const originalLog = console.log;
const originalError = console.error;
const originalNow = Date.now;
const originalServe = Bun.serve;
const intervals: { callback: () => void; delay: number | undefined }[] = [];
const errors: string[] = [];
let requests = 0;
let cycles = 0;
let rebuilds = 0;
let finishes = 0;
let failure = true;
let reentered = false;
let poll!: () => Promise<void>;
let scheduler!: () => void;
let active: Promise<void> | undefined;
const reentries: Promise<void>[] = [];
let server: ReturnType<typeof Bun.serve> | undefined;
function reenter() {
  if (reentered) return;
  reentered = true;
  const joined = poll();
  joined.catch(() => {});
  reentries.push(joined);
}
globalThis.setInterval = ((callback: () => void, delay?: number) => {
  intervals.push({ callback, delay });
  return intervals.length as unknown as ReturnType<typeof setInterval>;
}) as typeof setInterval;
console.error = (...args: unknown[]) => { errors.push(args.map(String).join(' ')); };
console.log = (...args: unknown[]) => {
  const text = String(args[0]);
  if (text.startsWith('[feeds] Starting poll cycle')) cycles++;
  if (text === '[feeds] FTS index rebuilt') {
    rebuilds++;
    if (scenario === 'fts-reentry') reenter();
    if (scenario === 'stats-recovery' && failure) db.exec('ALTER TABLE feeds RENAME TO unavailable_feeds');
  }
  if (text.startsWith('[feeds] Poll cycle complete')) {
    finishes++;
    if (scenario === 'final-log-reentry') reenter();
  }
};
const payload = (feed: FeedName) => envelope(feed, [row(feed)]);
globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
  const url = new URL(input instanceof Request ? input.url : String(input));
  if (server && url.origin === `http://127.0.0.1:${server.port}`) return originalFetch(input, init);
  assert.equal(url.origin, 'https://feed-single-flight.invalid', 'fixture cannot contact external services');
  const feed = url.pathname.slice(1) as FeedName;
  assert.ok(feeds.includes(feed));
  assert.equal(db.inTransaction, false, 'fetch must stay outside the SQLite transaction');
  requests++;
  if (feed === 'cisa_kev') {
    if (scenario === 'fetch-reentry') reenter();
    if (scenario === 'scheduler-fetch-reentry' && !reentered) { reentered = true; scheduler(); }
    if (failure && scenario === 'held-fetch') return heldFetch.promise;
    if (failure && ['held-json', 'manual-http'].includes(scenario)) {
      const response = Response.json({});
      Object.defineProperty(response, 'json', { value: () => heldJson.promise });
      return response;
    }
    if (failure && ['fetch-recovery', 'status-recovery'].includes(scenario)) throw new Error('synthetic fetch failure');
    if (failure && scenario === 'json-recovery') return new Response('{invalid JSON');
    if (failure && scenario === 'validation-recovery') return Response.json(envelope(feed, [row(feed), null]));
  }
  return Response.json(payload(feed));
}) as typeof fetch;

let exitCode = 0;
try {
  const module = await import('../src/feeds');
  poll = module.pollAllFeeds;
  scheduler = module.startFeedScheduler;
  if (scenario === 'import-reentry') {
    // Instrument the real connection at statement preparation; writes and
    // transactions still execute in SQLite, with no mocked persistence layer.
    const originalQuery = db.query.bind(db);
    db.query = ((sql: string) => {
      if (sql.trimStart().startsWith('INSERT INTO iocs')) reenter();
      return originalQuery(sql);
    }) as typeof db.query;
  }
  if (scenario === 'import-recovery') db.exec(`CREATE TRIGGER fail_import BEFORE INSERT ON iocs WHEN NEW.ioc_type = 'cve' BEGIN SELECT RAISE(ABORT, 'synthetic IOC write failure'); END;`);
  if (scenario === 'status-recovery') db.exec(`CREATE TRIGGER fail_status BEFORE UPDATE ON feeds WHEN NEW.status = 'error' BEGIN SELECT RAISE(ABORT, 'synthetic status write failure'); END;`);
  if (scenario === 'fts-recovery') db.exec('DROP TABLE iocs_fts');
  if (scenario === 'initial-read-recovery') db.exec('ALTER TABLE feeds RENAME TO unavailable_feeds');

  if (scenario === 'manual-http') {
    // Bind the real production entrypoint only to an owned ephemeral loopback port.
    Bun.serve = ((options: any) => {
      server = originalServe({ ...options, hostname: '127.0.0.1', port: 0 });
      return server;
    }) as typeof Bun.serve;
    await import('../src/index');
    await turn();
    assert.ok(server);
    assert.equal(requests, 3);
    assert.equal(count('ioc'), 3, 'peer feeds can commit while CISA body is held');
    for (let i = 0; i < 2; i++) {
      const response: Response = await fetch(`http://127.0.0.1:${server.port}/feeds/poll`, { method: 'POST' });
      assert.equal(response.status, 200);
      assert.deepEqual(await response.json(), { triggered: true, message: 'Poll started or already running' });
    }
    intervals[0]!.callback();
    await turn();
    assert.equal(requests, 3, 'manual and scheduled callers join the held initial cycle');
    active = poll();
    heldJson.resolve(payload('cisa_kev'));
    await active;
    assert.equal(count('ioc'), 4);
    assert.equal(rebuilds, 1);
    assert.equal(finishes, 1);
    await fetch(`http://127.0.0.1:${server.port}/feeds/poll`, { method: 'POST' });
    await until(() => finishes === 2);
    assert.equal(requests, 6, 'later manual request starts exactly one new cycle');
    assert.equal(count('ioc'), 8);
  } else if (scenario.startsWith('scheduler-')) {
    if (scenario === 'scheduler-fresh') db.exec(`UPDATE feeds SET last_poll = ${now}, status = 'ok'`);
    if (scenario === 'scheduler-init-retry') {
      db.exec('ALTER TABLE feeds RENAME TO unavailable_feeds');
      assert.throws(scheduler, /feeds/);
      assert.equal(intervals.length, 0, 'failed initialization must not claim a timer');
      db.exec('ALTER TABLE unavailable_feeds RENAME TO feeds');
    }
    Date.now = () => now;
    scheduler(); scheduler(); scheduler();
    await turn();
    assert.equal(intervals.length, 1, 'repeated starts must install one interval');
    assert.equal(intervals[0]!.delay, 123456);
    if (scenario === 'scheduler-fresh') {
      assert.equal(requests, 0, 'fresh feeds do not trigger an initial cycle');
      intervals[0]!.callback();
    }
    await until(() => finishes === 1);
    assert.equal(requests, 3, 'stale/start reentry must start only one immediate cycle');
    if (scenario === 'scheduler-fetch-reentry') assert.equal(reentered, true);
    scheduler();
    assert.equal(intervals.length, 1);
    assert.equal(requests, 3, 'repeated starts after completion do not restart polling');
    intervals[0]!.callback();
    await until(() => finishes === 2);
    assert.equal(requests, 6);
    assert.equal(count('ioc'), 8);
  } else {
    active = poll();
    active.catch(() => {});
    const joined = poll();
    joined.catch(() => {});
    await turn();
    assert.equal(requests, scenario === 'initial-read-recovery' ? 0 : 3, 'joined callers must fetch each feed once');
    assert.strictEqual(joined, active, 'concurrent callers must receive the active cycle promise');
    assert.equal(cycles, 1, 'concurrent requests do not queue a second cycle');
    if (['held-fetch', 'held-json'].includes(scenario)) {
      assert.equal(requests, 3);
      assert.equal(count('ioc'), 3);
      assert.equal(rebuilds, 0);
      assert.equal(finishes, 0);
      assert.strictEqual(poll(), active, 'ownership must remain through response body consumption');
      failure = false;
      heldFetch.resolve(Response.json(payload('cisa_kev')));
      heldJson.resolve(payload('cisa_kev'));
    }
    if (['initial-read-recovery', 'stats-recovery'].includes(scenario)) {
      await assert.rejects(active, /feeds/);
      assert.equal(requests, scenario === 'initial-read-recovery' ? 0 : 3);
      assert.equal(count('ioc'), scenario === 'initial-read-recovery' ? 0 : 4, 'stats failure does not undo prior commits');
      db.exec('ALTER TABLE unavailable_feeds RENAME TO feeds');
    } else if (scenario === 'fts-recovery') {
      await assert.rejects(active, { message: 'Feed search index rebuild failed' });
      assert.equal(finishes, 0, 'a failed rebuild must not report cycle completion');
    } else await active;
    for (const reentry of reentries) assert.strictEqual(reentry, active, 'the guard must cover fetch, import, FTS and final logging');
    if (scenario.endsWith('-reentry')) assert.equal(reentered, true);
    assert.equal(rebuilds, scenario === 'fts-recovery' || scenario === 'initial-read-recovery' ? 0 : 1);
    if (['fetch-recovery', 'json-recovery', 'validation-recovery', 'import-recovery', 'status-recovery'].includes(scenario)) {
      assert.equal(count('ioc'), 3, 'peer feed commits remain independent');
      assert.equal(count('status'), 2);
      if (scenario !== 'status-recovery') assert.equal(database.getFeeds().find(f => f.name === 'cisa_kev')!.status, 'error');
    } else if (scenario !== 'initial-read-recovery') assert.equal(count('ioc'), 4);
    const priorRequests = requests;
    const priorWrites = count('ioc');
    failure = false;
    if (scenario === 'import-recovery') db.exec('DROP TRIGGER fail_import');
    if (scenario === 'status-recovery') db.exec('DROP TRIGGER fail_status');
    if (scenario === 'fts-recovery') db.exec(ftsSchema);
    const next = poll();
    assert.notStrictEqual(next, active, 'a settled cycle must release its slot');
    await next;
    assert.equal(requests, priorRequests + 3);
    assert.equal(count('ioc'), priorWrites + 4);
    assert.ok(database.getFeeds().every(f => f.status === 'ok'));
    assert.equal(database.queryIOCs({ search: 'Synthetic' }).total, 2, 'later imports remain searchable');
  }
} catch (error) {
  originalError(error);
  exitCode = 1;
} finally {
  failure = false;
  heldFetch.resolve(Response.json(payload('cisa_kev')));
  heldJson.resolve(payload('cisa_kev'));
  await turn();
  server?.stop(true);
  globalThis.fetch = originalFetch;
  globalThis.setInterval = originalInterval;
  Date.now = originalNow;
  Bun.serve = originalServe;
  console.log = originalLog;
  console.error = originalError;
  db.close();
  rmSync(root, { recursive: true, force: true });
}
process.exit(exitCode);

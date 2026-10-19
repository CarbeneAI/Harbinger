import assert from 'node:assert/strict';
import { Database } from 'bun:sqlite';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { envelope, feeds, row } from './feed-cases';
import type { FeedName } from '../src/types';

const scenario = process.argv[2]!;
const root = mkdtempSync(join(tmpdir(), 'harbinger-fts-recovery-'));
process.env.DB_PATH = join(root, 'fixture.sqlite');
process.env.ABUSE_CH_AUTH_KEY = 'synthetic-offline-key';
process.env.PORT = '0';
process.env.HARBINGER_API_HOST = '127.0.0.1';
process.env.CORS_ALLOWED_ORIGIN = 'http://127.0.0.1:5174';
for (const key of ['HARBINGER_ALLOWED_HOSTS', 'WAZUH_DASHBOARD_URL', 'WAZUH_DASHBOARD_PASSWORD',
  'WAZUH_CA_FILE', 'WAZUH_INSECURE_TLS']) delete process.env[key];
for (const [key, feed] of [['CISA_KEV_URL', 'cisa_kev'], ['URLHAUS_URL', 'urlhaus'], ['THREATFOX_URL', 'threatfox']]) {
  process.env[key] = `https://owned-fts-fixture.invalid/${feed}`;
}
const originalExec = Database.prototype.exec;
const originalFetch = globalThis.fetch;
const originalInterval = globalThis.setInterval;
const originalServe = Bun.serve;
const originalLog = console.log;
const originalError = console.error;
const connections = new Set<Database>();
const logs: string[] = [];
const errors: string[] = [];
const logReentries: Promise<void>[] = [];
const intervals: (() => void)[] = [];
let requests = 0;
let failedRebuilds = 0;
let successfulRebuilds = 0;
let injectFailure = true;
let hold = true;
let active: Promise<void> | undefined;
let poll!: () => Promise<void>;
let server: ReturnType<typeof Bun.serve> | undefined;
let release!: (response: Response) => void;
const heldFetch = new Promise<Response>(resolve => { release = resolve; });
const stageError = 'Feed search index rebuild failed';
const payload = (feed: FeedName) => envelope(feed, [row(feed)]);
const turn = () => new Promise<void>(resolve => setImmediate(resolve));
async function until(predicate: () => boolean) {
  const end = Date.now() + 2000;
  while (!predicate()) {
    assert.ok(Date.now() < end, 'fixture state did not settle');
    await Bun.sleep(5);
  }
}
// The production entrypoint opens another connection. Instrument all owned
// connections at the rebuild boundary; the statement and SQLite failure are real.
Database.prototype.exec = function(sql: string, ...args: any[]) {
  connections.add(this);
  if (!sql.includes("VALUES('rebuild')")) return originalExec.call(this, sql, ...args);
  if (!injectFailure) {
    const result = originalExec.call(this, sql, ...args);
    successfulRebuilds++;
    return result;
  }
  const state = this.query('PRAGMA query_only').get() as { query_only: number };
  assert.equal(state.query_only, 0);
  originalExec.call(this, 'PRAGMA query_only = ON');
  try {
    return originalExec.call(this, sql, ...args);
  } catch (error) {
    assert.match(String(error), /readonly|read.only/i);
    failedRebuilds++;
    throw error;
  } finally {
    originalExec.call(this, 'PRAGMA query_only = OFF');
    assert.equal((this.query('PRAGMA query_only').get() as { query_only: number }).query_only, 0);
  }
};
console.log = (...args: unknown[]) => logs.push(args.map(String).join(' '));
console.error = (...args: unknown[]) => {
  const text = args.map(String).join(' ');
  errors.push(text);
  if (scenario === 'repeated-log-reentry' && text.startsWith('[feeds] FTS rebuild failed:')) {
    const joined = poll();
    joined.catch(() => {});
    logReentries.push(joined); // Await outside this synchronous logging hook.
    assert.strictEqual(joined, active);
  }
};
globalThis.setInterval = ((callback: () => void) => {
  intervals.push(callback);
  return intervals.length as unknown as ReturnType<typeof setInterval>;
}) as typeof setInterval;
globalThis.fetch = (async (input: RequestInfo | URL, options?: RequestInit) => {
  const url = new URL(input instanceof Request ? input.url : String(input));
  if (server && url.origin === `http://127.0.0.1:${server.port}`) return originalFetch(input, options);
  assert.equal(url.origin, 'https://owned-fts-fixture.invalid', 'no external request is allowed');
  const feed = url.pathname.slice(1) as FeedName;
  assert.ok(feeds.includes(feed));
  requests++;
  if (feed === 'cisa_kev' && hold) return heldFetch;
  return Response.json(payload(feed));
}) as typeof fetch;
const database = await import('../src/db');
const db = database.initDB();
for (const feed of feeds) database.upsertFeed(feed, `https://owned-fts-fixture.invalid/${feed}`);
const summaries = () => logs.filter(text => text.startsWith('[feeds] Poll cycle complete')).length;
function preservedState() {
  assert.equal(database.queryIOCs({}).total, 4, 'successful feed commits must remain visible');
  assert.equal(database.queryIOCs({ search: 'Synthetic' }).total, 0, 'the failed rebuild leaves derived search stale');
  const statuses = database.getFeeds();
  assert.equal(statuses.length, 3);
  for (const feed of statuses) {
    assert.equal(feed.status, 'ok');
    assert.equal(feed.error_msg, null);
    assert.equal(feed.last_count, feed.name === 'urlhaus' ? 2 : 1);
    assert.ok(feed.last_poll !== null);
  }
}
async function rejectedTogether(promises: Promise<void>[]) {
  const results = await Promise.allSettled(promises);
  for (const result of results) {
    assert.equal(result.status, 'rejected', 'FTS failure must reject every cycle joiner');
    if (result.status === 'rejected') {
      assert.ok(result.reason instanceof Error);
      assert.equal(result.reason.message, stageError);
      assert.strictEqual(result.reason, (results[0] as PromiseRejectedResult).reason);
    }
  }
}
try {
  ({ pollAllFeeds: poll } = await import('../src/feeds'));
  if (scenario === 'manual-http') {
    Bun.serve = ((options: any) => {
      server = originalServe({ ...options, hostname: '127.0.0.1', port: 0 });
      return server;
    }) as typeof Bun.serve;
    await import('../src/index');
    await until(() => requests === 3);
    assert.ok(server);
    active = poll();
    const response = await fetch(`http://127.0.0.1:${server.port}/feeds/poll`, { method: 'POST' });
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { triggered: true, message: 'Poll started or already running' });
    assert.equal(failedRebuilds, 0, 'acknowledgement precedes the held cycle outcome');
    intervals[0]!();
  } else active = poll();
  const joined = poll();
  const settlement = rejectedTogether([active, joined]);
  assert.strictEqual(joined, active);
  await until(() => requests === 3);
  await turn();
  assert.equal(database.queryIOCs({}).total, 3, 'peer imports complete while CISA is held');
  assert.equal(summaries(), 0);
  assert.strictEqual(poll(), active, 'ownership stays held until actual settlement');
  hold = false;
  release(Response.json(payload('cisa_kev')));
  await settlement;
  await turn();
  assert.equal(failedRebuilds, 1);
  assert.equal(summaries(), 0, 'failed indexing must not print normal cycle completion');
  preservedState();
  if (scenario === 'repeated-log-reentry') {
    const prior = active;
    active = poll();
    assert.notStrictEqual(active, prior, 'a failed attempt must release ownership');
    const second = poll();
    assert.strictEqual(second, active);
    await rejectedTogether([active, second]);
    assert.equal(failedRebuilds, 2);
    assert.equal(requests, 6, 'failure-log reentry must not queue extra imports');
    assert.equal(logReentries.length, 2);
    for (const reentry of logReentries) await rejectedTogether([reentry]);
    preservedState();
    assert.equal(summaries(), 0);
  }
  if (scenario === 'manual-http') {
    assert.ok(errors.some(text => text === '[feeds] Manual poll error: Error: ' + stageError));
    assert.ok(errors.some(text => text === '[feeds] Scheduled poll error: Error: ' + stageError));
  }
  const prior = active;
  const priorRequests = requests;
  injectFailure = false;
  if (scenario === 'manual-http') {
    const response = await fetch(`http://127.0.0.1:${server!.port}/feeds/poll`, { method: 'POST' });
    assert.equal(response.status, 200);
    await until(() => summaries() === 1);
  } else {
    active = poll();
    assert.notStrictEqual(active, prior);
    await active;
  }
  assert.equal(requests, priorRequests + 3);
  assert.equal(database.queryIOCs({}).total, 4, 'retry must not create duplicate logical IOCs');
  assert.equal(database.queryIOCs({ search: 'Synthetic' }).total, 2, 'native rebuild must restore MATCH search');
  assert.equal(successfulRebuilds, 1);
  assert.equal(summaries(), 1);
  assert.ok(database.getFeeds().every(feed => feed.status === 'ok'));
} finally {
  injectFailure = false;
  hold = false;
  release(Response.json(payload('cisa_kev')));
  await active?.catch(() => {});
  await turn();
  server?.stop(true);
  globalThis.fetch = originalFetch;
  globalThis.setInterval = originalInterval;
  Bun.serve = originalServe;
  console.log = originalLog;
  console.error = originalError;
  Database.prototype.exec = originalExec;
  for (const connection of connections) connection.close();
  rmSync(root, { recursive: true, force: true });
}

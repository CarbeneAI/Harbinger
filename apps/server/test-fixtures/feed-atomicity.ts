import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { FeedName } from '../src/types';
import { envelope, feeds, row } from './feed-cases';

const scenario = process.argv[2];
const directory = mkdtempSync(join(tmpdir(), 'harbinger-feed-atomicity-'));
process.env.DB_PATH = join(directory, 'fixture.db');
process.env.ABUSE_CH_AUTH_KEY = 'synthetic-offline-key';
for (const [key, name] of [['CISA_KEV_URL', 'cisa_kev'], ['URLHAUS_URL', 'urlhaus'], ['THREATFOX_URL', 'threatfox']]) {
  process.env[key] = `https://feed-atomicity.invalid/${name}`;
}
// Set DB_PATH before importing: no developer database is opened.
const database = await import('../src/db');
const db = database.initDB();
const originalFetch = globalThis.fetch;
try {
  const ids = Object.fromEntries(feeds.map(name => [name, database.upsertFeed(name, `https://feed-atomicity.invalid/${name}`).id])) as Record<FeedName, number>;
  const target: FeedName = scenario === 'domain-rollback' ? 'urlhaus' : scenario === 'threatfox-rollback' ? 'threatfox' : 'cisa_kev';
  db.query("UPDATE feeds SET status = 'ok', last_count = 9, last_poll = 1 WHERE name = ?").run(target);
  const payloads = Object.fromEntries(feeds.map(name => [name, envelope(name, [row(name)])])) as Record<FeedName, unknown>;
  const historical = {
    ioc_type: 'cve' as const, value: 'CVE-2026-12345', severity: 'low' as const,
    title: 'Historical title', description: 'Historical description', source_ref: 'https://history.invalid',
    tags: ['historical'], first_seen: 1, last_seen: 2,
  };
  if (scenario === 'overwrite-rollback' || scenario === 'empty') database.upsertIOC(ids.threatfox, historical);
  const previousRow = db.query('SELECT * FROM iocs WHERE value = ?').get(historical.value);
  const failure = 'synthetic transaction failure';
  if (['insert-rollback', 'overwrite-rollback', 'retry'].includes(scenario)) {
    payloads.cisa_kev = envelope('cisa_kev', [row('cisa_kev'), { ...row('cisa_kev'), cveID: 'CVE-2026-99999' }]);
    db.exec(`CREATE TRIGGER fail_import BEFORE INSERT ON iocs WHEN NEW.value = 'CVE-2026-99999' BEGIN SELECT RAISE(ABORT, 'synthetic transaction failure'); END;`);
  } else if (scenario === 'domain-rollback') {
    db.exec(`CREATE TRIGGER fail_import BEFORE INSERT ON iocs WHEN NEW.ioc_type = 'domain' AND NEW.feed_id = ${ids.urlhaus} BEGIN SELECT RAISE(ABORT, 'synthetic transaction failure'); END;`);
  } else if (scenario === 'threatfox-rollback') {
    payloads.threatfox = envelope('threatfox', [row('threatfox'), { ...row('threatfox'), ioc: 'failed.example.invalid' }]);
    db.exec(`CREATE TRIGGER fail_import BEFORE INSERT ON iocs WHEN NEW.value = 'failed.example.invalid' BEGIN SELECT RAISE(ABORT, 'synthetic transaction failure'); END;`);
  } else if (scenario === 'status-rollback') {
    db.exec(`CREATE TRIGGER fail_import BEFORE UPDATE ON feeds WHEN NEW.name = 'cisa_kev' AND NEW.status = 'ok' BEGIN SELECT RAISE(ABORT, 'synthetic transaction failure'); END;`);
  } else if (scenario === 'empty') {
    payloads.cisa_kev = envelope('cisa_kev', []);
  } else if (scenario === 'duplicates') {
    payloads.cisa_kev = envelope('cisa_kev', [row('cisa_kev'), row('cisa_kev')]);
  } else { throw new Error('Unknown fixture scenario'); }
  let requests = 0;
  globalThis.fetch = (async (input: string | URL | Request) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    assert.equal(url.origin, 'https://feed-atomicity.invalid');
    const feed = url.pathname.slice(1) as FeedName;
    assert.ok(feeds.includes(feed));
    assert.equal(db.inTransaction, false, 'network requests must not hold SQLite transactions');
    requests++;
    return Response.json(payloads[feed]);
  }) as typeof fetch;
  const { pollAllFeeds } = await import('../src/feeds');
  await pollAllFeeds();
  assert.equal(requests, 3);
  assert.equal(db.inTransaction, false, 'failed transactions must be closed');
  const status = () => database.getFeeds().find(feed => feed.name === target)!;
  const count = () => (db.query('SELECT COUNT(*) AS count FROM iocs WHERE feed_id = ?').get(ids[target]) as { count: number }).count;
  if (!['empty', 'duplicates'].includes(scenario)) {
    assert.equal(status().status, 'error', 'a database failure must fail the whole feed');
    assert.equal(status().error_msg, failure);
    assert.equal(status().last_count, 9, 'failed batches preserve the previous successful count');
    assert.equal(count(), 0, 'no rows from the failed batch may remain');
    if (target === 'cisa_kev') assert.deepEqual(db.query('SELECT * FROM iocs WHERE value = ?').get(historical.value), previousRow, 'rollback restores all overwritten fields and feed ownership');
  } else {
    assert.equal(status().status, 'ok');
    assert.equal(status().error_msg, null);
    assert.equal(status().last_count, scenario === 'empty' ? 0 : 2);
    assert.equal(count(), scenario === 'empty' ? 0 : 1, 'counts describe operations, not distinct inserts');
    if (scenario === 'empty') assert.deepEqual(db.query('SELECT * FROM iocs WHERE value = ?').get(historical.value), previousRow);
  }
  // Independent feeds retain their commits and remain searchable after rebuild.
  for (const name of feeds.filter(name => name !== target)) {
    const peer = database.getFeeds().find(feed => feed.name === name)!;
    assert.equal(peer.status, 'ok');
    assert.equal(peer.last_count, name === 'urlhaus' ? 2 : 1);
    const search = name === 'cisa_kev' ? 'Synthetic' : name === 'urlhaus' ? 'malware' : 'synthetic';
    assert.ok(database.queryIOCs({ feed: name, search }).total > 0, `${name} must remain searchable`);
  }
  if (scenario === 'retry') {
    db.exec('DROP TRIGGER fail_import');
    await pollAllFeeds();
    assert.equal(requests, 6);
    assert.equal(status().status, 'ok');
    assert.equal(status().last_count, 2);
    assert.equal(status().error_msg, null, 'successful retry clears the previous error');
    assert.equal(count(), 2);
    assert.equal(database.queryIOCs({ feed: target, search: 'Synthetic' }).total, 2);
  }
} finally {
  globalThis.fetch = originalFetch;
  db.close();
  rmSync(directory, { recursive: true, force: true });
}

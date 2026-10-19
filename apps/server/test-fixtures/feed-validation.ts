import assert from 'node:assert/strict';
import { mock } from 'bun:test';
import type { FeedName } from '../src/types';
import { credentialSentinel, envelope, feedCases, feeds, rawSentinel, row } from './feed-cases';

const fixture = feedCases.find(entry => entry.name === process.argv[2]);
assert.ok(fixture, 'known fixture required');
process.env.ABUSE_CH_AUTH_KEY = credentialSentinel;
for (const [key, name] of [['CISA_KEV_URL', 'cisa_kev'], ['URLHAUS_URL', 'urlhaus'], ['THREATFOX_URL', 'threatfox']]) {
  process.env[key] = `https://feed-validation.invalid/${name}`;
}
const ids = { cisa_kev: 1, urlhaus: 2, threatfox: 3 };
const writes: { feed: FeedName; value: Record<string, any> }[] = [];
const statuses: { feed: FeedName; status: string; options: { lastCount?: number; errorMsg?: string } }[] = [];
let rebuilds = 0;
let initializations = 0;
const originalLog = console.log;
const originalError = console.error;
const messages: string[] = [];
console.log = (...values) => { messages.push(values.join(' ')); };
console.error = (...values) => { messages.push(values.join(' ')); };
mock.module('../src/db', () => ({
  upsertFeed: () => { initializations++; },
  updateFeedStatus: (feed: FeedName, status: string, options: { lastCount?: number; errorMsg?: string }) => { statuses.push({ feed, status, options }); },
  upsertIOC: (id: number, value: Record<string, any>) => {
    const feed = feeds.find(name => ids[name] === id);
    assert.ok(feed);
    writes.push({ feed, value });
  },
  rebuildFTS: () => { rebuilds++; },
  getFeeds: () => feeds.map(name => ({ id: ids[name], name })),
  getStats: () => ({ totalIOCs: writes.length }),
}));
const originalFetch = globalThis.fetch;
let requests = 0;
globalThis.fetch = (async (input: string | URL | Request) => {
  const url = new URL(input instanceof Request ? input.url : String(input));
  assert.equal(url.origin, 'https://feed-validation.invalid', 'all requests must hit the fixture stub');
  const feed = url.pathname.slice(1) as FeedName;
  assert.ok(feeds.includes(feed));
  requests++;
  if (feed === fixture.feed) {
    if (fixture.raw !== undefined) return new Response(fixture.raw);
    return Response.json(fixture.payload);
  }
  return Response.json(envelope(feed, [row(feed)]));
}) as typeof fetch;

try {
  const { pollAllFeeds } = await import('../src/feeds');
  const before = Date.now();
  await pollAllFeeds();
  const after = Date.now();
  assert.equal(requests, 3);
  assert.equal(initializations, 0, 'polling must not start the scheduler');
  assert.equal(rebuilds, 1, 'other successful feeds still rebuild FTS after settlement');
  assert.equal(statuses.length, 3);
  const expectedCounts = fixture.counts || [1, 2, 1];
  for (const [index, feed] of feeds.entries()) {
    const status = statuses.find(entry => entry.feed === feed)!;
    assert.ok(status);
    const rejected: boolean = Boolean(fixture.reject && fixture.feed === feed);
    const ownWrites = writes.filter(entry => entry.feed === feed);
    assert.equal(ownWrites.length, rejected ? 0 : expectedCounts[index], `${feed} must validate its whole response before first IOC write`);
    assert.equal(status.status, rejected ? 'error' : 'ok', feed);
    if (rejected) {
      assert.equal(status.options.lastCount, undefined);
      const feedLabel: string = { cisa_kev: 'CISA KEV', urlhaus: 'URLhaus', threatfox: 'ThreatFox' }[feed];
      assert.equal(status.options.errorMsg, `Invalid ${feedLabel} feed response`);
    } else {
      assert.equal(status.options.lastCount, expectedCounts[index]);
      assert.equal(status.options.errorMsg, undefined);
      for (const { value } of ownWrites) {
        assert.ok(Number.isFinite(value.first_seen) && Number.isFinite(value.last_seen));
        assert.ok(Array.isArray(value.tags) && value.tags.every((tag: unknown) => typeof tag === 'string'));
      }
    }
  }
  const text = messages.join('\n');
  assert.ok(!text.includes(rawSentinel), 'response-validation logs must not echo raw records or status values');
  assert.ok(!text.includes(credentialSentinel), 'response-validation diagnostics must not echo credentials');
  const succeeded = fixture.reject ? 2 : 3;
  assert.ok(text.includes(`${succeeded}/3 feeds OK`));
  assert.ok(text.includes(`${writes.length} IOCs this cycle`));
  if (fixture.mapping === 'defaults') {
    const kev = writes.find(entry => entry.feed === 'cisa_kev')!.value;
    assert.deepEqual(kev, { ioc_type: 'cve', value: 'CVE-2026-12345', severity: 'critical', title: 'Synthetic vulnerability',
      description: 'Synthetic description', source_ref: 'https://nvd.nist.gov/vuln/detail/CVE-2026-12345',
      tags: ['Synthetic vendor', 'Synthetic product'], first_seen: Date.parse('2026-10-01'), last_seen: Date.parse('2026-10-01') });
    const urls = writes.filter(entry => entry.feed === 'urlhaus').map(entry => entry.value);
    assert.deepEqual(urls.map(entry => [entry.ioc_type, entry.value, entry.severity, entry.tags]), [
      ['url', 'http://malware.example.invalid/payload', 'high', ['offline', 'malware_download']],
      ['domain', 'malware.example.invalid', 'high', ['offline', 'malware_download']],
    ]);
    const fox = writes.find(entry => entry.feed === 'threatfox')!.value;
    assert.equal(fox.severity, 'critical');
    assert.deepEqual(fox.tags, ['synthetic.family', 'synthetic']);
    assert.equal(fox.first_seen, Date.parse('2026-10-01 01:02:03 UTC'));
    assert.equal(fox.last_seen, fox.first_seen);
  }
  if (['threatfox-null-fallbacks', 'threatfox-absent-fallbacks', 'urlhaus-null-fallbacks-and-unused-tags', 'urlhaus-absent-fallbacks'].includes(fixture.name)) {
    for (const { value } of writes.filter(entry => entry.feed === fixture.feed)) {
      assert.ok(value.first_seen >= before && value.first_seen <= after);
      assert.equal(value.last_seen, value.first_seen);
      assert.deepEqual(value.tags, []);
      assert.equal(value.severity, fixture.feed === 'threatfox' ? 'low' : 'medium');
    }
  }
  if (fixture.mapping === 'fox-types') assert.deepEqual(writes.filter(entry => entry.feed === 'threatfox').map(entry => [entry.value.ioc_type, entry.value.value]), [
    ['ip', '192.0.2.1'], ['domain', 'c2.example.invalid'], ['url', 'http://c2.example.invalid/path'],
    ['hash', 'a'.repeat(32)], ['hash', 'b'.repeat(64)], ['email', 'malware@example.invalid'],
  ]);
} finally {
  globalThis.fetch = originalFetch;
  console.log = originalLog;
  console.error = originalError;
}

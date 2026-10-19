import assert from 'node:assert/strict';
import { join } from 'node:path';
import { lookupCveExposure, getWazuhStatus } from '../src/wazuh-client';

const [scenario, directory] = process.argv.slice(2);
for (const key of ['WAZUH_CA_FILE', 'WAZUH_INSECURE_TLS', 'NODE_TLS_REJECT_UNAUTHORIZED', 'NODE_EXTRA_CA_CERTS', 'SSL_CERT_FILE', 'SSL_CERT_DIR', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY']) {
  delete process.env[key];
}
process.env.NO_PROXY = '*';
process.env.WAZUH_DASHBOARD_USER = 'fixture-user';
process.env.WAZUH_DASHBOARD_PASSWORD = 'fixture-password';

const cert = scenario === 'hostname-mismatch' ? 'wrong-host' : 'valid';
let requests = 0;
let redirectedRequests = 0;
const handlerErrors: Error[] = [];
const redirected = Bun.serve({
  hostname: '127.0.0.1', port: 0,
  fetch() { redirectedRequests++; return Response.json({}); },
});
const server = Bun.serve({
  hostname: '127.0.0.1', port: 0,
  ...(scenario === 'http-rejected' ? {} : {
    tls: { key: Bun.file(join(directory, `${cert}.key`)), cert: Bun.file(join(directory, `${cert}.pem`)) },
  }),
  async fetch(req) {
    requests++;
    assert.equal(req.method, 'POST');
    assert.equal(req.headers.get('Authorization'), `Basic ${Buffer.from('fixture-user:fixture-password').toString('base64')}`);
    assert.equal(req.headers.get('osd-xsrf'), 'true');
    const url = new URL(req.url);
    assert.equal(url.pathname, '/wazuh/api/console/proxy');
    assert.equal(url.searchParams.get('path'), 'wazuh-states-vulnerabilities*/_search');
    assert.equal(url.searchParams.get('method'), 'POST');
    const body = await req.json() as { aggs: { hosts: { terms?: unknown; cardinality?: unknown } } };
    if (scenario.startsWith('redirect-')) return Response.redirect(`http://127.0.0.1:${redirected.port}/redirected`, 307);
    return Response.json({
      timed_out: false, _shards: { total: 1, successful: 1, failed: 0, skipped: 0 },
      hits: { total: { value: 0, relation: 'eq' }, hits: [] },
      aggregations: {
        cves: { value: 0 },
        // Lookup requests terms buckets; health requests a cardinality value.
        hosts: body.aggs.hosts.terms ? { buckets: [] } : { value: 0 },
        crit: { n: { value: 0 } },
      },
    });
  },
  error(error) {
    handlerErrors.push(error);
    return new Response('fixture handler failed', { status: 500 });
  },
});
const protocol = scenario === 'http-rejected' ? 'http' : 'https';
process.env.WAZUH_DASHBOARD_URL = `${protocol}://127.0.0.1:${server.port}/wazuh/`;
if (!['untrusted-default', 'explicit-insecure', 'unrelated-https-stays-verified', 'redirect-insecure', 'http-rejected'].includes(scenario)) {
  process.env.WAZUH_CA_FILE = join(directory, 'ca.pem');
}
if (['explicit-insecure', 'unrelated-https-stays-verified', 'redirect-insecure', 'conflicting-options'].includes(scenario)) process.env.WAZUH_INSECURE_TLS = 'true';
if (scenario === 'invalid-ca') process.env.WAZUH_CA_FILE = join(directory, 'invalid.pem');
if (scenario === 'missing-ca') process.env.WAZUH_CA_FILE = join(directory, 'missing.pem');
if (scenario === 'relative-ca') process.env.WAZUH_CA_FILE = 'ca.pem';
if (scenario === 'non-ca-certificate') process.env.WAZUH_CA_FILE = join(directory, 'valid.pem');
if (scenario === 'invalid-insecure-value') process.env.WAZUH_INSECURE_TLS = 'yes';
if (scenario === 'url-credentials') process.env.WAZUH_DASHBOARD_URL = `https://embedded:password@127.0.0.1:${server.port}/wazuh/`;
if (scenario === 'url-query') process.env.WAZUH_DASHBOARD_URL += '?unexpected=1';

const originalFetch = globalThis.fetch;
globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
  const url = new URL(input instanceof Request ? input.url : String(input));
  assert.equal(url.hostname, '127.0.0.1', 'fixture may only contact its disposable servers');
  return originalFetch(input, init);
}) as typeof fetch;

let exitCode = 0;
try {
  const success = ['private-ca', 'explicit-insecure', 'unrelated-https-stays-verified'].includes(scenario);
  const result = await lookupCveExposure('CVE-2026-1234', 3000);
  if (success) {
    assert.equal(result.error, undefined, result.error);
    assert.equal(requests, 1);
    if (scenario === 'private-ca') {
      assert.equal((await getWazuhStatus()).connected, true);
      assert.equal(requests, 2);
    }
  } else {
    assert.ok(result.error, 'unsafe or invalid transport must produce a lookup failure');
    assert.equal(requests, scenario.startsWith('redirect-') ? 1 : 0, 'reject before credentials reach a handler');
    if (scenario.includes('-ca') || scenario === 'non-ca-certificate') assert.match(result.error, /WAZUH_CA_FILE/);
  }
  if (scenario === 'unrelated-https-stays-verified') {
    await assert.rejects(originalFetch(`https://127.0.0.1:${server.port}/unrelated`), 'the Wazuh exception must not change global TLS verification');
    assert.equal(process.env.NODE_TLS_REJECT_UNAUTHORIZED, undefined);
    assert.equal(requests, 1);
  }
  assert.equal(redirectedRequests, 0, 'redirect targets must never receive a request');
  assert.deepEqual(handlerErrors, [], 'a fixture handler failure must not masquerade as transport rejection');
} catch (error) {
  console.error(error);
  exitCode = 1;
} finally {
  server.stop(true);
  redirected.stop(true);
}
process.exit(exitCode);

import assert from 'node:assert/strict';
import { mock } from 'bun:test';

const scenario = process.argv[2];
for (const key of ['HARBINGER_API_HOST', 'HARBINGER_ALLOWED_HOSTS', 'CORS_ALLOWED_ORIGIN', 'CLIENT_PORT']) {
  delete process.env[key];
}
process.env.PORT = '0';
if (scenario === 'configured-origin') {
  process.env.CLIENT_PORT = '8174';
  process.env.CORS_ALLOWED_ORIGIN = 'https://dashboard.example.test';
  process.env.HARBINGER_ALLOWED_HOSTS = 'api.example.test';
}

// The real HTTP handler is exercised, but startup and route dependencies have
// no database, feed, provider, SSH, or external-network side effects.
let effects = 0;
const effect = () => { effects++; return {}; };
mock.module('../src/db', () => ({
  initDB: () => ({}), getStats: effect, getFeeds: () => [], queryIOCs: effect,
  getIOCById: effect, getBriefs: effect, getBriefById: effect,
}));
mock.module('../src/feeds', () => ({ startFeedScheduler() {}, pollAllFeeds: effect }));
mock.module('../src/ai-client', () => ({
  sendChatMessage: effect, generateThreatBrief: effect, generateDailyThreatBrief: effect,
  generateWeeklyStrategicBrief: effect, getOllamaModels: effect, QUICK_PROMPTS: [],
}));
mock.module('../src/wazuh-client', () => ({ getWazuhStatus: effect }));
mock.module('../src/exploit-signal', () => ({ getExploitSignalStatus: effect }));

const originalFetch = globalThis.fetch;
globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
  const url = new URL(input instanceof Request ? input.url : String(input));
  assert.equal(url.hostname, '127.0.0.1', 'fixture may only contact its local HTTP server');
  return originalFetch(input, init);
}) as typeof fetch;

const { server } = await import('../src/index');
const base = `http://127.0.0.1:${server.port}`;
let exitCode = 0;
try {
  if (scenario === 'default-bind') {
    assert.equal(server.hostname, '127.0.0.1');
    const response = await fetch(`${base}/health`);
    assert.equal(response.status, 200);
  } else if (scenario === 'foreign-origin') {
    for (const site of ['cross-site', 'same-site']) {
      const get = await fetch(`${base}/settings/ollama-models`, { headers: { 'Sec-Fetch-Site': site } });
      assert.equal(get.status, 403);
      assert.equal(effects, 0);
    }
    for (const origin of [
      'https://attacker.example.test', 'null', 'http://127.0.0.1:5174.attacker.test',
      'http://127.0.0.1:5174 https://attacker.test', 'http://127.0.0.1:5174/',
    ]) {
      for (const path of ['/feeds/poll', '/chat', '/briefs/generate', '/briefs/daily', '/briefs/weekly-strategic']) {
        const before = effects;
        const response = await fetch(base + path, {
          method: 'POST',
          headers: { Origin: origin, 'Content-Type': 'text/plain', 'X-Authentik-Username': 'forged' },
          body: 'not JSON',
        });
        assert.equal(response.status, 403, `${path} must reject ${origin} before handling it`);
        assert.equal(effects, before);
        assert.equal(response.headers.has('Access-Control-Allow-Origin'), false);
      }
      const preflight = await fetch(`${base}/feeds/poll`, { method: 'OPTIONS', headers: { Origin: origin } });
      assert.equal(preflight.status, 403);
      const before = effects;
      const get = await fetch(`${base}/settings/ollama-models`, { headers: { Origin: origin } });
      assert.equal(get.status, 403);
      assert.equal(effects, before);
    }
    const allowed = await fetch(`${base}/feeds/poll`, {
      method: 'POST', headers: { Origin: 'http://127.0.0.1:5174' },
    });
    assert.equal(allowed.status, 200);
    assert.equal(allowed.headers.get('Access-Control-Allow-Origin'), 'http://127.0.0.1:5174');
    assert.equal(effects, 1);
    const cli = await fetch(`${base}/feeds/poll`, { method: 'POST' });
    assert.equal(cli.status, 200);
    assert.equal(effects, 2);
  } else if (scenario === 'foreign-host') {
    for (const host of ['attacker.example.test', 'localhost.attacker.test', 'user@localhost', 'localhost,attacker.test']) {
      const response = await fetch(`${base}/feeds/poll`, {
        method: 'POST', headers: { Host: host, 'X-Forwarded-Host': 'localhost' },
      });
      assert.equal(response.status, 403, `unrecognized Host ${host} must not reach handlers`);
      assert.equal(effects, 0);
    }
    for (const host of ['localhost', `127.0.0.1:${server.port}`, `[::1]:${server.port}`]) {
      const response = await fetch(`${base}/health`, { headers: { Host: host } });
      assert.equal(response.status, 200);
    }
  } else if (scenario === 'configured-origin') {
    const response = await fetch(`${base}/feeds/poll`, {
      method: 'POST', headers: { Host: 'api.example.test', Origin: 'https://dashboard.example.test' },
    });
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('Access-Control-Allow-Origin'), 'https://dashboard.example.test');
    assert.equal(effects, 1);
    const denied = await fetch(`${base}/feeds/poll`, {
      method: 'POST', headers: { Host: 'api.example.test', Origin: 'http://127.0.0.1:5174' },
    });
    assert.equal(denied.status, 403);
    assert.equal(effects, 1);
  } else {
    throw new Error(`Unknown fixture ${scenario}`);
  }
} catch (error) {
  console.error(error);
  exitCode = 1;
} finally {
  server.stop(true);
}
process.exit(exitCode);

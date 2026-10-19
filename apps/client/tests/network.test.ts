import { afterAll, expect, mock, test } from 'bun:test';
import { createServer } from 'vite';
import { readNetworkPolicy } from '../../server/src/network-policy';

// Explicit fixture values override a developer's shell or root .env settings.
const settings = {
  HARBINGER_API_HOST: '127.0.0.1', HARBINGER_CLIENT_HOST: '127.0.0.1',
  HARBINGER_ALLOWED_HOSTS: '', CORS_ALLOWED_ORIGIN: 'http://127.0.0.1:5174', CLIENT_PORT: '5174',
};
const saved = new Map(Object.keys(settings).map(key => [key, process.env[key]]));
Object.assign(process.env, settings);
afterAll(() => {
  for (const [key, value] of saved) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
});

test('Vite binds loopback and refuses unrecognized Host names', async () => {
  const server = await createServer({ server: { port: 0, strictPort: true }, logLevel: 'error' });
  try {
    await server.listen();
    const address = server.httpServer!.address();
    if (!address || typeof address === 'string') throw new Error('Expected a TCP listener');
    expect(address.address).toBe('127.0.0.1');
    expect(server.config.server.allowedHosts).not.toBe(true);
    const base = `http://127.0.0.1:${address.port}`;
    const denied = await fetch(base, { headers: { Host: 'attacker.example.test' } });
    expect(denied.status).toBe(403);
    const local = await fetch(base, { headers: { Host: 'localhost' } });
    expect(local.status).toBe(200);
    expect(await local.text()).toContain('<div id="app">');
    expect(server.config.server.host).toBe(readNetworkPolicy({}).hostname);
  } finally {
    await server.close();
  }
});

test('Vite routes GET and POST to the configured API port without rewriting Origin', async () => {
  let modelCalls = 0;
  mock.module('../../server/src/db', () => ({
    initDB: () => ({}), getStats: () => ({ totalIOCs: 0 }), getFeeds: () => [],
    queryIOCs: () => ({}), getIOCById: () => null, getBriefs: () => [], getBriefById: () => null,
  }));
  mock.module('../../server/src/feeds', () => ({ startFeedScheduler() {}, pollAllFeeds() {} }));
  mock.module('../../server/src/ai-client', () => ({
    sendChatMessage: () => { modelCalls++; return { success: true, content: 'fixture' }; },
    generateThreatBrief() {}, generateDailyThreatBrief() {}, generateWeeklyStrategicBrief() {},
    getOllamaModels: () => [], QUICK_PROMPTS: [],
  }));
  mock.module('../../server/src/wazuh-client', () => ({ getWazuhStatus() {} }));
  mock.module('../../server/src/exploit-signal', () => ({ getExploitSignalStatus() {} }));
  const previousPort = process.env.PORT;
  process.env.PORT = '0';
  const { server: api } = await import('../../server/src/index');
  process.env.PORT = String(api.port);
  const vite = await createServer({ server: { port: 0, strictPort: true }, logLevel: 'error' });
  try {
    await vite.listen();
    const address = vite.httpServer!.address();
    if (!address || typeof address === 'string') throw new Error('Expected a TCP listener');
    const base = `http://127.0.0.1:${address.port}/api`;
    const health = await fetch(`${base}/health`);
    expect(health.status).toBe(200);
    expect(await health.json()).toMatchObject({ status: 'ok', iocCount: 0 });
    const allowed = await fetch(`${base}/chat`, {
      method: 'POST', headers: { Origin: 'http://127.0.0.1:5174', 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: 'fixture' }),
    });
    expect(await allowed.json()).toEqual({ success: true, content: 'fixture' });
    expect(modelCalls).toBe(1);
    const denied = await fetch(`${base}/chat`, {
      method: 'POST', headers: { Origin: 'https://attacker.example.test', 'Content-Type': 'text/plain' },
      body: 'not JSON',
    });
    expect(denied.status).toBe(403);
    expect(modelCalls).toBe(1);
  } finally {
    await vite.close();
    api.stop(true);
    if (previousPort === undefined) delete process.env.PORT;
    else process.env.PORT = previousPort;
  }
});

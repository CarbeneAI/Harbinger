import assert from 'node:assert/strict';
import { getOllamaModels, sendChatMessage } from '../src/ai-client';

const providerEnvPrefixes = [
  'ANTHROPIC_', 'OPENAI_', 'OLLAMA_', 'WAZUH_', 'AZURE_OPENAI_', 'GOOGLE_', 'GEMINI_',
  'COHERE_', 'MISTRAL_', 'GROQ_', 'DEEPSEEK_', 'XAI_', 'OPENROUTER_', 'HF_',
  'HUGGINGFACE_', 'VERTEX_', 'BEDROCK_',
];
const scenario = process.argv[2];
const discovery = scenario.startsWith('discovery-');
const recovery = scenario.endsWith('-recovery');
const networkError = scenario.endsWith('-network-error');
const nonOkBody = scenario.endsWith('-non-ok-body');
const delayedSuccess = scenario.endsWith('-delayed-success');
const timeoutMs = discovery ? 30_000 : 120_000;
const acceleratedMs = scenario.endsWith('-held-body') || nonOkBody || recovery ? 80 : 1200;
const requestedTimeouts: number[] = [];
const trackedTimers = new Set<ReturnType<typeof setTimeout>>();
const handlerErrors: Error[] = [];
let clearedTimers = 0;
let timeoutFirings = 0;
let cancelledResponses = 0;
let requestCount = 0;
let server: ReturnType<typeof Bun.serve> | undefined;
let serverStopped = false;

for (const key of Object.keys(process.env)) {
  if (/^(https?|all|no)_proxy$/i.test(key)) delete process.env[key];
}
for (const key of Object.keys(process.env)) {
  if (providerEnvPrefixes.some(prefix => key.toUpperCase().startsWith(prefix))) delete process.env[key];
}
for (const key of [
  'NODE_TLS_REJECT_UNAUTHORIZED', 'NODE_EXTRA_CA_CERTS', 'SSL_CERT_FILE', 'SSL_CERT_DIR',
  'CURL_CA_BUNDLE', 'REQUESTS_CA_BUNDLE', 'AWS_CA_BUNDLE',
]) delete process.env[key];
process.env.NO_PROXY = '*';
process.env.no_proxy = '*';

for (const key of [
  'HTTPS_PROXY', 'NODE_TLS_REJECT_UNAUTHORIZED', 'NODE_EXTRA_CA_CERTS', 'SSL_CERT_FILE',
  'OLLAMA_HOST', 'ANTHROPIC_API_KEY', 'AZURE_OPENAI_API_KEY', 'GOOGLE_API_KEY',
  'COHERE_API_KEY', 'OPENROUTER_API_KEY', 'WAZUH_DASHBOARD_URL',
]) assert.equal(process.env[key], undefined, `fixture must isolate ${key}`);

const originalSetTimeout = globalThis.setTimeout;
const originalClearTimeout = globalThis.clearTimeout;
const originalFetch = globalThis.fetch;
const originalError = console.error;
const encoder = new TextEncoder();

function delayedJson(value: unknown): Response {
  return new Response(new ReadableStream<Uint8Array>({
    start(controller) {
      originalSetTimeout(() => {
        controller.enqueue(encoder.encode(JSON.stringify(value)));
        controller.close();
      }, 20);
    },
  }), { headers: { 'Content-Type': 'application/json' } });
}

function startFixture() {
  server = Bun.serve({
    hostname: '127.0.0.1',
    port: 0,
    async fetch(request) {
      requestCount++;
      const url = new URL(request.url);
      if (discovery) {
        assert.equal(url.pathname, '/api/tags');
        assert.equal(request.method, 'GET');
      } else {
        assert.equal(url.pathname, '/v1/chat/completions');
        assert.equal(request.method, 'POST');
        assert.equal(request.headers.get('Content-Type'), 'application/json');
        assert.equal((await request.json()).model, 'fixture:latest');
      }

      if ((scenario.endsWith('-success') || delayedSuccess || (recovery && requestCount > 1))) {
        const payload = discovery
          ? { models: [{ name: 'fixture:latest' }] }
          : { choices: [{ message: { content: 'Synthetic loopback response' } }] };
        return delayedSuccess || (recovery && requestCount > 1)
          ? delayedJson(payload)
          : Response.json(payload);
      }

      return new Response(new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(encoder.encode(discovery ? '{"models":' : '{"choices":'));
        },
        cancel() {
          cancelledResponses++;
        },
      }), {
        status: nonOkBody ? 503 : 200,
        headers: { 'Content-Type': 'application/json' },
      });
    },
    error(error) {
      handlerErrors.push(error);
      return new Response('Loopback fixture handler failed', { status: 500 });
    },
  });

  const origin = `http://127.0.0.1:${server.port}`;
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    assert.equal(url.origin, origin, 'fixture fetch may only contact its owned loopback server');
    return originalFetch(input, init);
  }) as typeof fetch;
  return origin;
}

function installAcceleratedTimers() {
  globalThis.setTimeout = ((handler: TimerHandler, delay?: number, ...args: unknown[]) => {
    if (typeof handler === 'function' && delay === timeoutMs) {
      requestedTimeouts.push(delay);
      const timer = originalSetTimeout(() => {
        timeoutFirings++;
        handler(...args);
      }, acceleratedMs);
      trackedTimers.add(timer);
      return timer;
    }
    return originalSetTimeout(handler, delay, ...args);
  }) as typeof setTimeout;

  globalThis.clearTimeout = ((timer?: ReturnType<typeof setTimeout>) => {
    if (timer && trackedTimers.delete(timer)) clearedTimers++;
    return originalClearTimeout(timer);
  }) as typeof clearTimeout;
}

function stopServer() {
  if (server && !serverStopped) {
    server.stop(true);
    serverStopped = true;
  }
}

function invoke(origin: string): Promise<string[] | { success: boolean; content?: string; error?: string }> {
  return discovery
    ? getOllamaModels(origin)
    : sendChatMessage('Synthetic loopback prompt', [], undefined, undefined, 'ollama', origin, 'fixture:latest');
}

async function waitFor(operation: Promise<unknown>) {
  let deadline: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      operation.then(value => ({ settled: true as const, value })),
      new Promise<{ settled: false }>(resolve => {
        deadline = setTimeout(() => resolve({ settled: false }), 600);
      }),
    ]);
  } finally {
    if (deadline) clearTimeout(deadline);
  }
}

async function waitForResponseCancellation(): Promise<boolean> {
  const deadline = Date.now() + 300;
  while (cancelledResponses === 0 && Date.now() < deadline) await Bun.sleep(10);
  return cancelledResponses > 0;
}

async function run() {
  const scenarios = [
    'discovery-held-body', 'discovery-non-ok-body', 'discovery-success', 'discovery-network-error',
    'discovery-delayed-success', 'discovery-recovery',
    'generation-held-body', 'generation-non-ok-body', 'generation-success', 'generation-network-error',
    'generation-delayed-success', 'generation-recovery',
  ];
  assert.ok(scenarios.includes(scenario), `unknown fixture scenario: ${scenario}`);
  console.error = () => {};

  const origin = startFixture();
  if (networkError) stopServer();
  installAcceleratedTimers();

  try {
    let result: unknown;
    let response = await waitFor(invoke(origin));
    if (!response.settled) {
      stopServer();
      throw new Error(`${scenario} did not complete under its accelerated request deadline`);
    }
    result = response.value;

    if (recovery) {
      if (discovery) assert.deepEqual(result, []);
      else assert.match((result as { error: string }).error, /timed out \(2 min\)/);
      assert.equal(await waitForResponseCancellation(), true, 'the first held body must be cancelled before retry');

      response = await waitFor(invoke(origin));
      assert.equal(response.settled, true, 'a later request to the same local service must succeed');
      result = response.value;
      assert.equal(requestCount, 2);
    }

    if (scenario.endsWith('-success') || delayedSuccess || recovery) {
      if (discovery) assert.deepEqual(result, ['fixture:latest']);
      else assert.deepEqual(result, { success: true, content: 'Synthetic loopback response' });
      assert.ok(requestedTimeouts.length >= 1);
      assert.ok(requestedTimeouts.every(delay => delay === timeoutMs));
      assert.equal(timeoutFirings, recovery ? 1 : 0, 'successful body must finish before its deadline');
      assert.equal(clearedTimers, requestedTimeouts.length, 'each request must clear its timer in finally');
      assert.equal(trackedTimers.size, 0);
    } else if (networkError) {
      if (discovery) assert.deepEqual(result, []);
      else assert.match((result as { error: string }).error, /Ollama connection failed/);
      assert.deepEqual(requestedTimeouts, [timeoutMs]);
      assert.equal(timeoutFirings, 0);
      assert.equal(clearedTimers, 1, 'network failure must clear its request timer');
      assert.equal(trackedTimers.size, 0);
    } else if (nonOkBody && discovery) {
      assert.deepEqual(result, []);
      assert.equal(await waitForResponseCancellation(), true, 'model discovery must cancel its unread non-OK body');
      assert.deepEqual(requestedTimeouts, [timeoutMs]);
      assert.equal(timeoutFirings, 0, 'the response body should be cancelled before the deadline');
      assert.equal(clearedTimers, 1);
      assert.equal(trackedTimers.size, 0);
    } else {
      assert.equal(await waitForResponseCancellation(), true, 'timed-out response body must be cancelled');
      assert.deepEqual(requestedTimeouts, [timeoutMs]);
      assert.equal(timeoutFirings, 1);
      assert.equal(clearedTimers, 1, 'timed-out request must clear its timer in finally');
      assert.equal(trackedTimers.size, 0);
      if (discovery) assert.deepEqual(result, []);
      else assert.match((result as { error: string }).error, /timed out \(2 min\)/);
    }

    assert.deepEqual(handlerErrors, [], 'server handler errors must not look like valid negative responses');
    console.log(JSON.stringify({ scenario, timeoutMs, acceleratedMs, timeoutFirings, cancelledResponses,
      requestCount, requestedTimeouts, clearedTimers, result }));
  } finally {
    stopServer();
    globalThis.setTimeout = originalSetTimeout;
    globalThis.clearTimeout = originalClearTimeout;
    globalThis.fetch = originalFetch;
    console.error = originalError;
    for (const timer of trackedTimers) originalClearTimeout(timer);
    trackedTimers.clear();
  }
}

await run();

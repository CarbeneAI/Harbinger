import { describe, expect, test } from 'bun:test';
import { fileURLToPath } from 'node:url';

const fixture = fileURLToPath(new URL('../test-fixtures/ollama-body-deadlines.ts', import.meta.url));
const providerEnvPrefixes = [
  'ANTHROPIC_', 'OPENAI_', 'OLLAMA_', 'WAZUH_', 'AZURE_OPENAI_', 'GOOGLE_', 'GEMINI_',
  'COHERE_', 'MISTRAL_', 'GROQ_', 'DEEPSEEK_', 'XAI_', 'OPENROUTER_', 'HF_',
  'HUGGINGFACE_', 'VERTEX_', 'BEDROCK_',
];

function fixtureEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    HTTPS_PROXY: 'http://127.0.0.1:1',
    NODE_TLS_REJECT_UNAUTHORIZED: '0',
    NODE_EXTRA_CA_CERTS: '/fixture/unused-ca.pem',
    SSL_CERT_FILE: '/fixture/unused-ca.pem',
    OLLAMA_HOST: 'http://203.0.113.1:11434',
    ANTHROPIC_API_KEY: 'fixture-only-not-a-secret',
    AZURE_OPENAI_API_KEY: 'fixture-only-not-a-secret',
    GOOGLE_API_KEY: 'fixture-only-not-a-secret',
    COHERE_API_KEY: 'fixture-only-not-a-secret',
    OPENROUTER_API_KEY: 'fixture-only-not-a-secret',
    WAZUH_DASHBOARD_URL: 'https://fixture.invalid',
  };
  for (const key of Object.keys(env)) {
    if (/^(https?|all|no)_proxy$/i.test(key)) delete env[key];
  }
  for (const key of Object.keys(env)) {
    if (providerEnvPrefixes.some(prefix => key.toUpperCase().startsWith(prefix))) delete env[key];
  }
  for (const key of [
    'NODE_TLS_REJECT_UNAUTHORIZED', 'NODE_EXTRA_CA_CERTS', 'SSL_CERT_FILE', 'SSL_CERT_DIR',
    'CURL_CA_BUNDLE', 'REQUESTS_CA_BUNDLE', 'AWS_CA_BUNDLE',
  ]) delete env[key];
  env.NO_PROXY = '*';
  env.no_proxy = '*';
  return env;
}

describe('Ollama request deadlines', () => {
  for (const scenario of [
    'discovery-held-body',
    'discovery-non-ok-body',
    'discovery-success',
    'discovery-network-error',
    'discovery-delayed-success',
    'discovery-recovery',
    'generation-held-body',
    'generation-non-ok-body',
    'generation-success',
    'generation-network-error',
    'generation-delayed-success',
    'generation-recovery',
  ]) {
    test(scenario, async () => {
      const child = Bun.spawn([process.execPath, '--no-env-file', fixture, scenario], {
        stdout: 'pipe',
        stderr: 'pipe',
        env: fixtureEnv(),
      });
      const deadline = setTimeout(() => child.kill(), 5000);
      try {
        const [stdout, stderr, exitCode] = await Promise.all([
          new Response(child.stdout).text(),
          new Response(child.stderr).text(),
          child.exited,
        ]);
        expect({ exitCode, output: exitCode === 0 ? '' : stdout + stderr }).toEqual({
          exitCode: 0,
          output: '',
        });
      } finally {
        clearTimeout(deadline);
      }
    }, 6000);
  }
});

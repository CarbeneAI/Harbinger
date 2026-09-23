/**
 * Analysis provider for Harbinger.
 *
 * Env-switchable backends, mirroring Specter's triage-provider.ts.
 *
 * ANALYSIS_PROVIDER:
 *   claude    (default) - ssh to the Mac Studio, run `claude -p` on Claude Max
 *   ollama              - local Ollama (DellAI)
 *   anthropic           - paid Anthropic Messages API (legacy tool-use path)
 *
 * Three traps inherited from Specter (already paid for — do not rediscover):
 *  1. ANTHROPIC_API_KEY must be UNSET on the remote side or the CLI silently
 *     bills the paid API instead of the subscription. That exact silent
 *     fallback drained the balance to $0 and killed Specter's briefs on
 *     2026-07-25.
 *  2. --disallowedTools is VARIADIC and eats every following non-flag argument
 *     including the prompt. Follow it with another flag; send the prompt on
 *     stdin. That bug silently broke the PAI daily brief for three days in
 *     July 2026.
 *  3. Bun's fetch caps at 300s and IGNORES AbortSignal. Long Ollama calls need
 *     `timeout: false` or they die at exactly 300.0s.
 *
 * Tooling note: the CLI session runs with every tool disallowed. Harbinger
 * gathers IOC context and enrichment itself (see prefetch.ts) and injects the
 * results into the prompt. Specter tried granting a scoped Bash tool on
 * 2026-09-22 and reverted it — --allowedTools is variadic in the same way, so
 * the scope silently did not apply and a denial test had the model run
 * `whoami && ls ~/.ssh` on the Studio. IOC text is attacker-influenced
 * (hostnames, URLs, command lines lifted from live malware feeds), so a shell
 * on Clint's daily driver is not an acceptable default.
 */

import type { PAIChatMessage, PAIChatResponse } from './types';

export type AnalysisProvider = 'claude' | 'ollama' | 'anthropic';

/** Client-facing toggle (Cloud / Local). */
export type ClientAIProvider = 'anthropic' | 'ollama' | 'claude';

const DEFAULT_OLLAMA_URL = 'http://localhost:11434';
const DEFAULT_OLLAMA_MODEL = 'gemma4:31b';

/** Read ANALYSIS_PROVIDER from the environment. Default: claude. */
export function getAnalysisProvider(): AnalysisProvider {
  const raw = (process.env.ANALYSIS_PROVIDER || 'claude').toLowerCase().trim();
  if (raw === 'claude' || raw === 'ollama' || raw === 'anthropic') return raw;
  console.warn(
    `[analysis-provider] unknown ANALYSIS_PROVIDER="${process.env.ANALYSIS_PROVIDER}", using claude`,
  );
  return 'claude';
}

/**
 * Resolve which backend serves a request.
 * The client's Local toggle always wins; otherwise the server env decides.
 */
export function resolveAnalysisProvider(
  clientProvider?: ClientAIProvider,
): AnalysisProvider {
  if (clientProvider === 'ollama') return 'ollama';
  if (clientProvider === 'claude') return 'claude';
  return getAnalysisProvider();
}

// ---------------------------------------------------------------------------
// Claude CLI over ssh
// ---------------------------------------------------------------------------

/**
 * Run a prompt through the Claude CLI on the Studio, over ssh.
 *
 * Why ssh rather than running it locally: the CLI is authenticated on the
 * Studio via OAuth (Claude Max). Installing it on the app host would require a
 * fresh interactive /login and would not share the subscription session.
 */
export async function sendClaudeCliMessage(
  userMessage: string,
  chatHistory: PAIChatMessage[],
  systemPrompt: string,
): Promise<PAIChatResponse> {
  // No default. This repo is public, so the ssh target must never be baked in
  // (same rule as Specter, from the 2026-05-05 hardcoded-password leak).
  const host = process.env.CLAUDE_CLI_SSH_HOST;
  if (!host) {
    return {
      success: false,
      error:
        'CLAUDE_CLI_SSH_HOST is not set. Set it to user@host for the machine ' +
        'holding the Claude CLI session, or set ANALYSIS_PROVIDER=ollama.',
    };
  }

  const model = process.env.CLAUDE_CLI_MODEL ?? 'claude-sonnet-5';
  const bin = process.env.CLAUDE_CLI_BIN ?? '/opt/homebrew/bin/claude';
  const timeoutMs = Number(process.env.CLAUDE_CLI_TIMEOUT_MS ?? 900_000);

  const history = chatHistory
    .map((m) => `${m.role === 'user' ? 'User' : 'Assistant'}: ${m.content}`)
    .join('\n\n');
  const fullPrompt = [systemPrompt, history, userMessage]
    .filter(Boolean)
    .join('\n\n---\n\n');

  // Trap 1: unset the API key vars so the CLI uses the subscription session.
  // Trap 2: --disallowedTools is variadic, so --output-format MUST follow it.
  const remote = [
    'export PATH=$HOME/.bun/bin:/opt/homebrew/bin:$PATH;',
    'unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN;',
    bin,
    '-p',
    '--model', model,
    '--disallowedTools Bash Edit Write Read WebSearch WebFetch',
    '--output-format text',
    '--no-session-persistence',
  ].join(' ');

  let proc: ReturnType<typeof Bun.spawn> | undefined;
  try {
    proc = Bun.spawn(
      ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', host, remote],
      { stdin: 'pipe', stdout: 'pipe', stderr: 'pipe' },
    );

    const stdin = proc.stdin as unknown as { write(d: string): void; end(): void };
    stdin.write(fullPrompt);
    stdin.end();

    const killer = setTimeout(() => {
      try { proc?.kill(); } catch { /* already gone */ }
    }, timeoutMs);

    const [out, err, code] = await Promise.all([
      new Response(proc.stdout as ReadableStream).text(),
      new Response(proc.stderr as ReadableStream).text(),
      proc.exited,
    ]);
    clearTimeout(killer);

    if (code !== 0) {
      console.error('[analysis-provider] claude-cli exit', code, err.slice(0, 400));
      return {
        success: false,
        error: `Claude CLI failed (exit ${code}): ${err.slice(0, 200)}`,
      };
    }

    const content = out.trim();
    if (!content) {
      return { success: false, error: 'Claude CLI returned empty output' };
    }

    return {
      success: true,
      content,
      usage: {
        inputTokens: 0,
        outputTokens: 0,
        costUsd: null,       // Claude Max subscription — no per-token billing
        model: `${model} (subscription)`,
      },
    };
  } catch (error: unknown) {
    console.error('[analysis-provider] claude-cli error:', error);
    try { proc?.kill(); } catch { /* noop */ }
    const msg = error instanceof Error ? error.message : String(error);
    return { success: false, error: `Claude CLI error: ${msg}` };
  }
}

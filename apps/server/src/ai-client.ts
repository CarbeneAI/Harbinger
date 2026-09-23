/**
 * AI Client — Harbinger Threat Intelligence
 * Sends chat messages to Anthropic or Ollama for threat intelligence analysis.
 * Includes a search_iocs tool so Claude can query the local IOC database.
 *
 * Pattern mirrors Specter's pai-client.ts.
 */

import { homedir } from 'os';
import { readdirSync, readFileSync } from 'fs';
import { join } from 'path';
import type { PAIChatMessage, PAIChatResponse, TokenUsage, IOC, SeverityLevel } from './types';
import { queryIOCs, insertBrief } from './db';
import { callCveMcpTool } from './mcp-client';

// ---------------------------------------------------------------------------
// Pricing table — USD per million tokens (update when Anthropic changes rates)
// ---------------------------------------------------------------------------

interface ModelPricing {
  input: number;
  output: number;
  cacheWrite: number;
  cacheRead: number;
}

const PRICING: Record<string, ModelPricing> = {
  'claude-sonnet-4-6': { input: 3,  output: 15, cacheWrite: 3.75,  cacheRead: 0.30 },
  'claude-sonnet-4-5': { input: 3,  output: 15, cacheWrite: 3.75,  cacheRead: 0.30 },
  'claude-opus-4-7':   { input: 15, output: 75, cacheWrite: 18.75, cacheRead: 1.50 },
  'claude-haiku-4-5':  { input: 1,  output: 5,  cacheWrite: 1.25,  cacheRead: 0.10 },
};

function computeCost(
  model: string,
  inputTokens: number,
  outputTokens: number,
  cacheCreation: number,
  cacheRead: number,
): number | null {
  const p = PRICING[model];
  if (!p) return null;
  return (
    (inputTokens    / 1_000_000) * p.input +
    (outputTokens   / 1_000_000) * p.output +
    (cacheCreation  / 1_000_000) * p.cacheWrite +
    (cacheRead      / 1_000_000) * p.cacheRead
  );
}

/**
 * Defang URLs, hostnames, and IPv4 addresses in threat-intel output so that
 * Microsoft Teams / email clients / Slack do not block the message as
 * containing malicious links. Standard IOC-sharing convention:
 *   http://  -> hxxp://
 *   https:// -> hxxps://
 *   evil.com -> evil[.]com  (only the dots inside URL hostnames)
 *   1.2.3.4  -> 1[.]2[.]3[.]4
 * Idempotent: pre-defanged input ([.]) is not double-defanged.
 */
function defangText(text: string): string {
  if (!text) return text;

  // Protect fenced code blocks so live IOCs in hunt queries stay copy-paste
  // runnable. Replace each fenced block with a placeholder, defang the prose,
  // then swap the original blocks back in.
  const blocks: string[] = [];
  const placeholderText = text.replace(/```[\s\S]*?```/g, (match) => {
    blocks.push(match);
    return `__HARBINGER_CODEBLOCK_${blocks.length - 1}__`;
  });

  let result = placeholderText
    .replace(/\bhttps:\/\//gi, 'hxxps://')
    .replace(/\bhttp:\/\//gi, 'hxxp://')
    .replace(/\bftps:\/\//gi, 'fxps://')
    .replace(/\bftp:\/\//gi, 'fxp://');

  // Hostname inside any scheme://host[/path] — defang dots, not path dots.
  // Negative lookahead `(?!\])` keeps existing [.] from being double-defanged.
  result = result.replace(
    /([a-z]+:\/\/)([^\s\/?#]+)/gi,
    (_match, scheme: string, host: string) => `${scheme}${host.replace(/\.(?!\])/g, '[.]')}`,
  );

  // Bare IPv4 addresses (won't match already-defanged 1[.]2[.]3[.]4).
  result = result.replace(
    /\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
    '$1[.]$2[.]$3[.]$4',
  );

  // Restore preserved code blocks.
  result = result.replace(
    /__HARBINGER_CODEBLOCK_(\d+)__/g,
    (_match, idx: string) => blocks[Number(idx)] ?? '',
  );

  return result;
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type AIProvider = 'anthropic' | 'ollama' | 'claude';

// ---------------------------------------------------------------------------
// Tool definition for Anthropic API
// ---------------------------------------------------------------------------

const SEARCH_TOOL = {
  name: 'search_iocs',
  description:
    'Search the threat intelligence database for indicators of compromise (IOCs). ' +
    'Use this to find related IPs, domains, URLs, hashes, CVEs, or emails — ' +
    'and to understand the broader context of a threat, campaign, or actor.',
  input_schema: {
    type: 'object' as const,
    properties: {
      query: {
        type: 'string',
        description: 'Free-text search across IOC values, titles, and descriptions',
      },
      ioc_type: {
        type: 'string',
        description: 'Filter by type: ip | url | domain | hash | cve | email',
      },
      severity: {
        type: 'string',
        description: 'Filter by severity: critical | high | medium | low',
      },
      feed: {
        type: 'string',
        description: 'Filter by feed: cisa_kev | urlhaus | threatfox',
      },
      limit: {
        type: 'number',
        description: 'Maximum number of results to return (default 20, max 100)',
      },
    },
  },
};

// ---------------------------------------------------------------------------
// cve-mcp enrichment tools
//
// Backed by the audited cve-mcp Python server (pinned SHA a78d720).
// Tools selected to match Harbinger's IOC types: cve / ip / domain / url / hash.
// Implementation: see mcp-client.ts.
// ---------------------------------------------------------------------------

const CVE_MCP_TOOLS = [
  {
    name: 'lookup_cve',
    description: 'Fetch full NVD details for a CVE: CVSS score, severity, description, affected products, and references.',
    input_schema: {
      type: 'object' as const,
      properties: {
        cve_id: { type: 'string', description: 'CVE identifier (e.g. CVE-2021-44228)' },
      },
      required: ['cve_id'],
    },
  },
  {
    name: 'get_epss_score',
    description: 'Get FIRST.org EPSS exploit-probability score for a CVE (0.0–1.0). Higher means more likely to be exploited in the next 30 days.',
    input_schema: {
      type: 'object' as const,
      properties: {
        cve_ids: { type: 'string', description: 'CVE identifier (or comma-separated list, e.g. "CVE-2021-44228,CVE-2024-1234")' },
      },
      required: ['cve_ids'],
    },
  },
  {
    name: 'check_kev',
    description: 'Check if a CVE is in the CISA Known Exploited Vulnerabilities catalog. Direct CISA lookup (independent of Harbinger\'s local KEV mirror).',
    input_schema: {
      type: 'object' as const,
      properties: {
        cve_id: { type: 'string', description: 'CVE identifier' },
      },
      required: ['cve_id'],
    },
  },
  {
    name: 'get_attack_mapping',
    description: 'Map a CVE to MITRE ATT&CK techniques and tactics for context on how the vulnerability is typically exploited.',
    input_schema: {
      type: 'object' as const,
      properties: {
        cve_id: { type: 'string', description: 'CVE identifier' },
      },
      required: ['cve_id'],
    },
  },
  {
    name: 'check_ip_reputation',
    description: 'Check IP reputation across AbuseIPDB and GreyNoise. Returns abuse confidence, recent reports, scanner/benign classification, and tags.',
    input_schema: {
      type: 'object' as const,
      properties: {
        ip: { type: 'string', description: 'IPv4 or IPv6 address' },
      },
      required: ['ip'],
    },
  },
  {
    name: 'shodan_host_lookup',
    description: 'Get Shodan host intelligence: open ports, running services, banners, OS, and known vulnerabilities seen on the host.',
    input_schema: {
      type: 'object' as const,
      properties: {
        ip: { type: 'string', description: 'IPv4 address' },
      },
      required: ['ip'],
    },
  },
  {
    name: 'get_domain_intel',
    description: 'Get domain intelligence: SSL certificates from crt.sh transparency logs and discovered subdomains.',
    input_schema: {
      type: 'object' as const,
      properties: {
        domain: { type: 'string', description: 'Domain name (e.g. example.com)' },
      },
      required: ['domain'],
    },
  },
  {
    name: 'check_url_safety',
    description: 'Check URL safety via URLScan.io. Returns scan results and threat verdict.',
    input_schema: {
      type: 'object' as const,
      properties: {
        url_or_domain: { type: 'string', description: 'Full URL or domain to check (e.g. https://example.com/path or example.com)' },
      },
      required: ['url_or_domain'],
    },
  },
  {
    name: 'lookup_file_hash',
    description: 'Look up a file hash on VirusTotal. Returns detection ratio across antivirus engines, malware family attribution, and first/last seen dates.',
    input_schema: {
      type: 'object' as const,
      properties: {
        hash_str: { type: 'string', description: 'MD5, SHA-1, or SHA-256 hash' },
      },
      required: ['hash_str'],
    },
  },
];

const CVE_MCP_TOOL_NAMES = new Set(CVE_MCP_TOOLS.map((t) => t.name));

const MAX_TOOL_CALLS = 5;

// ---------------------------------------------------------------------------
// IOC context formatting
// ---------------------------------------------------------------------------

function formatIOCContext(iocs: IOC[]): string {
  if (!iocs || iocs.length === 0) return '';

  const lines = ['\n## Selected IOCs for Analysis\n'];

  for (const ioc of iocs) {
    lines.push(`### ${ioc.ioc_type.toUpperCase()}: ${ioc.value}`);
    lines.push(`- **Type**: ${ioc.ioc_type}`);
    lines.push(`- **Severity**: ${ioc.severity}`);
    if (ioc.title) lines.push(`- **Title**: ${ioc.title}`);
    if (ioc.description) lines.push(`- **Description**: ${ioc.description}`);
    if (ioc.feed_name) lines.push(`- **Source Feed**: ${ioc.feed_name}`);
    if (ioc.source_ref) lines.push(`- **Reference**: ${ioc.source_ref}`);
    if (ioc.tags && ioc.tags.length > 0) lines.push(`- **Tags**: ${ioc.tags.join(', ')}`);
    if (ioc.first_seen) lines.push(`- **First Seen**: ${new Date(ioc.first_seen).toISOString()}`);
    if (ioc.last_seen) lines.push(`- **Last Seen**: ${new Date(ioc.last_seen).toISOString()}`);
    lines.push('');
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// System prompt
// ---------------------------------------------------------------------------

function buildSystemPrompt(iocContext?: IOC[]): string {
  return `You are a senior threat intelligence analyst helping security teams understand and act on threat data.

Your expertise:
- Threat actor tracking and attribution
- MITRE ATT&CK framework mapping
- Indicator of compromise (IOC) analysis
- Vulnerability assessment and prioritization
- Hunt query generation (Sigma, KQL, SPL)

## How to Respond

1. **What is this?** — Explain the IOC or threat in plain language
2. **Why does it matter?** — Assess risk, urgency, and relevance to the organization
3. **How do I know?** — Show your reasoning from the data
4. **What do I do next?** — Specific hunt queries, blocks, or detection rules
5. **What should I watch for?** — Related IOCs, escalation indicators

Use markdown formatting. Be direct and actionable.

${iocContext ? formatIOCContext(iocContext) : ''}`;
}

// ---------------------------------------------------------------------------
// Quick prompts
// ---------------------------------------------------------------------------

export const QUICK_PROMPTS = {
  analyze:
    'Analyze this IOC. Search the threat intelligence database for related indicators — same IP ranges, domains, or threat actors. Explain what this IOC is, how serious it is, and whether it is part of a larger campaign.',
  brief:
    'Produce a threat brief in TWO parts. Both parts are REQUIRED — do not skip Part 2.\n\n' +
    '## PART 1 — Executive Summary\n' +
    'Summarize the most critical and recent threats in the intelligence database. Focus on active campaigns, newly exploited CVEs, and high-confidence IOCs. Organize by severity.\n\n' +
    'Defang every URL, hostname, and IP in PART 1 using the standard sharing convention: `http://` → `hxxp://`, `https://` → `hxxps://`, and replace dots in hostnames and IPv4 addresses with `[.]` (e.g. `evil[.]com`, `1[.]2[.]3[.]4`). Leave URL paths and CVE IDs unchanged. This makes Part 1 safe to paste into Teams, Slack, and email.\n\n' +
    '## PART 2 — Hunt Queries (REQUIRED — do not omit)\n' +
    'For the top 3-5 Critical/High IOCs you covered in Part 1, write paired hunt queries the analyst can run today. Use a top-level `## Hunt Queries` markdown header to start this section. For each IOC, write the IOC value as a heading, then provide BOTH of the following inside fenced code blocks:\n\n' +
    '1. A **Wazuh** OpenSearch / indexer DSL query against `wazuh-alerts-*`. Open the fence with ```` ```wazuh ````. Use real Wazuh field names: `data.srcip`, `data.dstip`, `data.url`, `data.dns.question`, `data.win.eventdata.image`, `data.win.eventdata.commandLine`, `syscheck.path`, `rule.id`. Examples: `data.srcip:"1.2.3.4"`, `data.url:*evilpath*`, `rule.id:5710 AND data.dstip:"1.2.3.4"`.\n' +
    '2. A **Google SecOps (Chronicle) UDM** search query. Open the fence with ```` ```chronicle ````. Use real UDM fields: `target.ip`, `principal.ip`, `network.http.user_agent`, `network.dns.questions.name`, `principal.process.command_line`, `target.file.sha256`, `principal.process.file.full_path`. Examples: `target.ip = "1.2.3.4"`, `network.dns.questions.name = "evil.com"`, `principal.process.command_line = /powershell.*-enc/ nocase`.\n\n' +
    'IOC values inside the fenced code blocks must stay LIVE (NOT defanged) so the queries are copy-paste runnable. The defang rule from Part 1 does NOT apply inside fenced code blocks in Part 2.\n\n' +
    'Both parts must appear in the output. If you have fewer than 3 Critical/High IOCs to query, write queries for whatever Critical/High IOCs you have and label the section accordingly — but still include Part 2.',
  hunt:
    'Generate threat hunting queries for this IOC across the tools the team actually runs. Provide queries in this order:\n\n' +
    '1. **Wazuh** — OpenSearch / Wazuh indexer DSL query against `wazuh-alerts-*`. Use real Wazuh fields: `data.srcip`, `data.dstip`, `data.url`, `data.dns.question`, `data.win.eventdata.*`, `syscheck.path`, `rule.id`. Show both an exact-match query and a behavioral pattern query.\n' +
    '2. **Google SecOps (Chronicle) UDM search** — UDM search syntax (e.g. `target.ip = "1.2.3.4"`, `principal.process.file.full_path = /evil\\.exe/`). Use real UDM fields: `target.ip`, `principal.ip`, `network.http.user_agent`, `network.dns.questions.name`, `principal.process.command_line`, `target.file.sha256`.\n' +
    '3. **Sigma** — universal Sigma rule YAML, so the team can port it to any other SIEM if needed.\n\n' +
    'For each platform, include detection logic for both the specific IOC AND a behavioral pattern associated with it. Wrap every query in a fenced code block with the right language tag.',
  mitre:
    'Map this IOC to the MITRE ATT&CK framework. Identify tactics, techniques, and sub-techniques. Then provide MITRE D3FEND countermeasures (Detect, Isolate, Deceive, Evict) and detection opportunities with data sources and pseudo-detection rules.',
};

// ---------------------------------------------------------------------------
// API key loading
// ---------------------------------------------------------------------------

async function getApiKey(): Promise<string> {
  if (process.env.ANTHROPIC_API_KEY) {
    return process.env.ANTHROPIC_API_KEY;
  }

  const envPath = `${homedir()}/.claude/.env`;
  try {
    const envFile = await Bun.file(envPath).text();
    const match = envFile.match(/ANTHROPIC_API_KEY=(.+)/);
    if (match) {
      return match[1].trim();
    }
  } catch (err) {
    console.error('[ai-client] Failed to read API key from .env:', err);
  }

  throw new Error(
    'No Anthropic API key found — set ANTHROPIC_API_KEY or add it to ~/.claude/.env',
  );
}

// ---------------------------------------------------------------------------
// IOC search — called when Claude uses the search_iocs tool
// ---------------------------------------------------------------------------

function executeSearchIocs(params: {
  query?: string;
  ioc_type?: string;
  severity?: string;
  feed?: string;
  limit?: number;
}): string {
  try {
    const limit = Math.min(params.limit ?? 20, 100);
    const { iocs } = queryIOCs({
      search: params.query,
      type: params.ioc_type as any,
      severity: params.severity as SeverityLevel | undefined,
      feed: params.feed as any,
      limit,
    });

    if (iocs.length === 0) {
      return 'No IOCs found matching the search criteria.';
    }

    const lines = [`Found ${iocs.length} IOC(s):\n`];
    for (const ioc of iocs) {
      lines.push(`- [${ioc.severity.toUpperCase()}] ${ioc.ioc_type.toUpperCase()}: ${ioc.value}`);
      if (ioc.title) lines.push(`  Title: ${ioc.title}`);
      if (ioc.description)
        lines.push(`  Description: ${ioc.description.slice(0, 200)}`);
      if (ioc.tags && ioc.tags.length > 0) lines.push(`  Tags: ${ioc.tags.join(', ')}`);
      if (ioc.source_ref) lines.push(`  Reference: ${ioc.source_ref}`);
      lines.push(
        `  Feed: ${ioc.feed_name ?? 'unknown'} | Last seen: ${new Date(ioc.last_seen).toISOString()}`,
      );
      lines.push('');
    }

    return lines.join('\n');
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error('[ai-client] search_iocs error:', err);
    return `Search error: ${msg}`;
  }
}

// ---------------------------------------------------------------------------
// Ollama
// ---------------------------------------------------------------------------

export async function getOllamaModels(ollamaUrl: string): Promise<string[]> {
  try {
    const response = await fetch(`${ollamaUrl}/api/tags`);
    if (!response.ok) return [];
    const data = (await response.json()) as any;
    return (data.models ?? []).map((m: any) => m.name as string);
  } catch {
    return [];
  }
}

async function sendOllamaMessage(
  userMessage: string,
  chatHistory: PAIChatMessage[],
  ollamaUrl: string,
  ollamaModel: string,
  iocContext?: IOC[],
): Promise<PAIChatResponse> {
  try {
    const systemPrompt = buildSystemPrompt(iocContext);

    const messages = [
      { role: 'system', content: systemPrompt },
      ...chatHistory.map((m) => ({ role: m.role, content: m.content })),
      { role: 'user', content: userMessage },
    ];

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 1_800_000); // 30-minute timeout (local model, ~8k-token brief)

    const response = await fetch(`${ollamaUrl}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: ollamaModel,
        messages,
        stream: false,
        options: {
          num_ctx: 32768,
          num_predict: 8192,
        },
      }),
      signal: controller.signal,
      // Bun caps fetch at 300s and ignores AbortSignal for that ceiling.
      // A local 31B brief generation runs ~9 min, so the cap must be lifted.
      timeout: false,
    } as any);

    clearTimeout(timeout);

    if (!response.ok) {
      const errorText = await response.text();
      console.error('[ai-client] Ollama error:', response.status, errorText);
      return {
        success: false,
        error: `Ollama error: ${response.status} — is Ollama running at ${ollamaUrl}?`,
      };
    }

    const data = (await response.json()) as any;
    // Ollama silently drops the OLDEST tokens when the prompt exceeds num_ctx,
    // which would produce a confident brief built on half the data. Make it loud.
    const NUM_CTX = 32768;
    const promptTokens: number = data.prompt_eval_count ?? 0;
    if (promptTokens >= NUM_CTX * 0.9) {
      console.error(
        `[ai-client] WARNING: prompt ${promptTokens} tokens vs num_ctx ${NUM_CTX} — ` +
          'input was likely truncated. Brief may be built on partial data.',
      );
    }
    const content: string = data.message?.content ?? '';
    return { success: true, content: defangText(content), modelUsed: ollamaModel };
  } catch (error: any) {
    console.error('[ai-client] Ollama error:', error);
    if (error?.name === 'AbortError') {
      return {
        success: false,
        error: 'Ollama request timed out (2 min). Try a smaller model for faster responses.',
      };
    }
    const msg = error instanceof Error ? error.message : 'Unknown error';
    return { success: false, error: `Ollama connection failed: ${msg}. Is Ollama running?` };
  }
}

// ---------------------------------------------------------------------------
// sendChatMessage — routes to Ollama or Anthropic
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Claude Code CLI provider (subscription auth, no API credits)
//
// Runs `claude -p` on the Mac Studio over ssh. Clint pays for Claude Code Max
// already, so this costs nothing extra and restores the depth the paid-API
// briefs had (local Ollama briefs run about a third the length).
//
// Why ssh instead of running it here: the CLI is authenticated on the Studio
// via OAuth. Installing it on DellAI would need a fresh interactive /login.
//
// Two load-bearing details:
//  1. ANTHROPIC_API_KEY is unset on the remote side. If it is present, the CLI
//     silently bills the paid API instead of the subscription. That exact
//     silent fallback drained the balance to $0 and killed the briefs on
//     2026-07-25. Unsetting it forces subscription auth and makes failure loud.
//  2. --disallowedTools is VARIADIC and greedily eats every following non-flag
//     argument. It MUST be followed by another flag, never by the prompt. That
//     bug silently broke the PAI daily brief for three days in July 2026.
//     Here the prompt arrives on stdin, and --output-format follows the list.
// ---------------------------------------------------------------------------
async function sendClaudeCliMessage(
  userMessage: string,
  chatHistory: PAIChatMessage[],
  iocContext?: IOC[],
): Promise<PAIChatResponse> {
  const host = process.env.CLAUDE_CLI_SSH_HOST ?? 'cgarrison@192.168.2.151';
  const model = process.env.CLAUDE_CLI_MODEL ?? 'claude-sonnet-5';
  const bin = process.env.CLAUDE_CLI_BIN ?? '/opt/homebrew/bin/claude';
  const timeoutMs = Number(process.env.CLAUDE_CLI_TIMEOUT_MS ?? 900_000);

  const systemPrompt = buildSystemPrompt(iocContext);
  const history = chatHistory
    .map((m) => `${m.role === 'user' ? 'User' : 'Assistant'}: ${m.content}`)
    .join('\n\n');
  const fullPrompt = [systemPrompt, history, userMessage]
    .filter(Boolean)
    .join('\n\n---\n\n');

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

  let proc: any;
  try {
    proc = Bun.spawn(
      ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', host, remote],
      { stdin: 'pipe', stdout: 'pipe', stderr: 'pipe' },
    );

    proc.stdin.write(fullPrompt);
    proc.stdin.end();

    const killer = setTimeout(() => {
      try { proc.kill(); } catch { /* already gone */ }
    }, timeoutMs);

    const [out, err, code] = await Promise.all([
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
      proc.exited,
    ]);
    clearTimeout(killer);

    if (code !== 0) {
      console.error('[ai-client] claude-cli exit', code, err.slice(0, 400));
      return { success: false, error: `Claude CLI failed (exit ${code}): ${err.slice(0, 200)}` };
    }

    // The CLI occasionally prefaces the answer with commentary. The brief must
    // begin at its own H1, so drop anything before the first markdown heading.
    let content = out.trim();
    const h1 = content.indexOf('# ');
    if (h1 > 0) content = content.slice(h1);

    if (!content) {
      return { success: false, error: 'Claude CLI returned empty output' };
    }
    return { success: true, content: defangText(content), modelUsed: model };
  } catch (error: any) {
    console.error('[ai-client] claude-cli error:', error);
    try { proc?.kill(); } catch { /* noop */ }
    return { success: false, error: `Claude CLI error: ${error?.message ?? error}` };
  }
}

export async function sendChatMessage(
  userMessage: string,
  chatHistory: PAIChatMessage[],
  iocContext?: IOC[],
  sessionId?: string,
  provider: AIProvider = 'anthropic',
  ollamaUrl?: string,
  ollamaModel?: string,
): Promise<PAIChatResponse> {
  if (provider === 'claude') {
    const viaCli = await sendClaudeCliMessage(userMessage, chatHistory, iocContext);
    if (viaCli.success) return viaCli;
    // Studio asleep, off the LAN, or ssh refused. A degraded brief beats no
    // brief, so fall through to the local model rather than failing the run.
    console.error(
      '[ai-client] claude-cli failed, falling back to local ollama:',
      viaCli.error,
    );
    return sendOllamaMessage(
      userMessage,
      chatHistory,
      ollamaUrl ?? process.env.OLLAMA_URL ?? 'http://localhost:11434',
      ollamaModel ?? process.env.OLLAMA_MODEL ?? 'gemma4:31b',
      iocContext,
    );
  }

  if (provider === 'ollama') {
    if (!ollamaModel) {
      return {
        success: false,
        error: 'No Ollama model selected. Open settings to choose a model.',
      };
    }
    return sendOllamaMessage(
      userMessage,
      chatHistory,
      ollamaUrl ?? 'http://localhost:11434',
      ollamaModel,
      iocContext,
    );
  }

  // Anthropic path with tool-use loop
  try {
    const apiKey = await getApiKey();
    const anthropicModel = 'claude-sonnet-4-6';

    // Accumulated token usage across all rounds (tool-use may span multiple API calls)
    let totalInputTokens = 0;
    let totalOutputTokens = 0;
    let totalCacheCreationTokens = 0;
    let totalCacheReadTokens = 0;

    const systemPrompt =
      buildSystemPrompt(iocContext) +
      `\n\n## Tools Available\n\n` +
      `**search_iocs** — query the live local threat intelligence database to find related IOCs by value, type, or feed.\n\n` +
      `**cve-mcp enrichment tools** (third-party threat intel — call only when the question warrants it):\n` +
      `- CVE: \`lookup_cve\`, \`get_epss_score\`, \`check_kev\`, \`get_attack_mapping\`\n` +
      `- IP: \`check_ip_reputation\` (AbuseIPDB+GreyNoise), \`shodan_host_lookup\`\n` +
      `- Domain: \`get_domain_intel\` (crt.sh certs + subdomains)\n` +
      `- URL: \`check_url_safety\` (URLScan)\n` +
      `- Hash: \`lookup_file_hash\` (VirusTotal)\n\n` +
      `**PRIVACY** — enrichment tools forward IOC values to third-party APIs (VirusTotal, Shodan, AbuseIPDB, GreyNoise, URLScan, etc.). Do NOT enrich IOCs that look internal or private: RFC1918 IPs (10.x, 172.16–31.x, 192.168.x), loopback/link-local, internal hostnames, .corp / .local / .lan / .internal TLDs, or hashes the user describes as internally generated. For those, use \`search_iocs\` only.\n\n` +
      `**DEFANG OUTPUT** — analysts often paste your responses into Microsoft Teams, Slack, or email, where live malicious URLs get blocked. Always defang URLs, hostnames, and IPs in your output using the standard IOC convention: \`http://\` → \`hxxp://\`, \`https://\` → \`hxxps://\`, dots in hostnames and IPv4 addresses → \`[.]\` (e.g. \`evil[.]com\`, \`1[.]2[.]3[.]4\`). Leave URL paths and CVE IDs unchanged. Apply this to ALL URLs and IPs in your responses — both IOCs and reference URLs.\n\n` +
      `IMPORTANT: Use the IOC context already provided above as your primary source. Call tools only to fill specific gaps — most analyses need 0–2 tool calls total. ` +
      `Never call enrichment tools speculatively. Always end with a complete written analysis, never on a tool call.`;

    const messages: any[] = [
      ...chatHistory.map((m) => ({ role: m.role, content: m.content })),
      { role: 'user', content: userMessage },
    ];

    let toolCallCount = 0;

    while (toolCallCount <= MAX_TOOL_CALLS) {
      const response = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01',
        },
        body: JSON.stringify({
          model: anthropicModel,
          max_tokens: 8192,
          system: systemPrompt,
          tools: [SEARCH_TOOL, ...CVE_MCP_TOOLS],
          messages,
        }),
      });

      if (!response.ok) {
        const errorText = await response.text();
        console.error('[ai-client] Anthropic API error:', response.status, errorText);
        return { success: false, error: `API error: ${response.status}` };
      }

      const data = (await response.json()) as any;

      // Accumulate token usage from every round (tool-use loops generate multiple API calls)
      if (data.usage) {
        totalInputTokens         += data.usage.input_tokens         ?? 0;
        totalOutputTokens        += data.usage.output_tokens        ?? 0;
        totalCacheCreationTokens += data.usage.cache_creation_input_tokens ?? 0;
        totalCacheReadTokens     += data.usage.cache_read_input_tokens     ?? 0;
      }

      if (data.stop_reason === 'tool_use') {
        toolCallCount++;

        const toolUseBlocks = (data.content as any[]).filter(
          (block: any) => block.type === 'tool_use',
        );
        const toolResults: any[] = [];

        for (const toolUse of toolUseBlocks) {
          if (toolUse.name === 'search_iocs') {
            console.log(`[ai-client] Tool call #${toolCallCount}: search_iocs`, toolUse.input);
            const resultText = executeSearchIocs(toolUse.input);
            toolResults.push({
              type: 'tool_result',
              tool_use_id: toolUse.id,
              content: resultText,
            });
          } else if (CVE_MCP_TOOL_NAMES.has(toolUse.name)) {
            console.log(`[ai-client] Tool call #${toolCallCount}: ${toolUse.name}`, toolUse.input);
            const resultText = await callCveMcpTool(toolUse.name, toolUse.input);
            toolResults.push({
              type: 'tool_result',
              tool_use_id: toolUse.id,
              content: resultText,
            });
          } else {
            console.warn(`[ai-client] Unknown tool: ${toolUse.name}`);
            toolResults.push({
              type: 'tool_result',
              tool_use_id: toolUse.id,
              content: `Unknown tool: ${toolUse.name}`,
              is_error: true,
            });
          }
        }

        messages.push({ role: 'assistant', content: data.content });
        messages.push({ role: 'user', content: toolResults });
        continue;
      }

      // Terminal response — extract text blocks and build usage summary
      const textBlocks = (data.content as any[]).filter((block: any) => block.type === 'text');
      const content = textBlocks.map((block: any) => block.text as string).join('\n');

      const usage: TokenUsage = {
        inputTokens:              totalInputTokens,
        outputTokens:             totalOutputTokens,
        cacheCreationInputTokens: totalCacheCreationTokens || undefined,
        cacheReadInputTokens:     totalCacheReadTokens     || undefined,
        costUsd: computeCost(
          anthropicModel,
          totalInputTokens,
          totalOutputTokens,
          totalCacheCreationTokens,
          totalCacheReadTokens,
        ),
        model: anthropicModel,
      };

      console.log(`[ai-client] Usage: ${totalInputTokens} in + ${totalOutputTokens} out, cost $${usage.costUsd?.toFixed(4) ?? 'unknown'}`);

      return { success: true, content: defangText(content), usage };
    }

    // Reached max tool calls
    return {
      success: true,
      content:
        'I performed multiple searches but reached the analysis limit. Please refine your question for more targeted results.',
    };
  } catch (error) {
    console.error('[ai-client] Error calling Anthropic:', error);
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}

// ---------------------------------------------------------------------------
// generateThreatBrief
// ---------------------------------------------------------------------------

/**
 * Query the last 100 IOCs, group by severity, and ask the AI for a threat brief.
 * Persists the brief to the database and returns the AI response.
 */
export async function generateThreatBrief(
  provider: AIProvider,
  ollamaUrl?: string,
  ollamaModel?: string,
): Promise<PAIChatResponse> {
  // Fetch the 100 most recent IOCs
  const { iocs } = queryIOCs({ limit: 100, sort: 'last_seen', sortDir: 'desc' });

  if (iocs.length === 0) {
    return {
      success: false,
      error: 'No IOCs in the database yet. Wait for the first feed poll to complete.',
    };
  }

  // Group by severity for the prompt context
  const bySeverity: Record<string, IOC[]> = {
    critical: [],
    high: [],
    medium: [],
    low: [],
  };
  for (const ioc of iocs) {
    (bySeverity[ioc.severity] ?? (bySeverity[ioc.severity] = [])).push(ioc);
  }

  const lines: string[] = ['## Threat Intelligence Database Snapshot\n'];
  for (const severity of ['critical', 'high', 'medium', 'low'] as const) {
    const group = bySeverity[severity];
    if (!group || group.length === 0) continue;
    lines.push(`### ${severity.toUpperCase()} (${group.length})`);
    for (const ioc of group.slice(0, 25)) {
      lines.push(
        `- [${ioc.ioc_type}] ${ioc.value}${ioc.title ? ` — ${ioc.title}` : ''}` +
          (ioc.tags && ioc.tags.length ? ` (${ioc.tags.slice(0, 3).join(', ')})` : ''),
      );
    }
    lines.push('');
  }

  const contextMarkdown = lines.join('\n');
  const prompt = QUICK_PROMPTS.brief + '\n\n' + contextMarkdown;

  const result = await sendChatMessage(prompt, [], undefined, undefined, provider, ollamaUrl, ollamaModel);

  // Defang any live URLs/IPs the AI emitted so the brief is safe to paste
  // into Teams/Slack/email without being blocked as containing malicious links.
  if (result.success && result.content) {
    result.content = defangText(result.content);
  }

  // Persist the brief if generation succeeded
  if (result.success && result.content) {
    try {
      const model =
        result.modelUsed ??
        (provider === 'ollama'
          ? (ollamaModel ?? 'ollama')
          : provider === 'claude'
            ? (process.env.CLAUDE_CLI_MODEL ?? 'claude-sonnet-5 (cli)')
            : 'claude-sonnet-4-6');
      insertBrief(result.content, {
        iocCount:     iocs.length,
        model,
        inputTokens:  result.usage?.inputTokens,
        outputTokens: result.usage?.outputTokens,
        costUsd:      result.usage?.costUsd ?? undefined,
      });
    } catch (err) {
      console.error('[ai-client] Failed to persist threat brief:', err);
    }
  }

  return result;
}

// ---------------------------------------------------------------------------
// generateDailyThreatBrief — last 24h, hunt + detection guide format
// ---------------------------------------------------------------------------

// Reads the N most recent archived briefs and returns their campaign headings
// grouped by date. Used to inject a "recently covered" list into the prompt so
// the model demotes carryover campaigns instead of re-featuring them daily.
// Fails open: any error returns '' so the brief still ships.
function getRecentBriefHeadings(days: number): string {
  try {
    const dir = join(homedir(), '.harbinger', 'briefs');
    const files = readdirSync(dir)
      .filter((f) => /^\d{4}-\d{2}-\d{2}\.md$/.test(f))
      .sort()
      .reverse()
      .slice(0, days);
    if (files.length === 0) return '';

    const blocks: string[] = [];
    for (const file of files) {
      const date = file.replace(/\.md$/, '');
      const body = readFileSync(join(dir, file), 'utf8');
      const headings = body
        .split('\n')
        .filter((l) => l.startsWith('### '))
        .map((l) => l.replace(/^###\s+/, '').trim())
        .filter((h) => h.length > 0);
      if (headings.length === 0) continue;
      blocks.push(`${date}:\n${headings.map((h) => `  - ${h}`).join('\n')}`);
    }
    return blocks.join('\n');
  } catch {
    return '';
  }
}

const DAILY_BRIEF_PROMPT =
  'You are writing a Daily Threat Hunt Brief for the threat hunters and detection engineer. The IOC dataset below is everything seen in the last 24 hours, sorted by severity. Pick the top 5 priority IOCs and produce the brief in the EXACT format shown below.\n\n' +
  'CRITICAL OUTPUT RULES:\n' +
  '- The IOC dataset provided below is the COMPLETE context for this brief. Do NOT call the `search_iocs` tool, the MCP tools, or any external lookup. Write the brief DIRECTLY from the dataset. If something is not in the data (e.g. specific attribution, MITRE mapping), use your training knowledge or label it as unattributed/unknown — do not search.\n' +
  '- Begin your response with the H1 heading on the very first line. NO preamble, introduction, meta-commentary, or explanation of your selection logic. Do NOT say things like "I now have sufficient data" or "The five priority IOCs are selected based on...". Start directly with the heading.\n' +
  '- Use the EXACT emoji and heading hierarchy shown below. The stoplight emoji (🔴 🟠 ⚠️) and section emoji (🚨 🎯 📊 ⭐) must appear as written.\n' +
  '- Defang every IOC in PROSE: `hxxp(s)://`, replace dots in hostnames and IPv4 addresses with `[.]` (e.g. `evil[.]com`, `1[.]2[.]3[.]4`). Leave URL paths and CVE IDs intact.\n' +
  '- IOC values INSIDE fenced code blocks must stay LIVE (NOT defanged) so the queries are copy-paste runnable in Wazuh and Chronicle.\n' +
  '- Always label hunt queries with whether they are Wazuh or Google SecOps Chronicle, and use the matching language tag on the fence (` ```wazuh ` or ` ```chronicle `).\n' +
  '- **FRESHNESS RULE.** A "Recently Covered" block listing campaign headings from the past 7 briefs may be included below. Treat those campaigns as ALREADY KNOWN to the readers. Do NOT re-feature them under 🔴 Critical or 🟠 High unless the dataset shows materially new infrastructure (new C2 domains, new CVE chain, new TTP, new attribution). If a campaign has only routine continued activity, move it to the new `## 🔄 ONGOING CAMPAIGNS` section as a single one-line bullet noting what is unchanged vs new. Lead the brief with what is genuinely NEW today — net-new campaigns, fresh CVE exploitation, new actor activity — even if their raw IOC count is lower than the carryover campaigns.\n\n' +
  'FORMAT TO PRODUCE (literal):\n\n' +
  '# 🚨 DAILY THREAT HUNT BRIEF\n\n' +
  '**Date:** <today\'s date in long form, e.g. May 7, 2026> | **Classification:** TLP:WHITE | **Window:** Last 24 hours\n\n' +
  '---\n\n' +
  '## 🔴 CRITICAL SEVERITY THREATS\n\n' +
  'For EACH Critical-severity priority IOC, emit this exact per-threat block:\n\n' +
  '### <Campaign or threat name — e.g. "Active Campaign: ClearFake Social Engineering Infrastructure">\n\n' +
  '**What is this?** <Plain-language 1–3 sentence explanation.>\n\n' +
  '**Why does it matter?**\n' +
  '- <impact bullet>\n' +
  '- <impact bullet>\n' +
  '- <impact bullet>\n\n' +
  '**Key Infrastructure (defanged):**\n' +
  '- `<defanged ioc>` — <one-line context>\n' +
  '- `<defanged ioc>` — <one-line context>\n\n' +
  '**What do I do next?**\n\n' +
  '*Wazuh hunt query (against `wazuh-alerts-*`):*\n\n' +
  '```wazuh\n<live, copy-paste-runnable OpenSearch / indexer DSL using real Wazuh fields: data.srcip, data.dstip, data.url, data.dns.question, data.win.eventdata.image, data.win.eventdata.commandLine, syscheck.path, rule.id>\n```\n\n' +
  '*Google SecOps Chronicle hunt query (UDM search):*\n\n' +
  '```chronicle\n<live UDM search using real fields: target.ip, principal.ip, network.http.user_agent, network.dns.questions.name, principal.process.command_line, target.file.sha256, principal.process.file.full_path>\n```\n\n' +
  'If no Critical-severity IOCs in the 24h window, write "_No Critical-severity threats observed in the window._" and continue.\n\n' +
  '## 🟠 HIGH SEVERITY THREATS\n\n' +
  'Same per-threat block as Critical. For newly-exploited or actively-exploited CVEs, lead the threat name with the CVE ID and add a ⭐ star emoji to mark emergency-patch priorities. Example: `### CVE-2026-41940: WebPros cPanel Authentication Bypass ⭐ CRITICAL`.\n\n' +
  'If none, write "_No High-severity threats observed in the window._"\n\n' +
  '## ⚠️ MEDIUM/EMERGING TRENDS\n\n' +
  'Compact bullet list of notable Medium-severity items, fresh CVE additions, or rising patterns from the dataset. No full per-threat block here — short bullets only, with defanged IOCs.\n\n' +
  '- <bullet>\n' +
  '- <bullet>\n\n' +
  '## 🔄 ONGOING CAMPAIGNS\n\n' +
  'One-line bullets for campaigns that ALREADY appeared in the Recently Covered list and show only routine continued activity (no new TTP, no new CVE, no new attribution). Note infrastructure churn count if any. If a campaign appeared in Recently Covered but is genuinely new today (new C2 cluster, new vector, new actor link), keep it in 🔴 Critical or 🟠 High instead and mention what changed. If the Recently Covered block is empty or no campaigns roll over, write "_No carryover campaigns to report._"\n\n' +
  '- **<Campaign>:** continued activity, <N> new IOCs same pattern, no change in TTP. Hunts from <YYYY-MM-DD> brief still apply.\n' +
  '- **<Campaign>:** quiet today, no new infrastructure observed.\n\n' +
  '## 🎯 IMMEDIATE ACTION ITEMS\n\n' +
  'Numbered list of the day\'s priorities, drawn from the threats above. Mix prose and code blocks where useful (e.g. a sinkhole list, a consolidated hunt query). Defang IOCs in prose; keep them live inside fenced code blocks.\n\n' +
  '1. **<Action — e.g. "Block <Campaign> Infrastructure">** *(Priority 1)*\n' +
  '   ```\n' +
  '   <consolidated DNS sinkhole list, one per line, defanged or live as appropriate for the action>\n' +
  '   ```\n' +
  '2. **<Action — e.g. "Hunt for Cobalt Strike Activity">**\n' +
  '   ```\n' +
  '   <consolidated cross-platform hunt query>\n' +
  '   ```\n' +
  '3. **Patch <CVE-IDs>** — <brief instruction per CVE>\n' +
  '4. **Monitor for escalation:** <what to watch for>\n\n' +
  '## 📊 CAMPAIGN ATTRIBUTION\n\n' +
  '**<Campaign or actor name>:** <Plain-English attribution. State motivation, sophistication, and what the IOC pattern suggests. If unattributed, say "unattributed" — do not invent attribution.>\n\n' +
  '**<Second campaign>:** <same>\n\n' +
  'End the document after Campaign Attribution. Do not add closing remarks, sign-offs, or summary paragraphs.';

// The prompts ask the model to write "today's date", but the real date was never
// supplied, leaving the model to infer it from IOC timestamps or the Recently
// Covered list. Sonnet usually guessed right; a local model guessed the day
// after the last archived brief. Inject the real Central-time date instead.
function todayLong(): string {
  return new Date().toLocaleDateString('en-US', {
    timeZone: 'America/Chicago',
    month: 'long',
    day: 'numeric',
    year: 'numeric',
  });
}

export async function generateDailyThreatBrief(
  provider: AIProvider,
  ollamaUrl?: string,
  ollamaModel?: string,
): Promise<PAIChatResponse> {
  // Last 24h of IOCs, severity-ordered. Pull more than the 100-cap default
  // so a busy day is captured fully.
  const since = Date.now() - 24 * 60 * 60 * 1000;
  const { iocs } = queryIOCs({ limit: 300, sort: 'last_seen', sortDir: 'desc', since });

  if (iocs.length === 0) {
    return {
      success: false,
      error: 'No IOCs seen in the last 24 hours. Wait for the next feed poll.',
    };
  }

  // Group by severity for prompt context (same shape as standard brief)
  const bySeverity: Record<string, IOC[]> = {
    critical: [],
    high: [],
    medium: [],
    low: [],
  };
  for (const ioc of iocs) {
    (bySeverity[ioc.severity] ?? (bySeverity[ioc.severity] = [])).push(ioc);
  }

  const lines: string[] = [
    '## Last 24h IOC Snapshot',
    `Total IOCs in window: ${iocs.length}`,
    '',
  ];
  for (const severity of ['critical', 'high', 'medium', 'low'] as const) {
    const group = bySeverity[severity];
    if (!group || group.length === 0) continue;
    lines.push(`### ${severity.toUpperCase()} (${group.length})`);
    for (const ioc of group.slice(0, 40)) {
      lines.push(
        `- [${ioc.ioc_type}] ${ioc.value}${ioc.title ? ` — ${ioc.title}` : ''}` +
          (ioc.tags && ioc.tags.length ? ` (${ioc.tags.slice(0, 4).join(', ')})` : '') +
          (ioc.description ? ` :: ${ioc.description.slice(0, 140)}` : ''),
      );
    }
    lines.push('');
  }

  const recentHeadings = getRecentBriefHeadings(7);
  const recentBlock = recentHeadings
    ? `## Recently Covered (past 7 briefs — do not re-feature unless materially new)\n${recentHeadings}\n\n`
    : '';

  const contextMarkdown = lines.join('\n');
  const prompt =
    DAILY_BRIEF_PROMPT +
    '\n\n' +
    `**TODAY'S DATE IS ${todayLong()}.** Use exactly this date in the Date: header. Do not infer the date from IOC timestamps or from the Recently Covered list.\n\n` +
    recentBlock +
    contextMarkdown;

  const result = await sendChatMessage(prompt, [], undefined, undefined, provider, ollamaUrl, ollamaModel);

  if (result.success && result.content) {
    // defangText now skips fenced code blocks, so live IOCs in queries/rules survive.
    result.content = defangText(result.content);
  }

  if (result.success && result.content) {
    try {
      const model =
        result.modelUsed ??
        (provider === 'ollama'
          ? (ollamaModel ?? 'ollama')
          : provider === 'claude'
            ? (process.env.CLAUDE_CLI_MODEL ?? 'claude-sonnet-5 (cli)')
            : 'claude-sonnet-4-6');
      insertBrief(result.content, {
        iocCount:     iocs.length,
        model,
        inputTokens:  result.usage?.inputTokens,
        outputTokens: result.usage?.outputTokens,
        costUsd:      result.usage?.costUsd ?? undefined,
      });
    } catch (err) {
      console.error('[ai-client] Failed to persist daily brief:', err);
    }
  }

  return result;
}

// ---------------------------------------------------------------------------
// generateWeeklyStrategicBrief — 7-day rollup, leadership / CISO lens
// ---------------------------------------------------------------------------

// Reads the last N daily briefs in full so the weekly synthesis has narrative
// continuity. Returns markdown blocks separated by horizontal rules with date
// headers. Fails open: error returns ''.
function getRecentBriefsFullText(days: number): string {
  try {
    const dir = join(homedir(), '.harbinger', 'briefs');
    const files = readdirSync(dir)
      .filter((f) => /^\d{4}-\d{2}-\d{2}\.md$/.test(f))
      .sort()
      .reverse()
      .slice(0, days);
    if (files.length === 0) return '';

    const blocks: string[] = [];
    for (const file of files) {
      const date = file.replace(/\.md$/, '');
      const body = readFileSync(join(dir, file), 'utf8');
      const MAX_CHARS_PER_BRIEF = 6000;
      const trimmed = body.trim();
      const clipped =
        trimmed.length > MAX_CHARS_PER_BRIEF
          ? trimmed.slice(0, MAX_CHARS_PER_BRIEF) +
            '\n\n_[brief truncated for weekly synthesis; full text in archive]_'
          : trimmed;
      blocks.push(`### Brief: ${date}\n\n${clipped}`);
    }
    return blocks.join('\n\n---\n\n');
  } catch {
    return '';
  }
}

const WEEKLY_STRATEGIC_PROMPT =
  'You are writing the Weekly Strategic Threat Synthesis for a security leadership audience (CISO, CTO, CSIRT leads). Below you have the full text of the past 7 daily threat hunt briefs AND a 7-day IOC volume snapshot. Your job is to SYNTHESIZE — find the patterns, the momentum, what changed week-over-week, and what leadership should DO about it. This is NOT a longer daily brief. The daily briefs are tactical (hunt queries, IOC blocking). The weekly is strategic (trends, control gaps, prioritization).\n\n' +
  'CRITICAL OUTPUT RULES:\n' +
  '- Source material is ONLY the data provided below. Do NOT call `search_iocs` or any other tool. Synthesize from the briefs + IOC snapshot. Use training knowledge for attribution context only.\n' +
  '- Begin your response with the H1 heading on the very first line. NO preamble.\n' +
  '- Use the exact emoji and heading hierarchy shown below.\n' +
  '- Defang IOCs in prose (`[.]`, `hxxp(s)://`); leave IOCs inside fenced code blocks LIVE.\n' +
  '- Lead with what CHANGED this week. If a campaign has been in every daily brief for 7 days running, the leadership read is "persistent, baked into hunt rules, stop talking about it." If a NEW actor or CVE emerged mid-week, that is the lead story.\n' +
  '- Strategic Recommendations must be concrete and actionable — process changes, control gaps to close, detection coverage to add, vendor escalations to make. Not "improve security posture." Bad: "increase monitoring." Good: "add Sigma rule for Cobalt Strike watermark 987654321 to Wazuh ruleset — appeared in 6/7 briefs, hunt automation has zero blocking detections."\n\n' +
  'FORMAT TO PRODUCE (literal):\n\n' +
  '# 📅 WEEKLY STRATEGIC THREAT SYNTHESIS\n\n' +
  '**Week ending:** <today\'s date long form> | **Classification:** TLP:WHITE | **Window:** Last 7 days | **Audience:** CISO / CTO / CSIRT leads\n\n' +
  '---\n\n' +
  '## 🗓️ WEEK IN REVIEW\n\n' +
  '1-2 paragraphs. What was the dominant threat story this week? Was it CVE-driven, ransomware-driven, infostealer-driven, nation-state-driven? Was the week busy or quiet relative to a normal week? Any single event that shaped the week (zero-day disclosure, major breach, sector-targeted campaign)?\n\n' +
  '## 📈 CAMPAIGN MOMENTUM\n\n' +
  'Categorize the campaigns that appeared in the past 7 briefs into these buckets. Use one-line bullets, defanged IOCs only where they add signal.\n\n' +
  '**🔼 Trending up:** New infrastructure, new TTP, expanded targeting, new geos.\n' +
  '- <Campaign> — <what changed, what to do about it>\n\n' +
  '**🔽 Trending down / quieted:** Less activity than prior weeks, may indicate disruption or pivot.\n' +
  '- <Campaign> — <observed change, hypothesis if any>\n\n' +
  '**⏸️ Persistent baseline:** Appears every day, no meaningful change. These should be in your automated blocklist / detection ruleset, not in conversation.\n' +
  '- <Campaign> — <one line, no detail needed>\n\n' +
  '## 🆕 NEW & NOTABLE\n\n' +
  'Net-new threats that first appeared this week. New actors, new campaigns, new CVE exploitation chains, new TTPs. For each: name, what it is in 1 sentence, why it matters strategically (not tactically — leave hunt queries to the daily).\n\n' +
  '- **<Name>** — <1 sentence what + 1 sentence why it matters at leadership level>\n\n' +
  '## 📊 CVE LANDSCAPE\n\n' +
  'Which CVEs got new exploitation activity this week. Group by patch urgency. If a CVE is being actively exploited in the wild AND your org has not patched, that is the lead bullet.\n\n' +
  '- **CVE-YYYY-NNNN** — <product> — <KEV status, exploitation breadth, patch availability>\n\n' +
  '## 🎯 STRATEGIC RECOMMENDATIONS\n\n' +
  '3-5 numbered, concrete actions for leadership this week. These are NOT hunt queries. They are decisions: where to spend budget, which control gap to close, which vendor to escalate to, which Sigma rule to add to the ruleset, which threat to brief executive leadership on. Each item ≤ 3 lines.\n\n' +
  '1. **<Action>** — <why, expected impact>\n' +
  '2. **<Action>** — <why, expected impact>\n\n' +
  '## 📌 WATCHLIST — NEXT WEEK\n\n' +
  'Campaigns, CVEs, actors to actively watch for in the coming 7 days. Be specific about WHY each one is on the list and what would escalate it.\n\n' +
  '- **<Item>** — <why on watchlist, escalation trigger>\n\n' +
  'End the document after the watchlist. No closing remarks, no sign-off.';

export async function generateWeeklyStrategicBrief(
  provider: AIProvider,
  ollamaUrl?: string,
  ollamaModel?: string,
): Promise<PAIChatResponse> {
  // 7-day IOC snapshot for volume signal
  const since = Date.now() - 7 * 24 * 60 * 60 * 1000;
  const { iocs } = queryIOCs({ limit: 1000, sort: 'last_seen', sortDir: 'desc', since });

  const briefArchive = getRecentBriefsFullText(7);
  if (!briefArchive) {
    return {
      success: false,
      error: 'No archived daily briefs found in ~/.harbinger/briefs/. Weekly synthesis needs at least one daily brief to roll up.',
    };
  }

  // Severity-grouped IOC counts only (raw values are already in the briefs;
  // we just want the volume signal for the week here).
  const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const ioc of iocs) counts[ioc.severity] = (counts[ioc.severity] ?? 0) + 1;

  const iocSummary = [
    '## 7-Day IOC Volume Snapshot',
    `Total IOCs ingested in window: ${iocs.length}`,
    `By severity: 🔴 critical ${counts.critical} | 🟠 high ${counts.high} | ⚠️ medium ${counts.medium} | low ${counts.low}`,
    '',
  ].join('\n');

  const archiveBlock = `## Past 7 Daily Briefs (newest first)\n\n${briefArchive}\n`;

  const prompt =
    WEEKLY_STRATEGIC_PROMPT +
    '\n\n' +
    `**TODAY'S DATE IS ${todayLong()}.** Use exactly this date in the Date: header. Do not infer the date from IOC timestamps or from the Recently Covered list.\n\n` +
    iocSummary +
    '\n' +
    archiveBlock;

  const result = await sendChatMessage(prompt, [], undefined, undefined, provider, ollamaUrl, ollamaModel);

  if (result.success && result.content) {
    result.content = defangText(result.content);
  }

  if (result.success && result.content) {
    try {
      const model =
        result.modelUsed ??
        (provider === 'ollama'
          ? (ollamaModel ?? 'ollama')
          : provider === 'claude'
            ? (process.env.CLAUDE_CLI_MODEL ?? 'claude-sonnet-5 (cli)')
            : 'claude-sonnet-4-6');
      insertBrief(result.content, {
        iocCount:     iocs.length,
        model,
        inputTokens:  result.usage?.inputTokens,
        outputTokens: result.usage?.outputTokens,
        costUsd:      result.usage?.costUsd ?? undefined,
      });
    } catch (err) {
      console.error('[ai-client] Failed to persist weekly brief:', err);
    }
  }

  return result;
}

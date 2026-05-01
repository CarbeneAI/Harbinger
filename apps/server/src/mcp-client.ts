/**
 * MCP client for the cve-mcp threat-intel server.
 *
 * Spawns the audited cve-mcp Python server (~/Dev/cve-mcp-server) as a
 * stdio child process and exposes a small typed interface for invoking
 * its tools from Harbinger's AI tool-use loop.
 *
 * Singleton lifecycle: lazy start on first call, restart on stdio close.
 * Process is reaped on Bun shutdown via process.on('exit').
 */

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const DEFAULT_PYTHON = `${process.env.HOME}/Dev/cve-mcp-server/.venv/bin/python`;
const DEFAULT_CWD = `${process.env.HOME}/Dev/cve-mcp-server`;

export interface CveMcpStatus {
  enabled: boolean;
  connected: boolean;
  toolCount?: number;
  lastError?: string;
}

let client: Client | null = null;
let transport: StdioClientTransport | null = null;
let connecting: Promise<Client> | null = null;
let lastError: string | undefined;

function isEnabled(): boolean {
  return (process.env.CVE_MCP_ENABLED ?? 'true').toLowerCase() !== 'false';
}

// Minimal env passed to the cve-mcp child. cve-mcp loads its own .env from
// CWD via python-dotenv, so it does NOT need our parent-process secrets
// (ANTHROPIC_API_KEY, ABUSE_CH_AUTH_KEY, etc.). Forward only system basics
// plus any CVE_MCP_* overrides the operator set.
function buildChildEnv(): Record<string, string> {
  const allowed = ['PATH', 'HOME', 'LANG', 'LC_ALL', 'TZ', 'TMPDIR', 'USER'];
  const out: Record<string, string> = {};
  for (const key of allowed) {
    const v = process.env[key];
    if (v !== undefined) out[key] = v;
  }
  for (const [k, v] of Object.entries(process.env)) {
    if (k.startsWith('CVE_MCP_') && v !== undefined) out[k] = v;
  }
  return out;
}

async function connect(): Promise<Client> {
  if (client) return client;
  if (connecting) return connecting;

  const command = process.env.CVE_MCP_PYTHON ?? DEFAULT_PYTHON;
  const cwd = process.env.CVE_MCP_CWD ?? DEFAULT_CWD;

  connecting = (async () => {
    transport = new StdioClientTransport({
      command,
      args: ['-m', 'cve_mcp.server'],
      cwd,
      env: buildChildEnv(),
    });

    const c = new Client(
      { name: 'harbinger', version: '0.1.0' },
      { capabilities: {} },
    );

    await c.connect(transport);
    client = c;
    lastError = undefined;

    // Reset state if the child process dies so the next call retries.
    transport.onclose = () => {
      client = null;
      transport = null;
      connecting = null;
    };

    return c;
  })();

  try {
    return await connecting;
  } catch (err) {
    lastError = err instanceof Error ? err.message : String(err);
    client = null;
    transport = null;
    connecting = null;
    throw err;
  }
}

export async function callCveMcpTool(
  name: string,
  args: Record<string, unknown>,
): Promise<string> {
  if (!isEnabled()) {
    return 'cve-mcp integration is disabled (set CVE_MCP_ENABLED=true to enable).';
  }

  try {
    const c = await connect();
    const result = await c.callTool({ name, arguments: args });

    const content = result.content as Array<{ type: string; text?: string }> | undefined;
    if (!content || content.length === 0) return '(no content)';

    return content
      .filter((b) => b.type === 'text' && typeof b.text === 'string')
      .map((b) => b.text!)
      .join('\n')
      .trim();
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    lastError = msg;
    console.error(`[mcp-client] cve-mcp tool '${name}' failed:`, msg);
    return `cve-mcp tool error: ${msg}`;
  }
}

export async function getCveMcpStatus(): Promise<CveMcpStatus> {
  if (!isEnabled()) return { enabled: false, connected: false };
  try {
    const c = await connect();
    const tools = await c.listTools();
    return { enabled: true, connected: true, toolCount: tools.tools.length };
  } catch (err) {
    return {
      enabled: true,
      connected: false,
      lastError: err instanceof Error ? err.message : String(err),
    };
  }
}

// Best-effort cleanup on Bun exit.
process.on('exit', () => {
  void transport?.close();
});

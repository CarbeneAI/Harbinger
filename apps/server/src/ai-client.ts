/**
 * AI Client — Harbinger Threat Intelligence
 * Sends chat messages to Anthropic or Ollama for threat intelligence analysis.
 * Includes a search_iocs tool so Claude can query the local IOC database.
 *
 * Pattern mirrors Specter's pai-client.ts.
 */

import { homedir } from 'os';
import type { PAIChatMessage, PAIChatResponse, IOC, SeverityLevel } from './types';
import { queryIOCs, insertBrief } from './db';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type AIProvider = 'anthropic' | 'ollama';

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

const MAX_TOOL_CALLS = 3;

// ---------------------------------------------------------------------------
// System prompt
// ---------------------------------------------------------------------------

function buildSystemPrompt(): string {
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

Use markdown formatting. Be direct and actionable.`;
}

// ---------------------------------------------------------------------------
// Quick prompts
// ---------------------------------------------------------------------------

export const QUICK_PROMPTS = {
  analyze:
    'Analyze this IOC. Search the threat intelligence database for related indicators — same IP ranges, domains, or threat actors. Explain what this IOC is, how serious it is, and whether it is part of a larger campaign.',
  brief:
    'Generate a threat brief summarizing the most critical and recent threats in the intelligence database. Focus on active campaigns, newly exploited CVEs, and high-confidence IOCs. Organize by severity.',
  hunt:
    'Generate threat hunting queries for this IOC. Provide queries in Sigma rule format, KQL (for Sentinel/Elastic), and SPL (for Splunk). Include detection logic for both the specific IOC and behavioral patterns associated with it.',
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
): Promise<PAIChatResponse> {
  try {
    const systemPrompt = buildSystemPrompt();

    const messages = [
      { role: 'system', content: systemPrompt },
      ...chatHistory.map((m) => ({ role: m.role, content: m.content })),
      { role: 'user', content: userMessage },
    ];

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 120_000); // 2-minute timeout

    const response = await fetch(`${ollamaUrl}/v1/chat/completions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: ollamaModel,
        messages,
        max_tokens: 2048,
        stream: false,
      }),
      signal: controller.signal,
    });

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
    const content: string = data.choices?.[0]?.message?.content ?? '';
    return { success: true, content };
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

export async function sendChatMessage(
  userMessage: string,
  chatHistory: PAIChatMessage[],
  provider: AIProvider = 'anthropic',
  ollamaUrl?: string,
  ollamaModel?: string,
): Promise<PAIChatResponse> {
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
    );
  }

  // Anthropic path with tool-use loop
  try {
    const apiKey = await getApiKey();

    const systemPrompt =
      buildSystemPrompt() +
      `\n\n## Tools Available\n\n` +
      `You have access to \`search_iocs\` to query the live threat intelligence database. ` +
      `Use it proactively to:\n` +
      `- Find related IOCs by value, type, or feed\n` +
      `- Understand campaign scope by correlating indicators\n` +
      `- Verify whether an IOC is known and its confidence level\n\n` +
      `When you search, briefly explain *why* you're searching so the analyst understands your reasoning.`;

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
          model: 'claude-sonnet-4-20250514',
          max_tokens: 2048,
          system: systemPrompt,
          tools: [SEARCH_TOOL],
          messages,
        }),
      });

      if (!response.ok) {
        const errorText = await response.text();
        console.error('[ai-client] Anthropic API error:', response.status, errorText);
        return { success: false, error: `API error: ${response.status}` };
      }

      const data = (await response.json()) as any;

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
          }
        }

        messages.push({ role: 'assistant', content: data.content });
        messages.push({ role: 'user', content: toolResults });
        continue;
      }

      // Terminal response — extract text blocks
      const textBlocks = (data.content as any[]).filter((block: any) => block.type === 'text');
      const content = textBlocks.map((block: any) => block.text as string).join('\n');
      return { success: true, content };
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

  const result = await sendChatMessage(prompt, [], provider, ollamaUrl, ollamaModel);

  // Persist the brief if generation succeeded
  if (result.success && result.content) {
    try {
      const model =
        provider === 'ollama' ? (ollamaModel ?? 'ollama') : 'claude-sonnet-4-20250514';
      insertBrief(result.content, { iocCount: iocs.length, model });
    } catch (err) {
      console.error('[ai-client] Failed to persist threat brief:', err);
    }
  }

  return result;
}

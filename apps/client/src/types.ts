export type IOCType = 'ip' | 'url' | 'domain' | 'hash' | 'cve' | 'email';
export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low';
export type FeedName = 'cisa_kev' | 'urlhaus' | 'threatfox';

export interface IOC {
  id: number;
  feed_id: number;
  feed_name?: FeedName;
  ioc_type: IOCType;
  value: string;
  severity: SeverityLevel;
  title?: string;
  description?: string;
  source_ref?: string;
  tags?: string[];
  first_seen: number;
  last_seen: number;
}

export interface Feed {
  id: number;
  name: FeedName;
  url: string;
  last_poll?: number;
  last_count: number;
  status: 'ok' | 'error' | 'pending';
  error_msg?: string;
}

export interface IOCStats {
  totalIOCs: number;
  byType: Record<IOCType, number>;
  bySeverity: Record<SeverityLevel, number>;
  byFeed: Record<FeedName, number>;
  lastUpdated?: number;
}

export interface McpStatus {
  enabled: boolean;
  connected: boolean;
  toolCount?: number;
  lastError?: string;
}

export interface ThreatBrief {
  id: number;
  created_at: number;
  content: string;
  ioc_count?: number;
  model?: string;
  input_tokens?: number;
  output_tokens?: number;
  cost_usd?: number;
}

export interface PAIChatMessage {
  role: 'user' | 'assistant';
  content: string;
}

export interface TokenUsage {
  inputTokens: number;
  outputTokens: number;
  cacheCreationInputTokens?: number;
  cacheReadInputTokens?: number;
  costUsd: number | null;
  model: string;
}

export interface PAIChatResponse {
  success: boolean;
  content?: string;
  error?: string;
  usage?: TokenUsage;
}

// Client-specific additions
export interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
  timestamp: number;
  usage?: TokenUsage;
  isBrief?: boolean;
}

export interface QuickPrompts {
  analyze: string;
  brief: string;
  hunt: string;
  mitre: string;
}

export type AIProvider = 'anthropic' | 'ollama';

export interface AIProviderConfig {
  provider: AIProvider;
  ollamaUrl: string;
  ollamaModel: string;
  availableModels: string[];
}

// Helpers
export function getSeverityColor(severity: SeverityLevel): string {
  switch (severity) {
    case 'critical': return '#f7768e';
    case 'high':     return '#e0af68';
    case 'medium':   return '#a855f7';
    case 'low':      return '#9ece6a';
  }
}

export function formatRelativeTime(unixMs: number): string {
  const now = Date.now();
  const diffMs = now - unixMs;
  const diffSec = Math.floor(diffMs / 1000);

  if (diffSec < 60) return `${diffSec}s ago`;

  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;

  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;

  const diffDay = Math.floor(diffHr / 24);
  if (diffDay < 30) return `${diffDay}d ago`;

  const diffMo = Math.floor(diffDay / 30);
  if (diffMo < 12) return `${diffMo}mo ago`;

  const diffYr = Math.floor(diffMo / 12);
  return `${diffYr}y ago`;
}

export function getSeverityFromConfidence(confidence: number): SeverityLevel {
  if (confidence >= 80) return 'critical';
  if (confidence >= 60) return 'high';
  if (confidence >= 40) return 'medium';
  return 'low';
}

export function parseTagsJson(raw: string): string[] {
  try { return JSON.parse(raw); } catch { return []; }
}

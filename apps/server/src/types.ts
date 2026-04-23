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

export interface ThreatBrief {
  id: number;
  created_at: number;
  content: string;
  ioc_count?: number;
  model?: string;
}

export interface PAIChatMessage {
  role: 'user' | 'assistant';
  content: string;
}

export interface PAIChatResponse {
  success: boolean;
  content?: string;
  error?: string;
}

// Helpers
export function getSeverityFromConfidence(confidence: number): SeverityLevel {
  if (confidence >= 80) return 'critical';
  if (confidence >= 60) return 'high';
  if (confidence >= 40) return 'medium';
  return 'low';
}

export function parseTagsJson(raw: string): string[] {
  try { return JSON.parse(raw); } catch { return []; }
}

/**
 * Harbinger Threat Intelligence Server
 * HTTP API for IOC management, feed polling, and AI-powered analysis
 */

import { initDB, getStats, getFeeds, queryIOCs, getIOCById, getBriefs, getBriefById } from './db';
import { startFeedScheduler, pollAllFeeds } from './feeds';
import { sendChatMessage, generateThreatBrief, getOllamaModels, QUICK_PROMPTS } from './ai-client';
import { getCveMcpStatus } from './mcp-client';

// Initialize database
const db = initDB();

// Start feed polling
startFeedScheduler();

// CORS headers
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  });
}

const server = Bun.serve({
  port: parseInt(process.env.PORT || '4001'),

  async fetch(req: Request) {
    const url = new URL(req.url);
    const path = url.pathname;

    // Preflight
    if (req.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    // GET /health
    if (path === '/health' && req.method === 'GET') {
      const stats = getStats();
      return json({
        status: 'ok',
        timestamp: Date.now(),
        iocCount: stats.totalIOCs,
        feedCount: getFeeds().length,
      });
    }

    // GET /stats
    if (path === '/stats' && req.method === 'GET') {
      return json(getStats());
    }

    // GET /feeds
    if (path === '/feeds' && req.method === 'GET') {
      return json(getFeeds());
    }

    // POST /feeds/poll
    if (path === '/feeds/poll' && req.method === 'POST') {
      pollAllFeeds(); // fire and forget
      return json({ triggered: true, message: 'Poll started' });
    }

    // GET /mcp/status — cve-mcp threat-intel enrichment health
    if (path === '/mcp/status' && req.method === 'GET') {
      const status = await getCveMcpStatus();
      return json(status);
    }

    // GET /iocs
    if (path === '/iocs' && req.method === 'GET') {
      const params = {
        search: url.searchParams.get('search') || undefined,
        type: (url.searchParams.get('type') || undefined) as any,
        severity: (url.searchParams.get('severity') || undefined) as any,
        feed: (url.searchParams.get('feed') || undefined) as any,
        sort: (url.searchParams.get('sort') || 'last_seen') as any,
        sortDir: (url.searchParams.get('sortDir') || 'desc') as 'asc' | 'desc',
        limit: Math.min(parseInt(url.searchParams.get('limit') || '50'), 200),
        offset: parseInt(url.searchParams.get('offset') || '0'),
      };
      const result = queryIOCs(params);
      return json({ ...result, limit: params.limit, offset: params.offset });
    }

    // GET /iocs/:id
    if (path.startsWith('/iocs/') && req.method === 'GET') {
      const id = parseInt(path.split('/')[2]);
      if (isNaN(id)) return json({ error: 'Invalid ID' }, 400);
      const ioc = getIOCById(id);
      if (!ioc) return json({ error: 'Not found' }, 404);
      return json(ioc);
    }

    // POST /iocs/search
    if (path === '/iocs/search' && req.method === 'POST') {
      try {
        const body = await req.json() as any;
        const result = queryIOCs({
          search: body.query,
          type: body.type,
          severity: body.severity,
          feed: body.feed,
          limit: Math.min(body.limit || 20, 100),
        });
        return json(result);
      } catch {
        return json({ error: 'Invalid request' }, 400);
      }
    }

    // GET /chat/prompts
    if (path === '/chat/prompts' && req.method === 'GET') {
      return json(QUICK_PROMPTS);
    }

    // POST /chat
    if (path === '/chat' && req.method === 'POST') {
      try {
        const body = await req.json() as any;
        const { message, history = [], iocContext, provider, ollamaUrl, ollamaModel, sessionId } = body;

        if (!message) {
          return json({ success: false, error: 'Message required' }, 400);
        }

        const response = await sendChatMessage(
          message, history, iocContext, sessionId,
          provider, ollamaUrl, ollamaModel
        );
        return json(response);
      } catch (error) {
        console.error('Chat error:', error);
        return json({ success: false, error: 'Internal error' }, 500);
      }
    }

    // POST /briefs/generate
    if (path === '/briefs/generate' && req.method === 'POST') {
      try {
        const body = await req.json() as any;
        const { provider, ollamaUrl, ollamaModel } = body || {};
        const response = await generateThreatBrief(provider, ollamaUrl, ollamaModel);
        return json(response);
      } catch (error) {
        console.error('Brief generation error:', error);
        return json({ success: false, error: 'Internal error' }, 500);
      }
    }

    // GET /briefs
    if (path === '/briefs' && req.method === 'GET') {
      const limit = parseInt(url.searchParams.get('limit') || '10');
      return json(getBriefs(limit));
    }

    // GET /briefs/:id
    if (path.startsWith('/briefs/') && req.method === 'GET') {
      const id = parseInt(path.split('/')[2]);
      if (isNaN(id)) return json({ error: 'Invalid ID' }, 400);
      const brief = getBriefById(id);
      if (!brief) return json({ error: 'Not found' }, 404);
      return json(brief);
    }

    // GET /settings/ollama-models
    if (path === '/settings/ollama-models' && req.method === 'GET') {
      const ollamaUrl = url.searchParams.get('ollamaUrl') || 'http://localhost:11434';
      const models = await getOllamaModels(ollamaUrl);
      return json({ models });
    }

    // Default
    return new Response('Harbinger Threat Intelligence Server', {
      headers: { ...corsHeaders, 'Content-Type': 'text/plain' },
    });
  },
});

console.log(`Harbinger Server running on http://localhost:${server.port}`);
console.log(`Health check: http://localhost:${server.port}/health`);
console.log(`Feeds: ${getFeeds().length} configured`);

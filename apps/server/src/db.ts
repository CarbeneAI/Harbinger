import { Database } from 'bun:sqlite';
import type {
  IOC,
  Feed,
  IOCStats,
  ThreatBrief,
  IOCType,
  SeverityLevel,
  FeedName,
} from './types';
import { parseTagsJson } from './types';

const DB_PATH = process.env.DB_PATH ?? './harbinger.db';

let db: Database;

export function initDB(): Database {
  db = new Database(DB_PATH, { create: true });
  db.exec('PRAGMA journal_mode = WAL;');
  db.exec('PRAGMA foreign_keys = ON;');

  // ── Feeds table ──────────────────────────────────────────────────────────
  db.exec(`
    CREATE TABLE IF NOT EXISTS feeds (
      id        INTEGER PRIMARY KEY AUTOINCREMENT,
      name      TEXT    NOT NULL UNIQUE,
      url       TEXT    NOT NULL,
      last_poll INTEGER,
      last_count INTEGER NOT NULL DEFAULT 0,
      status    TEXT    NOT NULL DEFAULT 'pending',
      error_msg TEXT
    );
  `);

  // ── IOCs table ────────────────────────────────────────────────────────────
  db.exec(`
    CREATE TABLE IF NOT EXISTS iocs (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      feed_id     INTEGER NOT NULL REFERENCES feeds(id) ON DELETE CASCADE,
      ioc_type    TEXT    NOT NULL,
      value       TEXT    NOT NULL,
      severity    TEXT    NOT NULL DEFAULT 'medium',
      title       TEXT,
      description TEXT,
      source_ref  TEXT,
      tags        TEXT    NOT NULL DEFAULT '[]',
      first_seen  INTEGER NOT NULL,
      last_seen   INTEGER NOT NULL,
      UNIQUE(value, ioc_type)
    );
  `);

  // ── Indexes ───────────────────────────────────────────────────────────────
  db.exec(`CREATE INDEX IF NOT EXISTS idx_iocs_type      ON iocs(ioc_type);`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_iocs_severity  ON iocs(severity);`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_iocs_feed_id   ON iocs(feed_id);`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_iocs_last_seen ON iocs(last_seen);`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_iocs_value     ON iocs(value);`);

  // ── FTS5 virtual table ────────────────────────────────────────────────────
  db.exec(`
    CREATE VIRTUAL TABLE IF NOT EXISTS iocs_fts
    USING fts5(value, title, description, tags, content='iocs', content_rowid='id');
  `);

  // ── Threat briefs table ───────────────────────────────────────────────────
  db.exec(`
    CREATE TABLE IF NOT EXISTS threat_briefs (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      created_at   INTEGER NOT NULL,
      content      TEXT    NOT NULL,
      ioc_count    INTEGER,
      model        TEXT,
      input_tokens INTEGER,
      output_tokens INTEGER,
      cost_usd     REAL
    );
  `);

  // Migrate existing DB: add cost columns if they don't exist yet
  const briefCols = db
    .query<{ name: string }, []>(`PRAGMA table_info(threat_briefs)`)
    .all()
    .map((r) => r.name);
  if (!briefCols.includes('input_tokens')) {
    db.exec(`ALTER TABLE threat_briefs ADD COLUMN input_tokens INTEGER;`);
  }
  if (!briefCols.includes('output_tokens')) {
    db.exec(`ALTER TABLE threat_briefs ADD COLUMN output_tokens INTEGER;`);
  }
  if (!briefCols.includes('cost_usd')) {
    db.exec(`ALTER TABLE threat_briefs ADD COLUMN cost_usd REAL;`);
  }

  return db;
}

function getDB(): Database {
  if (!db) initDB();
  return db;
}

// ── Feed operations ───────────────────────────────────────────────────────────

export function upsertFeed(
  name: FeedName,
  url: string,
): Feed {
  const d = getDB();
  d.exec(`
    INSERT INTO feeds (name, url, status)
    VALUES (?, ?, 'pending')
    ON CONFLICT(name) DO UPDATE SET url = excluded.url;
  `, [name, url]);

  return d.query<Feed, [string]>(
    'SELECT * FROM feeds WHERE name = ?'
  ).get(name)!;
}

export function updateFeedStatus(
  name: FeedName,
  status: Feed['status'],
  opts: { lastCount?: number; errorMsg?: string } = {},
): void {
  const d = getDB();
  const now = Date.now();
  d.exec(`
    UPDATE feeds
    SET status = ?, last_poll = ?, last_count = COALESCE(?, last_count), error_msg = ?
    WHERE name = ?;
  `, [status, now, opts.lastCount ?? null, opts.errorMsg ?? null, name]);
}

export function getFeeds(): Feed[] {
  return getDB().query<Feed, []>('SELECT * FROM feeds ORDER BY name').all();
}

// ── IOC operations ────────────────────────────────────────────────────────────

export function upsertIOC(
  feedId: number,
  ioc: Omit<IOC, 'id' | 'feed_id' | 'feed_name'>,
): void {
  const d = getDB();
  const tagsJson = JSON.stringify(ioc.tags ?? []);
  const now = Date.now();

  d.exec(`
    INSERT INTO iocs (feed_id, ioc_type, value, severity, title, description, source_ref, tags, first_seen, last_seen)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(value, ioc_type) DO UPDATE SET
      feed_id     = excluded.feed_id,
      severity    = excluded.severity,
      title       = excluded.title,
      description = excluded.description,
      source_ref  = excluded.source_ref,
      tags        = excluded.tags,
      last_seen   = excluded.last_seen;
  `, [
    feedId,
    ioc.ioc_type,
    ioc.value,
    ioc.severity,
    ioc.title ?? null,
    ioc.description ?? null,
    ioc.source_ref ?? null,
    tagsJson,
    ioc.first_seen ?? now,
    ioc.last_seen ?? now,
  ]);
}

export function rebuildFTS(): void {
  const d = getDB();
  d.exec(`INSERT INTO iocs_fts(iocs_fts) VALUES('rebuild');`);
}

// Raw row shape returned from DB before transformation
interface RawIOCRow {
  id: number;
  feed_id: number;
  feed_name: string | null;
  ioc_type: string;
  value: string;
  severity: string;
  title: string | null;
  description: string | null;
  source_ref: string | null;
  tags: string;
  first_seen: number;
  last_seen: number;
}

function rowToIOC(row: RawIOCRow): IOC {
  return {
    id: row.id,
    feed_id: row.feed_id,
    feed_name: (row.feed_name ?? undefined) as FeedName | undefined,
    ioc_type: row.ioc_type as IOCType,
    value: row.value,
    severity: row.severity as SeverityLevel,
    title: row.title ?? undefined,
    description: row.description ?? undefined,
    source_ref: row.source_ref ?? undefined,
    tags: parseTagsJson(row.tags),
    first_seen: row.first_seen,
    last_seen: row.last_seen,
  };
}

export interface QueryIOCsParams {
  search?: string;
  type?: IOCType;
  severity?: SeverityLevel;
  feed?: FeedName;
  sort?: 'last_seen' | 'first_seen' | 'severity' | 'value';
  sortDir?: 'asc' | 'desc';
  limit?: number;
  offset?: number;
  /** Unix-ms cutoff. When set, only return IOCs with last_seen >= since. */
  since?: number;
}

export function queryIOCs(params: QueryIOCsParams = {}): { iocs: IOC[]; total: number } {
  const d = getDB();
  const {
    search,
    type,
    severity,
    feed,
    sort = 'last_seen',
    sortDir = 'desc',
    limit = 50,
    offset = 0,
    since,
  } = params;

  // Whitelist sort columns to prevent SQL injection
  const validSorts = ['last_seen', 'first_seen', 'severity', 'value'] as const;
  const safeSort = validSorts.includes(sort as typeof validSorts[number]) ? sort : 'last_seen';
  const safeDir = sortDir === 'asc' ? 'ASC' : 'DESC';

  const conditions: string[] = [];
  const args: (string | number)[] = [];

  if (search) {
    // Join with FTS5 for full-text search
    conditions.push('i.id IN (SELECT rowid FROM iocs_fts WHERE iocs_fts MATCH ?)');
    args.push(search + '*');
  }
  if (type) {
    conditions.push('i.ioc_type = ?');
    args.push(type);
  }
  if (severity) {
    conditions.push('i.severity = ?');
    args.push(severity);
  }
  if (feed) {
    conditions.push('f.name = ?');
    args.push(feed);
  }
  if (typeof since === 'number') {
    conditions.push('i.last_seen >= ?');
    args.push(since);
  }

  const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

  const baseQuery = `
    FROM iocs i
    LEFT JOIN feeds f ON f.id = i.feed_id
    ${where}
  `;

  // Count query
  const countRow = d.query<{ total: number }, typeof args>(
    `SELECT COUNT(*) as total ${baseQuery}`
  ).get(...args as []);
  const total = countRow?.total ?? 0;

  // Data query
  const rows = d.query<RawIOCRow, typeof args>(`
    SELECT
      i.id,
      i.feed_id,
      f.name AS feed_name,
      i.ioc_type,
      i.value,
      i.severity,
      i.title,
      i.description,
      i.source_ref,
      i.tags,
      i.first_seen,
      i.last_seen
    ${baseQuery}
    ORDER BY i.${safeSort} ${safeDir}
    LIMIT ? OFFSET ?
  `).all(...args as [], limit, offset);

  return { iocs: rows.map(rowToIOC), total };
}

export function getIOCById(id: number): IOC | null {
  const d = getDB();
  const row = d.query<RawIOCRow, [number]>(`
    SELECT
      i.id,
      i.feed_id,
      f.name AS feed_name,
      i.ioc_type,
      i.value,
      i.severity,
      i.title,
      i.description,
      i.source_ref,
      i.tags,
      i.first_seen,
      i.last_seen
    FROM iocs i
    LEFT JOIN feeds f ON f.id = i.feed_id
    WHERE i.id = ?
  `).get(id);
  return row ? rowToIOC(row) : null;
}

// ── Stats ─────────────────────────────────────────────────────────────────────

export function getStats(): IOCStats {
  const d = getDB();

  const total = d.query<{ cnt: number }, []>(
    'SELECT COUNT(*) as cnt FROM iocs'
  ).get()?.cnt ?? 0;

  // by type
  const typeRows = d.query<{ ioc_type: string; cnt: number }, []>(
    'SELECT ioc_type, COUNT(*) as cnt FROM iocs GROUP BY ioc_type'
  ).all();

  // by severity
  const sevRows = d.query<{ severity: string; cnt: number }, []>(
    'SELECT severity, COUNT(*) as cnt FROM iocs GROUP BY severity'
  ).all();

  // by feed
  const feedRows = d.query<{ name: string; cnt: number }, []>(`
    SELECT f.name, COUNT(i.id) as cnt
    FROM feeds f
    LEFT JOIN iocs i ON i.feed_id = f.id
    GROUP BY f.name
  `).all();

  // last updated
  const lastRow = d.query<{ last_seen: number | null }, []>(
    'SELECT MAX(last_seen) as last_seen FROM iocs'
  ).get();

  const byType = {} as Record<IOCType, number>;
  for (const r of typeRows) byType[r.ioc_type as IOCType] = r.cnt;

  const bySeverity = {} as Record<SeverityLevel, number>;
  for (const r of sevRows) bySeverity[r.severity as SeverityLevel] = r.cnt;

  const byFeed = {} as Record<FeedName, number>;
  for (const r of feedRows) byFeed[r.name as FeedName] = r.cnt;

  return {
    totalIOCs: total,
    byType,
    bySeverity,
    byFeed,
    lastUpdated: lastRow?.last_seen ?? undefined,
  };
}

// ── Threat Briefs ─────────────────────────────────────────────────────────────

export function insertBrief(
  content: string,
  opts: {
    iocCount?: number;
    model?: string;
    inputTokens?: number;
    outputTokens?: number;
    costUsd?: number;
  } = {},
): ThreatBrief {
  const d = getDB();
  const now = Date.now();
  const result = d.query<
    { id: number },
    [number, string, number | null, string | null, number | null, number | null, number | null]
  >(`
    INSERT INTO threat_briefs (created_at, content, ioc_count, model, input_tokens, output_tokens, cost_usd)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    RETURNING id
  `).get(
    now,
    content,
    opts.iocCount   ?? null,
    opts.model      ?? null,
    opts.inputTokens  != null ? opts.inputTokens  : null,
    opts.outputTokens != null ? opts.outputTokens : null,
    opts.costUsd      != null ? opts.costUsd      : null,
  );

  return getBriefById(result!.id)!;
}

export function getBriefs(limit = 10, offset = 0): ThreatBrief[] {
  return getDB().query<ThreatBrief, [number, number]>(`
    SELECT * FROM threat_briefs ORDER BY created_at DESC LIMIT ? OFFSET ?
  `).all(limit, offset);
}

export function getBriefById(id: number): ThreatBrief | null {
  return getDB().query<ThreatBrief, [number]>(
    'SELECT * FROM threat_briefs WHERE id = ?'
  ).get(id) ?? null;
}

// ── Self-test (run as script) ─────────────────────────────────────────────────
if (import.meta.main) {
  const database = initDB();
  console.log('DB initialized at:', DB_PATH);
  console.log('Tables:', database.query("SELECT name FROM sqlite_master WHERE type='table'").all());
  console.log('Stats:', getStats());
  console.log('db.ts is importable and functional.');
}

import { eq, and, desc, sql, between, gte, lte, like } from 'drizzle-orm';
import type { DatabaseConnection } from '../connection';
import { auditLog } from '../schema';

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  traceId: string;
  spanId: string;
  clientId: string | null;
  serverName: string;
  method: string;
  toolName: string | null;
  requestParams: string | null;
  responseData: string | null;
  verdict: 'allow' | 'block' | 'warn';
  blockReason: string | null;
  durationMs: number;
  upstreamDurationMs: number | null;
  tokenInput: number | null;
  tokenOutput: number | null;
  tokenModel: string | null;
  securityEvents: string | null;
  createdAt: string | null;
}

export class AuditLogRepository {
  private db: DatabaseConnection;

  constructor(db: DatabaseConnection) {
    this.db = db;
  }

  /** Insert a new audit log entry */
  insert(entry: {
    id: string;
    timestamp: string;
    traceId: string;
    spanId: string;
    clientId: string;
    serverName: string;
    method: string;
    toolName?: string;
    requestParams?: unknown;
    responseData?: unknown;
    verdict: 'allow' | 'block' | 'warn';
    blockReason?: string;
    durationMs: number;
    upstreamDurationMs?: number;
    tokenUsage?: { inputTokens: number; outputTokens: number; model: string };
    securityEvents?: unknown[];
  }): void {
    this.db.insert(auditLog).values({
      id: entry.id,
      timestamp: entry.timestamp,
      traceId: entry.traceId,
      spanId: entry.spanId,
      clientId: entry.clientId,
      serverName: entry.serverName,
      method: entry.method,
      toolName: entry.toolName ?? null,
      requestParams: entry.requestParams ? JSON.stringify(entry.requestParams) : null,
      responseData: entry.responseData ? JSON.stringify(entry.responseData) : null,
      verdict: entry.verdict,
      blockReason: entry.blockReason ?? null,
      durationMs: entry.durationMs,
      upstreamDurationMs: entry.upstreamDurationMs ?? null,
      tokenInput: entry.tokenUsage?.inputTokens ?? null,
      tokenOutput: entry.tokenUsage?.outputTokens ?? null,
      tokenModel: entry.tokenUsage?.model ?? null,
      securityEvents: entry.securityEvents ? JSON.stringify(entry.securityEvents) : null,
    }).run();
  }

  /** Query entries with filtering and pagination */
  query(opts: {
    limit?: number;
    offset?: number;
    serverName?: string;
    method?: string;
    verdict?: 'allow' | 'block' | 'warn';
    clientId?: string;
    since?: string;
    until?: string;
  } = {}): AuditLogEntry[] {
    const conditions = [];

    if (opts.serverName) conditions.push(eq(auditLog.serverName, opts.serverName));
    if (opts.method) conditions.push(eq(auditLog.method, opts.method));
    if (opts.verdict) conditions.push(eq(auditLog.verdict, opts.verdict));
    if (opts.clientId) conditions.push(eq(auditLog.clientId, opts.clientId));
    if (opts.since && opts.until) {
      conditions.push(between(auditLog.timestamp, opts.since, opts.until));
    } else if (opts.since) {
      conditions.push(gte(auditLog.timestamp, opts.since));
    } else if (opts.until) {
      conditions.push(lte(auditLog.timestamp, opts.until));
    }

    const query = this.db
      .select()
      .from(auditLog)
      .where(and(...conditions))
      .orderBy(desc(auditLog.timestamp))
      .limit(opts.limit ?? 100)
      .offset(opts.offset ?? 0);

    return query.all() as AuditLogEntry[];
  }

  /** Get a single entry by ID */
  getById(id: string): AuditLogEntry | undefined {
    return this.db
      .select()
      .from(auditLog)
      .where(eq(auditLog.id, id))
      .get() as AuditLogEntry | undefined;
  }

  /** Count entries for stats */
  count(opts: {
    serverName?: string;
    verdict?: 'allow' | 'block' | 'warn';
    since?: string;
  } = {}): number {
    const conditions = [];

    if (opts.serverName) conditions.push(eq(auditLog.serverName, opts.serverName));
    if (opts.verdict) conditions.push(eq(auditLog.verdict, opts.verdict));
    if (opts.since) conditions.push(gte(auditLog.timestamp, opts.since));

    const result = this.db
      .select({ count: sql<number>`count(*)` })
      .from(auditLog)
      .where(and(...conditions))
      .get();

    return result?.count ?? 0;
  }

  /** Get latency statistics for a time range */
  getLatencyStats(since: string): {
    avgMs: number;
    p50Ms: number;
    p95Ms: number;
    p99Ms: number;
    maxMs: number;
    count: number;
  } {
    const result = this.db
      .select({
        avgMs: sql<number>`avg(${auditLog.durationMs})`.as('avg_ms'),
        maxMs: sql<number>`max(${auditLog.durationMs})`.as('max_ms'),
        count: sql<number>`count(*)`.as('count'),
      })
      .from(auditLog)
      .where(gte(auditLog.timestamp, since))
      .get();

    return {
      avgMs: Math.round(result?.avgMs ?? 0),
      p50Ms: 0, // Requires PERCENTILE_CONT — simplified for SQLite
      p95Ms: 0,
      p99Ms: 0,
      maxMs: Math.round(result?.maxMs ?? 0),
      count: result?.count ?? 0,
    };
  }

  /** Count verdicts grouped by type */
  countByVerdict(since: string): { allow: number; block: number; warn: number } {
    const rows = this.db
      .select({
        verdict: auditLog.verdict,
        count: sql<number>`count(*)`,
      })
      .from(auditLog)
      .where(gte(auditLog.timestamp, since))
      .groupBy(auditLog.verdict)
      .all();

    const result = { allow: 0, block: 0, warn: 0 };
    for (const row of rows) {
      if (row.verdict === 'allow') result.allow = row.count;
      else if (row.verdict === 'block') result.block = row.count;
      else if (row.verdict === 'warn') result.warn = row.count;
    }
    return result;
  }

  /** Delete entries older than a cutoff */
  deleteOlderThan(cutoff: string): number {
    return this.db.delete(auditLog).where(lt(auditLog.timestamp, cutoff)).run()
      .changes;
  }

  /** Get total token usage in a time range */
  getTokenUsage(since: string): { inputTokens: number; outputTokens: number } {
    const result = this.db
      .select({
        inputTokens: sql<number>`coalesce(sum(${auditLog.tokenInput}), 0)`,
        outputTokens: sql<number>`coalesce(sum(${auditLog.tokenOutput}), 0)`,
      })
      .from(auditLog)
      .where(gte(auditLog.timestamp, since))
      .get();

    return {
      inputTokens: result?.inputTokens ?? 0,
      outputTokens: result?.outputTokens ?? 0,
    };
  }
}

function lt(column: any, value: string) {
  return sql`${column} < ${value}`;
}

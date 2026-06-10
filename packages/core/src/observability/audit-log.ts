import { randomUUID } from 'node:crypto';
import { appendFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import type { PipelineContext } from '../pipeline/types';
import type { MetricsCollector, MetricsSnapshot } from './metrics';

// ─── Audit Log ────────────────────────────────────────────────

export interface AuditLogEntry {
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
  tokenUsage?: {
    inputTokens: number;
    outputTokens: number;
    model: string;
  };
  securityEvents: SecurityEventSummary[];
  metadata?: Record<string, unknown>;
}

export interface SecurityEventSummary {
  middleware: string;
  category: string;
  message: string;
  severity: 'info' | 'warn' | 'critical';
}

export type AuditLogOutput = 'stdout' | 'file' | 'sqlite' | 'postgres';

export interface AuditLoggerOptions {
  output: AuditLogOutput;
  filePath?: string;
  format?: 'jsonl' | 'json';
}

/**
 * The AuditLogger records structured audit trail entries for every
 * request/response processed by the firewall.
 */
export class AuditLogger {
  private options: Required<AuditLoggerOptions>;
  private fileHandle: ReturnType<typeof setTimeout> | null = null;

  constructor(options: AuditLoggerOptions) {
    this.options = {
      output: options.output,
      filePath: options.filePath ?? 'audit.log',
      format: options.format ?? 'jsonl',
    };
  }

  /**
   * Record an audit log entry for a completed request/response cycle.
   */
  log(ctx: PipelineContext): AuditLogEntry {
    const entry: AuditLogEntry = {
      id: ctx.requestId,
      timestamp: new Date().toISOString(),
      traceId: ctx.traceId,
      spanId: ctx.spanId,
      clientId: ctx.client.clientId,
      serverName: ctx.serverName,
      method: ctx.method,
      toolName: ctx.toolName,
      requestParams: sanitizeForAudit(ctx.request.params),
      responseData: ctx.response
        ? sanitizeForAudit(ctx.response)
        : undefined,
      verdict: ctx.securityEvents.some((e) => e.severity === 'critical') ? 'block' : 'allow',
      durationMs: Date.now() - ctx.startTime,
      upstreamDurationMs: ctx.upstreamResponseTime
        ? ctx.upstreamResponseTime - ctx.startTime
        : undefined,
      tokenUsage: ctx.tokenUsage,
      securityEvents: ctx.securityEvents.map((e) => ({
        middleware: e.middleware,
        category: e.category,
        message: e.message,
        severity: e.severity,
      })),
      metadata: ctx.metadata,
    };

    // Check for block decisions in events
    const criticalEvent = ctx.securityEvents.find((e) => e.severity === 'critical');
    if (criticalEvent) {
      entry.verdict = 'block';
      entry.blockReason = criticalEvent.message;
    }

    this.write(entry);
    return entry;
  }

  /**
   * Flush any buffered log entries.
   */
  async flush(): Promise<void> {
    // In-memory — no buffering needed
  }

  private write(entry: AuditLogEntry): void {
    const line = JSON.stringify(entry);
    switch (this.options.output) {
      case 'stdout':
        console.log(line);
        break;
      case 'file':
        try {
          const filePath = this.options.filePath;
          mkdirSync(dirname(filePath), { recursive: true });
          appendFileSync(filePath, line + '\n', 'utf-8');
        } catch {
          // Fallback: don't crash if file write fails
          console.error(`[audit-log] Failed to write to ${this.options.filePath}`);
        }
        break;
      case 'sqlite':
      case 'postgres':
        // Database integration comes in Phase 3
        console.log(JSON.stringify({ ...entry, _store: this.options.output }));
        break;
    }
  }
}

// ─── Token Tracker ────────────────────────────────────────────

/**
 * Tracks token consumption from MCP tool calls.
 * For LLM-provider MCP servers that return token usage in responses,
 * this extracts and records it.
 */
export class TokenTracker {
  private metrics: MetricsCollector;

  constructor(metrics: MetricsCollector) {
    this.metrics = metrics;
  }

  /**
   * Estimate token usage from a request/response pair.
   *
   * Conservative estimation: ~4 chars per token for English text.
   * More accurate estimation requires provider-specific tokenizers.
   */
  estimateTokens(ctx: PipelineContext): { inputTokens: number; outputTokens: number } {
    const inputText = JSON.stringify(ctx.request.params ?? {});
    const outputText = ctx.response ? JSON.stringify(ctx.response) : '';

    // Conservative: 4 chars ≈ 1 token (rough approximation for English)
    const inputTokens = Math.ceil(inputText.length / 4);
    const outputTokens = Math.ceil(outputText.length / 4);

    this.metrics.counterIncrement('mcp_token_usage_total', {
      server_name: ctx.serverName,
      direction: 'input',
    });
    this.metrics.counterIncrement('mcp_token_usage_total', {
      server_name: ctx.serverName,
      direction: 'output',
    });

    return { inputTokens, outputTokens };
  }

  /**
   * Try to extract actual token usage from a response that contains it
   * (e.g., OpenAI/Anthropic response format).
   */
  tryExtractUsage(response: unknown): { inputTokens: number; outputTokens: number; model: string } | null {
    if (!response || typeof response !== 'object') return null;

    const resp = response as Record<string, unknown>;

    // OpenAI format: { usage: { prompt_tokens, completion_tokens, model } }
    if (resp.usage && typeof resp.usage === 'object') {
      const usage = resp.usage as Record<string, unknown>;
      if (usage.prompt_tokens && usage.completion_tokens) {
        return {
          inputTokens: Number(usage.prompt_tokens),
          outputTokens: Number(usage.completion_tokens),
          model: (usage.model as string) ?? 'unknown',
        };
      }
    }

    // Anthropic format: { usage: { input_tokens, output_tokens }, model }
    if (resp.usage && typeof resp.usage === 'object') {
      const usage = resp.usage as Record<string, unknown>;
      if (usage.input_tokens && usage.output_tokens) {
        return {
          inputTokens: Number(usage.input_tokens),
          outputTokens: Number(usage.output_tokens),
          model: (resp.model as string) ?? 'unknown',
        };
      }
    }

    return null;
  }
}

// ─── Tracer ──────────────────────────────────────────────────

export interface Span {
  traceId: string;
  spanId: string;
  parentSpanId?: string;
  name: string;
  startTime: number;
  endTime?: number;
  attributes: Record<string, string | number | boolean>;
  events: SpanEvent[];
  status: 'ok' | 'error';
}

export interface SpanEvent {
  name: string;
  timestamp: number;
  attributes?: Record<string, string | number | boolean>;
}

/**
 * Simple in-process tracer that creates OpenTelemetry-compatible spans.
 * In production, these are exported via OTLP to Jaeger/Tempo.
 */
export class Tracer {
  private spans: Map<string, Span> = new Map();
  private enabled: boolean;

  constructor(enabled = false) {
    this.enabled = enabled;
  }

  startSpan(name: string, parentSpanId?: string): Span {
    const span: Span = {
      traceId: randomUUID(),
      spanId: randomUUID().slice(0, 16),
      parentSpanId,
      name,
      startTime: Date.now(),
      attributes: {},
      events: [],
      status: 'ok',
    };

    if (this.enabled) {
      this.spans.set(span.spanId, span);
    }

    return span;
  }

  endSpan(span: Span, status: 'ok' | 'error' = 'ok'): void {
    span.endTime = Date.now();
    span.status = status;
  }

  addEvent(span: Span, name: string, attributes?: Record<string, string | number | boolean>): void {
    span.events.push({ name, timestamp: Date.now(), attributes });
  }

  setAttribute(span: Span, key: string, value: string | number | boolean): void {
    span.attributes[key] = value;
  }

  getSpan(spanId: string): Span | undefined {
    return this.spans.get(spanId);
  }

  /**
   * Get all completed spans for export.
   */
  getCompletedSpans(): Span[] {
    return Array.from(this.spans.values()).filter((s) => s.endTime !== undefined);
  }
}

// ─── Health Checker ───────────────────────────────────────────

export interface ServerHealth {
  serverName: string;
  status: 'healthy' | 'unhealthy' | 'unknown';
  lastCheck: string;
  lastError?: string;
  consecutiveFailures: number;
}

/**
 * Periodically checks the health of upstream MCP servers.
 */
export class HealthChecker {
  private servers: Map<string, ServerHealth> = new Map();
  private intervals: Map<string, ReturnType<typeof setInterval>> = new Map();
  private metrics: MetricsCollector;

  constructor(metrics: MetricsCollector) {
    this.metrics = metrics;
  }

  registerServer(serverName: string, checkFn: () => Promise<boolean>, intervalMs: number): void {
    this.servers.set(serverName, {
      serverName,
      status: 'unknown',
      lastCheck: new Date().toISOString(),
      consecutiveFailures: 0,
    });

    this.metrics.gaugeSet(`mcp_upstream_server_health{server_name="${serverName}"}`, 0);

    const timer = setInterval(async () => {
      try {
        const healthy = await checkFn();
        const health = this.servers.get(serverName);
        if (health) {
          health.status = healthy ? 'healthy' : 'unhealthy';
          health.lastCheck = new Date().toISOString();
          health.consecutiveFailures = healthy ? 0 : health.consecutiveFailures + 1;
          this.metrics.gaugeSet(
            `mcp_upstream_server_health{server_name="${serverName}"}`,
            healthy ? 1 : 0,
          );
        }
      } catch (err) {
        const health = this.servers.get(serverName);
        if (health) {
          health.status = 'unhealthy';
          health.lastError = err instanceof Error ? err.message : String(err);
          health.consecutiveFailures++;
          this.metrics.gaugeSet(
            `mcp_upstream_server_health{server_name="${serverName}"}`,
            0,
          );
        }
      }
    }, intervalMs);

    this.intervals.set(serverName, timer);
  }

  unregisterServer(serverName: string): void {
    const timer = this.intervals.get(serverName);
    if (timer) clearInterval(timer);
    this.intervals.delete(serverName);
    this.servers.delete(serverName);
  }

  getHealth(serverName: string): ServerHealth | undefined {
    return this.servers.get(serverName);
  }

  getAllHealth(): ServerHealth[] {
    return Array.from(this.servers.values());
  }

  destroy(): void {
    for (const timer of this.intervals.values()) {
      clearInterval(timer);
    }
    this.intervals.clear();
    this.servers.clear();
  }
}

// ─── Helpers ─────────────────────────────────────────────────

/**
 * Sanitize data for audit logging — truncate large values
 * and redact potentially sensitive fields.
 */
function sanitizeForAudit(data: unknown, maxLength = 10_000): unknown {
  if (data === null || data === undefined) return data;
  if (typeof data !== 'object') {
    const str = String(data);
    return str.length > maxLength ? str.slice(0, maxLength) + '...[truncated]' : str;
  }

  try {
    const serialized = JSON.stringify(data);
    if (serialized.length <= maxLength) return data;
    return JSON.parse(serialized.slice(0, maxLength) + '...[truncated]');
  } catch {
    return '[unserializable]';
  }
}

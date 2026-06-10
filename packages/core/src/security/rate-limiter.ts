import type { SecurityMiddleware, PipelineContext, SecurityDecision } from '../pipeline/types';
import type { RateLimitRule } from '@ziwansi/mcp-firewall-config';

// ─── Rate Limiter ──────────────────────────────────────────────

interface WindowBucket {
  timestamps: number[];
  count: number;
}

/**
 * Sliding-window rate limiter middleware.
 *
 * Limits the number of requests per time window, keyed by
 * configurable dimensions (client-id, tool-name, server-name, api-key).
 *
 * Priority: 40
 */
export class RateLimiterMiddleware implements SecurityMiddleware {
  readonly name = 'rate-limiter';
  readonly priority = 40;
  readonly phase = 'request' as const;

  private rules: CompiledRateLimitRule[];
  private buckets: Map<string, WindowBucket> = new Map();

  // Periodic cleanup of expired buckets
  private cleanupInterval: ReturnType<typeof setInterval>;

  constructor(rules: RateLimitRule[]) {
    this.rules = rules.map(compileRule);

    // Clean up stale buckets every 60 seconds
    this.cleanupInterval = setInterval(() => this.cleanup(), 60_000);
  }

  async evaluate(ctx: PipelineContext): Promise<SecurityDecision | null> {
    if (this.rules.length === 0) return null;

    const now = Date.now();

    for (const rule of this.rules) {
      const key = buildKey(rule.keyBy, ctx);

      let bucket = this.buckets.get(key);
      if (!bucket) {
        bucket = { timestamps: [], count: 0 };
        this.buckets.set(key, bucket);
      }

      // Remove timestamps outside the window
      const cutoff = now - rule.windowMs;
      bucket.timestamps = bucket.timestamps.filter((t) => t > cutoff);
      bucket.count = bucket.timestamps.length;

      if (bucket.count >= rule.maxRequests) {
        return {
          verdict: 'block',
          reason: `Rate limit exceeded for "${rule.name}": ${bucket.count}/${rule.maxRequests} requests in window`,
          errorCode: -32001,
          metadata: {
            limitName: rule.name,
            current: bucket.count,
            limit: rule.maxRequests,
            windowMs: rule.windowMs,
          },
        };
      }

      // Record this request
      bucket.timestamps.push(now);
      bucket.count = bucket.timestamps.length;
    }

    return null;
  }

  /**
   * Get current usage statistics for all active rate limit rules.
   */
  getStats(): Array<{ ruleName: string; keys: Array<{ key: string; count: number }> }> {
    const now = Date.now();
    return this.rules.map((rule) => ({
      ruleName: rule.name,
      keys: Array.from(this.buckets.entries())
        .filter(([k]) => k.startsWith(rule.name + ':'))
        .map(([k, bucket]) => {
          const cutoff = now - rule.windowMs;
          const active = bucket.timestamps.filter((t) => t > cutoff).length;
          return { key: k, count: active };
        }),
    }));
  }

  private cleanup(): void {
    const now = Date.now();
    const maxWindow = Math.max(...this.rules.map((r) => r.windowMs), 60_000);
    const cutoff = now - maxWindow;

    for (const [key, bucket] of this.buckets) {
      bucket.timestamps = bucket.timestamps.filter((t) => t > cutoff);
      if (bucket.timestamps.length === 0) {
        this.buckets.delete(key);
      }
    }
  }

  /**
   * Clean up interval on destroy.
   */
  destroy(): void {
    clearInterval(this.cleanupInterval);
    this.buckets.clear();
  }
}

// ─── Compiled rule ────────────────────────────────────────────

interface CompiledRateLimitRule {
  name: string;
  windowMs: number;
  maxRequests: number;
  keyBy: RateLimitRule['keyBy'];
  strategy: RateLimitRule['strategy'];
}

function compileRule(rule: RateLimitRule): CompiledRateLimitRule {
  return {
    name: rule.name,
    windowMs: parseWindow(rule.window),
    maxRequests: rule.maxRequests,
    keyBy: rule.keyBy,
    strategy: rule.strategy,
  };
}

function buildKey(keyBy: RateLimitRule['keyBy'], ctx: PipelineContext): string {
  return keyBy
    .map((dim) => {
      switch (dim) {
        case 'client-id':
          return ctx.client.clientId;
        case 'api-key':
          return (ctx.metadata['apiKey'] as string) ?? 'unknown';
        case 'tool-name':
          return ctx.toolName ?? ctx.method;
        case 'server-name':
          return ctx.serverName;
      }
    })
    .join(':');
}

/**
 * Parse a duration string like "1s", "1m", "1h" to milliseconds.
 */
function parseWindow(window: string): number {
  const match = window.match(/^(\d+)(s|m|h|d)$/);
  if (!match) {
    throw new Error(`Invalid window format: "${window}". Use <number><s|m|h|d>`);
  }
  const value = parseInt(match[1]!, 10);
  switch (match[2]) {
    case 's':
      return value * 1000;
    case 'm':
      return value * 60_000;
    case 'h':
      return value * 3_600_000;
    case 'd':
      return value * 86_400_000;
    default:
      return 60_000;
  }
}

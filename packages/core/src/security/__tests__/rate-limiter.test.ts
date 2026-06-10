import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { RateLimiterMiddleware } from '../../security/rate-limiter';
import { createPipelineContext } from '../../pipeline/context';
import type { RateLimitRule } from '@ziwansi/mcp-firewall-config';

describe('RateLimiterMiddleware', () => {
  let middleware: RateLimiterMiddleware;

  afterEach(() => {
    if (middleware) {
      middleware.destroy();
    }
  });

  const rule: RateLimitRule = {
    name: 'test-limit',
    window: '1s',
    maxRequests: 3,
    keyBy: ['client-id'],
    strategy: 'sliding-window',
  };

  it('should allow requests under the limit', async () => {
    middleware = new RateLimiterMiddleware([rule]);
    const ctx = createPipelineContext({
      clientId: 'test-client',
      serverName: 'test',
      method: 'tools/call',
      request: { jsonrpc: '2.0', id: '1', method: 'tools/call' },
    });

    const r1 = await middleware.evaluate(ctx);
    const r2 = await middleware.evaluate(ctx);
    const r3 = await middleware.evaluate(ctx);

    expect(r1).toBeNull();
    expect(r2).toBeNull();
    expect(r3).toBeNull();
  });

  it('should block requests over the limit', async () => {
    middleware = new RateLimiterMiddleware([rule]);
    const ctx = createPipelineContext({
      clientId: 'test-client',
      serverName: 'test',
      method: 'tools/call',
      request: { jsonrpc: '2.0', id: '1', method: 'tools/call' },
    });

    await middleware.evaluate(ctx);
    await middleware.evaluate(ctx);
    await middleware.evaluate(ctx);
    const r4 = await middleware.evaluate(ctx);

    expect(r4?.verdict).toBe('block');
    expect(r4?.reason).toContain('Rate limit exceeded');
  });

  it('should key by tool-name independently', async () => {
    middleware = new RateLimiterMiddleware([
      {
        name: 'per-tool',
        window: '1h',
        maxRequests: 1,
        keyBy: ['client-id', 'tool-name'],
      },
    ]);

    const ctx1 = createPipelineContext({
      clientId: 'client',
      serverName: 'srv',
      method: 'tools/call',
      toolName: 'tool_a',
      request: { jsonrpc: '2.0', id: '1', method: 'tools/call', params: { name: 'tool_a' } },
    });
    const ctx2 = createPipelineContext({
      clientId: 'client',
      serverName: 'srv',
      method: 'tools/call',
      toolName: 'tool_b',
      request: { jsonrpc: '2.0', id: '2', method: 'tools/call', params: { name: 'tool_b' } },
    });

    const r1 = await middleware.evaluate(ctx1);
    const r2 = await middleware.evaluate(ctx2);

    expect(r1).toBeNull();
    expect(r2).toBeNull();
  });

  it('should return stats for rate limiters', () => {
    middleware = new RateLimiterMiddleware([rule]);
    const stats = middleware.getStats();
    expect(stats).toHaveLength(1);
    expect(stats[0]!.ruleName).toBe('test-limit');
  });
});

import { describe, it, expect } from 'vitest';
import { ConcurrencyLimiterMiddleware } from '../../security/concurrency-limiter';
import { createPipelineContext } from '../../pipeline/context';

describe('ConcurrencyLimiterMiddleware', () => {
  const defaultOpts = (overrides: Partial<{
    enabled: boolean; maxConcurrent: number; maxConcurrentPerTool: number;
    queueEnabled: boolean; maxQueueSize: number;
  }> = {}) => ({
    enabled: true,
    maxConcurrent: 2,
    maxConcurrentPerTool: 5,
    queueEnabled: false,
    maxQueueSize: 10,
    ...overrides,
  });

  const makeCtx = (clientId: string, toolName?: string) =>
    createPipelineContext({
      clientId,
      serverName: 'test',
      method: 'tools/call',
      toolName,
      request: {
        jsonrpc: '2.0',
        id: '1',
        method: 'tools/call',
        params: toolName ? { name: toolName, arguments: {} } : undefined,
      },
    });

  // ─── Basic concurrency limit ─────────────────────────────────

  it('should pass when under concurrency limit', async () => {
    const mw = new ConcurrencyLimiterMiddleware(defaultOpts({ maxConcurrent: 10 }));
    const ctx = makeCtx('client-1', 'read_file');
    const result = await mw.evaluate(ctx);
    expect(result).toBeNull();
  });

  it('should block when client exceeds max concurrent', async () => {
    const mw = new ConcurrencyLimiterMiddleware(defaultOpts({ maxConcurrent: 2 }));

    // Fill up to the limit
    await mw.evaluate(makeCtx('client-A', 'tool1'));
    await mw.evaluate(makeCtx('client-A', 'tool2'));

    // 3rd request should block
    const ctx3 = makeCtx('client-A', 'tool3');
    const result = await mw.evaluate(ctx3);
    expect(result?.verdict).toBe('block');
    expect(result?.reason).toContain('concurrent');
  });

  it('should allow requests from different clients', async () => {
    const mw = new ConcurrencyLimiterMiddleware(defaultOpts({ maxConcurrent: 1 }));

    // Fill client-A's limit
    await mw.evaluate(makeCtx('client-A', 'tool1'));

    // client-B should still pass
    const ctxB = makeCtx('client-B', 'tool1');
    const result = await mw.evaluate(ctxB);
    expect(result).toBeNull();
  });

  // ─── Tool-level concurrency ──────────────────────────────────

  it('should block when tool exceeds max concurrent', async () => {
    const mw = new ConcurrencyLimiterMiddleware(defaultOpts({
      maxConcurrent: 100,
      maxConcurrentPerTool: 2,
    }));

    // Fill tool limit
    await mw.evaluate(makeCtx('client-1', 'write_file'));
    await mw.evaluate(makeCtx('client-2', 'write_file'));

    // 3rd request to same tool
    const ctx3 = makeCtx('client-3', 'write_file');
    const result = await mw.evaluate(ctx3);
    expect(result?.verdict).toBe('block');
  });

  it('should allow same client using different tools', async () => {
    const mw = new ConcurrencyLimiterMiddleware(defaultOpts({
      maxConcurrent: 10,
      maxConcurrentPerTool: 1,
    }));

    await mw.evaluate(makeCtx('client-1', 'read_file'));
    const ctx = makeCtx('client-1', 'write_file');
    const result = await mw.evaluate(ctx);
    expect(result).toBeNull();
  });

  // ─── Release and re-allow ────────────────────────────────────

  it('should allow new request after releasing a slot', async () => {
    const mw = new ConcurrencyLimiterMiddleware(defaultOpts({ maxConcurrent: 1 }));

    const ctx1 = makeCtx('client-X', 'tool1');
    await mw.evaluate(ctx1); // Takes the only slot

    // 2nd request blocked
    const ctx2 = makeCtx('client-X', 'tool1');
    const blocked = await mw.evaluate(ctx2);
    expect(blocked?.verdict).toBe('block');

    // Release
    mw.release('client-X', 'test:tool1');

    // Now a new request should pass
    const ctx3 = makeCtx('client-X', 'tool1');
    const result = await mw.evaluate(ctx3);
    expect(result).toBeNull();
  });

  it('should correctly track tool count after release', async () => {
    const mw = new ConcurrencyLimiterMiddleware(defaultOpts({
      maxConcurrent: 10,
      maxConcurrentPerTool: 1,
    }));

    await mw.evaluate(makeCtx('c1', 'write_file'));
    const blocked = await mw.evaluate(makeCtx('c2', 'write_file'));
    expect(blocked?.verdict).toBe('block');

    mw.release('c1', 'test:write_file');

    const pass = await mw.evaluate(makeCtx('c2', 'write_file'));
    expect(pass).toBeNull();
  });

  // ─── Queue mode ───────────────────────────────────────────────

  it('should queue requests when queue is enabled', async () => {
    const mw = new ConcurrencyLimiterMiddleware(defaultOpts({
      maxConcurrent: 1,
      queueEnabled: true,
      maxQueueSize: 5,
    }));

    // Take the only slot
    await mw.evaluate(makeCtx('q-client', 'tool1'));

    // Queue the request (it returns a Promise that resolves on release)
    const ctx2 = makeCtx('q-client', 'tool2');
    const queuedPromise = mw.evaluate(ctx2);

    // Release slot — this should process the queue
    mw.release('q-client', 'test:tool1');

    const result = await queuedPromise;
    expect(result).toBeNull();

    // Release the queued request's slot too
    mw.release('q-client', 'test:tool2');
  });

  it('should block when queue is full', async () => {
    const mw = new ConcurrencyLimiterMiddleware(defaultOpts({
      maxConcurrent: 1,
      queueEnabled: true,
      maxQueueSize: 1,
    }));

    // Take the slot
    await mw.evaluate(makeCtx('full-client', 'tool1'));

    // Queue one (fills queue)
    const queued = mw.evaluate(makeCtx('full-client', 'tool2'));

    // Queue is full — this should block immediately
    const ctx3 = makeCtx('full-client', 'tool3');
    const result = await mw.evaluate(ctx3);
    expect(result?.verdict).toBe('block');
    expect(result?.reason).toContain('queue');

    // Clean up
    mw.release('full-client', 'test:tool1');
    await queued;
    mw.release('full-client', 'test:tool2');
  });

  // ─── Stats ────────────────────────────────────────────────────

  it('should report correct stats', async () => {
    const mw = new ConcurrencyLimiterMiddleware(defaultOpts({ maxConcurrent: 10 }));

    await mw.evaluate(makeCtx('s1', 'tool_a'));
    await mw.evaluate(makeCtx('s1', 'tool_b'));
    await mw.evaluate(makeCtx('s2', 'tool_a'));

    const stats = mw.getStats();
    expect(stats.activeClients).toBeGreaterThanOrEqual(1);
    expect(stats.activeTools).toBeGreaterThanOrEqual(1);

    // Clean up
    mw.release('s1', 'test:tool_a');
    mw.release('s1', 'test:tool_b');
    mw.release('s2', 'test:tool_a');
  });

  // ─── Disabled ────────────────────────────────────────────────

  it('should pass when disabled', async () => {
    const mw = new ConcurrencyLimiterMiddleware(defaultOpts({
      enabled: false,
      maxConcurrent: 1, // Would block if enabled
    }));
    const ctx = makeCtx('test', 'tool1');
    expect(await mw.evaluate(ctx)).toBeNull();
    expect(await mw.evaluate(ctx)).toBeNull();
  });

  // ─── Metadata storage for release ────────────────────────────

  it('should store concurrency keys in context metadata', async () => {
    const mw = new ConcurrencyLimiterMiddleware(defaultOpts({ maxConcurrent: 10 }));
    const ctx = makeCtx('meta-test', 'read_config');
    await mw.evaluate(ctx);

    expect(ctx.metadata['_concurrencyClientKey']).toBe('meta-test');
    expect(ctx.metadata['_concurrencyToolKey']).toBe('test:read_config');

    mw.release('meta-test', 'test:read_config');
  });
});

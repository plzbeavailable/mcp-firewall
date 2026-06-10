import { describe, it, expect } from 'vitest';
import { ResponseLimiterMiddleware } from '../../security/response-limiter';
import { createPipelineContext, cloneContextForResponse } from '../../pipeline/context';

describe('ResponseLimiterMiddleware', () => {
  const defaultOpts = (overrides: Partial<{
    enabled: boolean; maxResponseSize: number; maxItems: number; maxResponseDepth: number;
  }> = {}) => ({
    enabled: true,
    maxResponseSize: 10_485_760, // 10 MB
    maxItems: 100,
    maxResponseDepth: 10,
    ...overrides,
  });

  const makeResponseCtx = (responseResult: unknown) => {
    const ctx = createPipelineContext({
      clientId: 'test',
      serverName: 'test',
      method: 'tools/call',
      request: { jsonrpc: '2.0', id: '1', method: 'tools/call' },
    });
    return cloneContextForResponse(ctx, {
      jsonrpc: '2.0',
      id: '1',
      result: responseResult,
    });
  };

  // ─── Response size limits ────────────────────────────────────

  it('should pass for small responses', async () => {
    const mw = new ResponseLimiterMiddleware(defaultOpts());
    const ctx = makeResponseCtx({ message: 'ok' });
    const result = await mw.evaluate(ctx);
    expect(result).toBeNull();
  });

  it('should block responses exceeding size limit', async () => {
    const mw = new ResponseLimiterMiddleware(defaultOpts({ maxResponseSize: 50 }));
    const ctx = makeResponseCtx({ data: 'x'.repeat(200) });
    const result = await mw.evaluate(ctx);
    expect(result?.verdict).toBe('block');
    expect(result?.reason).toContain('size');
  });

  it('should pass responses just under the size limit', async () => {
    const mw = new ResponseLimiterMiddleware(defaultOpts({ maxResponseSize: 500 }));
    const ctx = makeResponseCtx({ data: 'x'.repeat(100) });
    const result = await mw.evaluate(ctx);
    expect(result).toBeNull();
  });

  // ─── Item count limits ───────────────────────────────────────

  it('should block when array result exceeds item limit', async () => {
    const mw = new ResponseLimiterMiddleware(defaultOpts({ maxItems: 5 }));
    const ctx = makeResponseCtx(Array.from({ length: 10 }, (_, i) => ({ id: i })));
    const result = await mw.evaluate(ctx);
    expect(result?.verdict).toBe('block');
    expect(result?.reason).toContain('item count');
  });

  it('should block when items array exceeds limit', async () => {
    const mw = new ResponseLimiterMiddleware(defaultOpts({ maxItems: 3 }));
    const ctx = makeResponseCtx({ items: [1, 2, 3, 4, 5] });
    const result = await mw.evaluate(ctx);
    expect(result?.verdict).toBe('block');
  });

  it('should block when data array exceeds limit', async () => {
    const mw = new ResponseLimiterMiddleware(defaultOpts({ maxItems: 2 }));
    const ctx = makeResponseCtx({ data: ['a', 'b', 'c'] });
    const result = await mw.evaluate(ctx);
    expect(result?.verdict).toBe('block');
  });

  it('should block when results array exceeds limit', async () => {
    const mw = new ResponseLimiterMiddleware(defaultOpts({ maxItems: 4 }));
    const ctx = makeResponseCtx({ results: [1, 2, 3, 4, 5, 6] });
    const result = await mw.evaluate(ctx);
    expect(result?.verdict).toBe('block');
  });

  it('should block when tools array exceeds limit', async () => {
    const mw = new ResponseLimiterMiddleware(defaultOpts({ maxItems: 2 }));
    const tools = [{ name: 'a' }, { name: 'b' }, { name: 'c' }];
    const ctx = makeResponseCtx({ tools });
    const result = await mw.evaluate(ctx);
    expect(result?.verdict).toBe('block');
  });

  it('should pass when item count is under limit', async () => {
    const mw = new ResponseLimiterMiddleware(defaultOpts({ maxItems: 10 }));
    const ctx = makeResponseCtx({ items: [1, 2, 3, 4, 5] });
    const result = await mw.evaluate(ctx);
    expect(result).toBeNull();
  });

  // ─── Depth limits ─────────────────────────────────────────────

  it('should block when response depth exceeds limit', async () => {
    const mw = new ResponseLimiterMiddleware(defaultOpts({ maxResponseDepth: 3 }));
    const deep = { a: { b: { c: { d: { e: 'too deep' } } } } };
    const ctx = makeResponseCtx(deep);
    const result = await mw.evaluate(ctx);
    expect(result?.verdict).toBe('block');
    expect(result?.reason).toContain('depth');
  });

  it('should pass when depth is under limit', async () => {
    const mw = new ResponseLimiterMiddleware(defaultOpts({ maxResponseDepth: 10 }));
    const shallow = { a: { b: { c: 'shallow' } } };
    const ctx = makeResponseCtx(shallow);
    const result = await mw.evaluate(ctx);
    expect(result).toBeNull();
  });

  it('should count array nesting in depth', async () => {
    const mw = new ResponseLimiterMiddleware(defaultOpts({ maxResponseDepth: 2 }));
    const nested = { items: [[[1, 2, 3]]] }; // depth 4
    const ctx = makeResponseCtx(nested);
    const result = await mw.evaluate(ctx);
    expect(result?.verdict).toBe('block');
  });

  // ─── Disabled ────────────────────────────────────────────────

  it('should pass when disabled', async () => {
    const mw = new ResponseLimiterMiddleware(defaultOpts({
      enabled: false,
      maxResponseSize: 10, // Would block if enabled
    }));
    const ctx = makeResponseCtx({ data: 'x'.repeat(1000) });
    const result = await mw.evaluate(ctx);
    expect(result).toBeNull();
  });

  // ─── No response (request phase) ─────────────────────────────

  it('should pass in request phase (no response)', async () => {
    const mw = new ResponseLimiterMiddleware(defaultOpts());
    const ctx = createPipelineContext({
      clientId: 'test',
      serverName: 'test',
      method: 'tools/call',
      request: { jsonrpc: '2.0', id: '1', method: 'tools/call' },
    });
    // No response set — this is request phase
    const result = await mw.evaluate(ctx);
    expect(result).toBeNull();
  });

  // ─── Edge: empty response ────────────────────────────────────

  it('should pass for empty object response', async () => {
    const mw = new ResponseLimiterMiddleware(defaultOpts());
    const ctx = makeResponseCtx({});
    const result = await mw.evaluate(ctx);
    expect(result).toBeNull();
  });

  it('should pass for null result response', async () => {
    const mw = new ResponseLimiterMiddleware(defaultOpts());
    const ctx = makeResponseCtx(null);
    const result = await mw.evaluate(ctx);
    expect(result).toBeNull();
  });

  // ─── Large item count in nested structures ───────────────────

  it('should count items in content array', async () => {
    const mw = new ResponseLimiterMiddleware(defaultOpts({ maxItems: 3 }));
    const ctx = makeResponseCtx({ content: [{ type: 'text', text: 'a' }, { type: 'text', text: 'b' }, { type: 'text', text: 'c' }, { type: 'text', text: 'd' }] });
    const result = await mw.evaluate(ctx);
    expect(result?.verdict).toBe('block');
  });

  it('should count items in prompts array', async () => {
    const mw = new ResponseLimiterMiddleware(defaultOpts({ maxItems: 2 }));
    const ctx = makeResponseCtx({ prompts: ['p1', 'p2', 'p3'] });
    const result = await mw.evaluate(ctx);
    expect(result?.verdict).toBe('block');
  });
});

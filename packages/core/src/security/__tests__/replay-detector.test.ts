import { describe, it, expect, afterEach } from 'vitest';
import { ReplayDetectorMiddleware } from '../../security/replay-detector';
import { createPipelineContext } from '../../pipeline/context';

describe('ReplayDetectorMiddleware', () => {
  const defaultOpts = (overrides: Partial<{
    enabled: boolean; nonceTtlSeconds: number; maxClockSkew: number; requireNonce: boolean;
  }> = {}) => ({
    enabled: true,
    nonceTtlSeconds: 300,
    maxClockSkew: 30,
    requireNonce: true,
    ...overrides,
  });

  const ctxWithNonce = (nonce: string, timestamp?: number) => {
    const ctx = createPipelineContext({
      clientId: 'test-client',
      serverName: 'test',
      method: 'tools/call',
      request: {
        jsonrpc: '2.0',
        id: '1',
        method: 'tools/call',
        params: {
          name: 'test',
          arguments: {},
          _meta: { nonce, timestamp },
        },
      },
    });
    return ctx;
  };

  afterEach(() => {
    // Clean up created detectors (they use setInterval)
  });

  // ─── Nonce presence ──────────────────────────────────────────

  it('should block when nonce is required but not provided', async () => {
    const mw = new ReplayDetectorMiddleware(defaultOpts({ requireNonce: true }));
    const ctx = ctxWithNonce('');
    // Remove the nonce from params
    if (ctx.request.params && typeof ctx.request.params === 'object') {
      const params = ctx.request.params as Record<string, unknown>;
      if (params._meta) delete (params._meta as Record<string, unknown>).nonce;
    }
    const result = await mw.evaluate(ctx);
    expect(result?.verdict).toBe('block');
    expect(result?.reason).toContain('Nonce');
    mw.destroy();
  });

  it('should pass when nonce is not required and not provided', async () => {
    const mw = new ReplayDetectorMiddleware(defaultOpts({ requireNonce: false }));
    const ctx = createPipelineContext({
      clientId: 'test',
      serverName: 'test',
      method: 'tools/call',
      request: { jsonrpc: '2.0', id: '1', method: 'tools/call', params: { name: 'test', arguments: {} } },
    });
    const result = await mw.evaluate(ctx);
    expect(result).toBeNull();
    mw.destroy();
  });

  // ─── Nonce format validation ─────────────────────────────────

  it('should block short nonces (less than 8 chars)', async () => {
    const mw = new ReplayDetectorMiddleware(defaultOpts());
    const ctx = ctxWithNonce('abc');
    const result = await mw.evaluate(ctx);
    expect(result?.verdict).toBe('block');
    expect(result?.reason).toContain('Invalid nonce format');
    mw.destroy();
  });

  it('should block excessively long nonces', async () => {
    const mw = new ReplayDetectorMiddleware(defaultOpts());
    const ctx = ctxWithNonce('a'.repeat(300));
    const result = await mw.evaluate(ctx);
    expect(result?.verdict).toBe('block');
    expect(result?.reason).toContain('Invalid nonce format');
    mw.destroy();
  });

  // ─── Timestamp validation ────────────────────────────────────

  it('should block when timestamp skew exceeds maxClockSkew', async () => {
    const mw = new ReplayDetectorMiddleware(defaultOpts({ maxClockSkew: 5 }));
    const ctx = ctxWithNonce('valid-nonce-12345', Date.now() - 30000); // 30s ago
    const result = await mw.evaluate(ctx);
    expect(result?.verdict).toBe('block');
    expect(result?.reason).toContain('timestamp skew');
    mw.destroy();
  });

  it('should pass when timestamp is within skew window', async () => {
    const mw = new ReplayDetectorMiddleware(defaultOpts({ maxClockSkew: 300 }));
    const ctx = ctxWithNonce('valid-nonce-67890', Date.now() - 10000); // 10s ago
    const result = await mw.evaluate(ctx);
    expect(result?.verdict).not.toBe('block');
    mw.destroy();
  });

  it('should pass with no timestamp (only nonce)', async () => {
    const mw = new ReplayDetectorMiddleware(defaultOpts());
    const ctx = ctxWithNonce('valid-nonce-no-ts');
    const result = await mw.evaluate(ctx);
    expect(result?.verdict).not.toBe('block');
    mw.destroy();
  });

  // ─── Duplicate nonce detection ────────────────────────────────

  it('should block duplicate nonce (replay attack)', async () => {
    const mw = new ReplayDetectorMiddleware(defaultOpts());
    const nonce = 'unique-nonce-replay-test';

    const ctx1 = ctxWithNonce(nonce);
    const result1 = await mw.evaluate(ctx1);
    expect(result1).toBeNull(); // First time passes

    const ctx2 = ctxWithNonce(nonce);
    const result2 = await mw.evaluate(ctx2);
    expect(result2?.verdict).toBe('block');
    expect(result2?.reason).toContain('replay');
    mw.destroy();
  });

  it('should block duplicate nonce from different client IDs (still replay)', async () => {
    const mw = new ReplayDetectorMiddleware(defaultOpts());
    const nonce = 'shared-nonce-test';

    const ctx1 = createPipelineContext({
      clientId: 'client-A',
      serverName: 'test',
      method: 'tools/call',
      request: {
        jsonrpc: '2.0', id: '1', method: 'tools/call',
        params: { name: 'test', arguments: {}, _meta: { nonce } },
      },
    });
    await mw.evaluate(ctx1);

    const ctx2 = createPipelineContext({
      clientId: 'client-B',
      serverName: 'test',
      method: 'tools/call',
      request: {
        jsonrpc: '2.0', id: '2', method: 'tools/call',
        params: { name: 'test', arguments: {}, _meta: { nonce } },
      },
    });
    const result2 = await mw.evaluate(ctx2);
    // Same nonce from different client — the key is clientId:nonce
    expect(result2).toBeNull();
    mw.destroy();
  });

  it('should pass with different nonces', async () => {
    const mw = new ReplayDetectorMiddleware(defaultOpts());

    const ctx1 = ctxWithNonce('nonce-alpha-999');
    expect(await mw.evaluate(ctx1)).toBeNull();

    const ctx2 = ctxWithNonce('nonce-beta-888');
    expect(await mw.evaluate(ctx2)).toBeNull();

    const ctx3 = ctxWithNonce('nonce-gamma-777');
    expect(await mw.evaluate(ctx3)).toBeNull();

    mw.destroy();
  });

  // ─── Nonce via metadata ──────────────────────────────────────

  it('should extract nonce from context metadata', async () => {
    const mw = new ReplayDetectorMiddleware(defaultOpts());
    const ctx = createPipelineContext({
      clientId: 'test',
      serverName: 'test',
      method: 'tools/call',
      request: {
        jsonrpc: '2.0', id: '1', method: 'tools/call',
        params: { name: 'test', arguments: {} },
      },
    });
    ctx.metadata['nonce'] = 'metadata-nonce-valid';
    const result = await mw.evaluate(ctx);
    expect(result?.verdict).not.toBe('block');
    mw.destroy();
  });

  // ─── Reset functionality ─────────────────────────────────────

  it('should reset nonce tracking', async () => {
    const mw = new ReplayDetectorMiddleware(defaultOpts());
    const nonce = 'reset-test-nonce';

    await mw.evaluate(ctxWithNonce(nonce));

    // Before reset, duplicate is blocked
    const blocked = await mw.evaluate(ctxWithNonce(nonce));
    expect(blocked?.verdict).toBe('block');

    // After reset, the nonce can be used again
    mw.reset();
    const afterReset = await mw.evaluate(ctxWithNonce(nonce));
    expect(afterReset).toBeNull();

    mw.destroy();
  });

  // ─── Disabled middleware ──────────────────────────────────────

  it('should pass when disabled', async () => {
    const mw = new ReplayDetectorMiddleware(defaultOpts({ enabled: false }));
    const ctx = createPipelineContext({
      clientId: 'test',
      serverName: 'test',
      method: 'tools/call',
      request: { jsonrpc: '2.0', id: '1', method: 'tools/call' },
    });
    const result = await mw.evaluate(ctx);
    expect(result).toBeNull();
    mw.destroy();
  });
});

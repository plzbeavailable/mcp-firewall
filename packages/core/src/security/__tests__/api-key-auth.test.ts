import { describe, it, expect } from 'vitest';
import { ApiKeyAuthMiddleware } from '../../security/api-key-auth';
import { createPipelineContext } from '../../pipeline/context';

describe('ApiKeyAuthMiddleware', () => {
  it('should pass when auth is disabled', async () => {
    const mw = new ApiKeyAuthMiddleware([], false);
    const ctx = createPipelineContext({
      clientId: 'default',
      serverName: 'test',
      method: 'tools/list',
      request: { jsonrpc: '2.0', id: '1', method: 'tools/list' },
    });
    const result = await mw.evaluate(ctx);
    expect(result).toBeNull();
  });

  it('should pass with no keys configured', async () => {
    const mw = new ApiKeyAuthMiddleware([], true);
    const ctx = createPipelineContext({
      clientId: 'default',
      serverName: 'test',
      method: 'tools/list',
      request: { jsonrpc: '2.0', id: '1', method: 'tools/list' },
    });
    const result = await mw.evaluate(ctx);
    expect(result).toBeNull();
  });

  it('should block when API key is required but not provided', async () => {
    const mw = new ApiKeyAuthMiddleware(
      [{ key: 'secret-key-123', clientId: 'trusted-client' }],
      true,
    );
    const ctx = createPipelineContext({
      clientId: 'anonymous',
      serverName: 'test',
      method: 'tools/list',
      request: { jsonrpc: '2.0', id: '1', method: 'tools/list' },
    });
    const result = await mw.evaluate(ctx);
    expect(result?.verdict).toBe('block');
    expect(result?.reason).toContain('required');
  });

  it('should pass when valid API key is in metadata', async () => {
    const mw = new ApiKeyAuthMiddleware(
      [{ key: 'secret-key-123', clientId: 'trusted-client' }],
      true,
    );
    const ctx = createPipelineContext({
      clientId: 'default',
      serverName: 'test',
      method: 'tools/list',
      request: { jsonrpc: '2.0', id: '1', method: 'tools/list' },
    });
    ctx.metadata['apiKey'] = 'secret-key-123';
    const result = await mw.evaluate(ctx);
    expect(result).toBeNull();
    expect(ctx.client.clientId).toBe('trusted-client');
    expect(ctx.client.authType).toBe('api-key');
  });

  it('should block when invalid API key is provided', async () => {
    const mw = new ApiKeyAuthMiddleware(
      [{ key: 'secret-key-123', clientId: 'trusted-client' }],
      true,
    );
    const ctx = createPipelineContext({
      clientId: 'default',
      serverName: 'test',
      method: 'tools/list',
      request: { jsonrpc: '2.0', id: '1', method: 'tools/list' },
    });
    ctx.metadata['apiKey'] = 'wrong-key';
    const result = await mw.evaluate(ctx);
    expect(result?.verdict).toBe('block');
    expect(result?.reason).toContain('Invalid');
  });

  describe('extractFromHeader', () => {
    it('should extract Bearer token', () => {
      expect(ApiKeyAuthMiddleware.extractFromHeader('Bearer my-secret-key')).toBe(
        'my-secret-key',
      );
    });

    it('should extract direct key', () => {
      expect(ApiKeyAuthMiddleware.extractFromHeader('my-api-key-with-20plus-chars')).toBe(
        'my-api-key-with-20plus-chars',
      );
    });

    it('should return null for invalid header', () => {
      expect(ApiKeyAuthMiddleware.extractFromHeader('abc')).toBeNull();
    });
  });
});

import { describe, it, expect } from 'vitest';
import { JwtAuthMiddleware, JwksClient } from '../../security/jwt-auth';
import { createPipelineContext } from '../../pipeline/context';
import { createHmac } from 'node:crypto';

// ─── Helper: Create a valid JWT for testing ──────────────────

function createTestJwt(
  payload: Record<string, unknown>,
  secret = 'test-secret',
  algorithm = 'HS256',
): string {
  const header = {
    alg: algorithm,
    typ: 'JWT',
  };

  const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = createHmac('sha256', secret)
    .update(`${headerB64}.${payloadB64}`)
    .digest('base64url');

  return `${headerB64}.${payloadB64}.${signature}`;
}

describe('JwtAuthMiddleware', () => {
  const validOptions = {
    jwksUrl: 'https://example.com/.well-known/jwks.json',
    issuer: 'https://auth.example.com',
    audience: 'mcp-firewall',
  };

  it('should return null when disabled', async () => {
    const mw = new JwtAuthMiddleware(validOptions);
    mw.setEnabled(false);

    const ctx = createPipelineContext({
      clientId: 'test',
      serverName: 'srv',
      method: 'tools/list',
      request: { jsonrpc: '2.0', id: '1', method: 'tools/list' },
    });

    const result = await mw.evaluate(ctx);
    expect(result).toBeNull();
  });

  it('should block when no token is provided', async () => {
    const mw = new JwtAuthMiddleware(validOptions);

    const ctx = createPipelineContext({
      clientId: 'test',
      serverName: 'srv',
      method: 'tools/list',
      request: { jsonrpc: '2.0', id: '1', method: 'tools/list' },
    });

    const result = await mw.evaluate(ctx);
    expect(result?.verdict).toBe('block');
    expect(result?.reason).toContain('required');
  });

  it('should block a malformed JWT', async () => {
    const mw = new JwtAuthMiddleware(validOptions);

    const ctx = createPipelineContext({
      clientId: 'test',
      serverName: 'srv',
      method: 'tools/list',
      request: { jsonrpc: '2.0', id: '1', method: 'tools/list' },
    });
    ctx.metadata['jwtToken'] = 'not.a.jwt';

    const result = await mw.evaluate(ctx);
    expect(result?.verdict).toBe('block');
    expect(result?.reason).toContain('Malformed');
  });

  it('should block a token with "none" algorithm', async () => {
    const mw = new JwtAuthMiddleware(validOptions);

    // Create a JWT with alg: none (header + payload, no signature)
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(
      JSON.stringify({
        sub: 'user123',
        iss: 'https://auth.example.com',
        aud: 'mcp-firewall',
        exp: Math.floor(Date.now() / 1000) + 3600,
      }),
    ).toString('base64url');

    const ctx = createPipelineContext({
      clientId: 'test',
      serverName: 'srv',
      method: 'tools/list',
      request: { jsonrpc: '2.0', id: '1', method: 'tools/list' },
    });
    ctx.metadata['jwtToken'] = `${header}.${payload}.`;

    const result = await mw.evaluate(ctx);
    expect(result?.verdict).toBe('block');
    expect(result?.reason).toContain('algorithm');
  });

  it('should block a token with wrong issuer', async () => {
    const mw = new JwtAuthMiddleware(validOptions);

    const token = createTestJwt({
      sub: 'user123',
      iss: 'https://wrong-issuer.example.com',
      aud: 'mcp-firewall',
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
    });

    const ctx = createPipelineContext({
      clientId: 'test',
      serverName: 'srv',
      method: 'tools/list',
      request: { jsonrpc: '2.0', id: '1', method: 'tools/list' },
    });
    ctx.metadata['jwtToken'] = token;

    const result = await mw.evaluate(ctx);
    expect(result?.verdict).toBe('block');
    expect(result?.reason).toContain('issuer');
  });

  it('should block an expired token', async () => {
    const mw = new JwtAuthMiddleware(validOptions);

    const token = createTestJwt({
      sub: 'user123',
      iss: 'https://auth.example.com',
      aud: 'mcp-firewall',
      exp: Math.floor(Date.now() / 1000) - 3600, // expired 1 hour ago
      iat: Math.floor(Date.now() / 1000) - 7200,
    });

    const ctx = createPipelineContext({
      clientId: 'test',
      serverName: 'srv',
      method: 'tools/list',
      request: { jsonrpc: '2.0', id: '1', method: 'tools/list' },
    });
    ctx.metadata['jwtToken'] = token;

    const result = await mw.evaluate(ctx);
    expect(result?.verdict).toBe('block');
    expect(result?.reason).toContain('expired');
  });

  it('should extract token from Authorization header metadata', async () => {
    const mw = new JwtAuthMiddleware(validOptions);

    const token = createTestJwt({
      sub: 'user456',
      iss: 'https://auth.example.com',
      aud: 'mcp-firewall',
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
    });

    const ctx = createPipelineContext({
      clientId: 'test',
      serverName: 'srv',
      method: 'tools/list',
      request: { jsonrpc: '2.0', id: '1', method: 'tools/list' },
    });
    ctx.metadata['authorization'] = `Bearer ${token}`;

    // This will still fail at JWKS fetch (since we can't reach example.com in test),
    // but it proves token extraction + decode works.
    const result = await mw.evaluate(ctx);
    // Expect a "Failed to fetch JWKS" block (network error in test env)
    expect(result?.verdict).toBe('block');
    expect(result?.reason).toContain('JWKS');
  });
});

describe('JwksClient', () => {
  it('should initialize with a JWKS URL', () => {
    const client = new JwksClient('https://example.com/.well-known/jwks.json');
    expect(client).toBeDefined();
  });
});

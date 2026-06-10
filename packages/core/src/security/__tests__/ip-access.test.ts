import { describe, it, expect, beforeEach } from 'vitest';
import { IpAccessMiddleware } from '../../security/ip-access';
import { createPipelineContext } from '../../pipeline/context';

describe('IpAccessMiddleware', () => {
  const defaultOpts = (overrides: Partial<{
    enabled: boolean; allowlist: string[]; blocklist: string[];
    defaultDeny: boolean; geoBlock: string[];
  }> = {}) => ({
    enabled: true,
    allowlist: [],
    blocklist: [],
    defaultDeny: true,
    geoBlock: [],
    ...overrides,
  });

  const ctxWithIp = (ip: string, xff?: string) =>
    createPipelineContext({
      clientId: 'test',
      serverName: 'test',
      method: 'tools/call',
      request: { jsonrpc: '2.0', id: '1', method: 'tools/call' },
    });

  // ─── Blocklist tests ──────────────────────────────────────────

  it('should block IP in blocklist (single IP)', async () => {
    const mw = new IpAccessMiddleware(defaultOpts({ blocklist: ['192.168.1.100'] }));
    const ctx = ctxWithIp('192.168.1.100');
    ctx.metadata['clientIp'] = '192.168.1.100';
    const result = await mw.evaluate(ctx);
    expect(result?.verdict).toBe('block');
    expect(result?.reason).toContain('blocklist');
  });

  it('should block IP in blocklist (CIDR range)', async () => {
    const mw = new IpAccessMiddleware(defaultOpts({ blocklist: ['10.0.0.0/8'] }));
    const ctx = ctxWithIp('10.0.0.1');
    ctx.metadata['clientIp'] = '10.0.0.1';
    const result = await mw.evaluate(ctx);
    expect(result?.verdict).toBe('block');
  });

  it('should NOT block IP outside blocklist CIDR', async () => {
    const mw = new IpAccessMiddleware(defaultOpts({ blocklist: ['10.0.0.0/8'] }));
    const ctx = ctxWithIp('192.168.1.1');
    ctx.metadata['clientIp'] = '192.168.1.1';
    const result = await mw.evaluate(ctx);
    expect(result).toBeNull();
  });

  it('should block IP in blocklist /32 CIDR', async () => {
    const mw = new IpAccessMiddleware(defaultOpts({ blocklist: ['172.16.0.5/32'] }));
    const ctx = ctxWithIp('172.16.0.5');
    ctx.metadata['clientIp'] = '172.16.0.5';
    const result = await mw.evaluate(ctx);
    expect(result?.verdict).toBe('block');
  });

  // ─── Allowlist tests ──────────────────────────────────────────

  it('should block when not in allowlist (defaultDeny)', async () => {
    const mw = new IpAccessMiddleware(defaultOpts({ allowlist: ['192.168.0.0/16'] }));
    const ctx = ctxWithIp('10.0.0.1');
    ctx.metadata['clientIp'] = '10.0.0.1';
    const result = await mw.evaluate(ctx);
    expect(result?.verdict).toBe('block');
  });

  it('should pass when in allowlist', async () => {
    const mw = new IpAccessMiddleware(defaultOpts({ allowlist: ['192.168.0.0/16'] }));
    const ctx = ctxWithIp('192.168.1.100');
    ctx.metadata['clientIp'] = '192.168.1.100';
    const result = await mw.evaluate(ctx);
    expect(result).toBeNull();
  });

  it('should warn (not block) when not in allowlist and defaultDeny=false', async () => {
    const mw = new IpAccessMiddleware(defaultOpts({
      allowlist: ['10.0.0.0/8'],
      defaultDeny: false,
    }));
    const ctx = ctxWithIp('192.168.1.1');
    ctx.metadata['clientIp'] = '192.168.1.1';
    const result = await mw.evaluate(ctx);
    expect(result?.verdict).toBe('warn');
  });

  // ─── Precedence: blocklist > allowlist ────────────────────────

  it('should block even if IP is in allowlist when also in blocklist', async () => {
    const mw = new IpAccessMiddleware(defaultOpts({
      allowlist: ['10.0.0.0/8'],
      blocklist: ['10.0.0.99'],
    }));
    const ctx = ctxWithIp('10.0.0.99');
    ctx.metadata['clientIp'] = '10.0.0.99';
    const result = await mw.evaluate(ctx);
    expect(result?.verdict).toBe('block');
    expect(result?.reason).toContain('blocklist');
  });

  // ─── Disabled middleware ──────────────────────────────────────

  it('should pass when disabled', async () => {
    const mw = new IpAccessMiddleware(defaultOpts({
      enabled: false,
      blocklist: ['192.168.1.1'],
    }));
    const ctx = ctxWithIp('192.168.1.1');
    ctx.metadata['clientIp'] = '192.168.1.1';
    const result = await mw.evaluate(ctx);
    expect(result).toBeNull();
  });

  // ─── No IP available ─────────────────────────────────────────

  it('should pass when no client IP is available', async () => {
    const mw = new IpAccessMiddleware(defaultOpts({
      blocklist: ['0.0.0.0/0'],
    }));
    const ctx = ctxWithIp('unknown');
    // No clientIp set in metadata
    const result = await mw.evaluate(ctx);
    expect(result).toBeNull();
  });

  // ─── X-Forwarded-For extraction ──────────────────────────────

  it('should extract IP from X-Forwarded-For header', async () => {
    const mw = new IpAccessMiddleware(defaultOpts({ blocklist: ['1.2.3.4'] }));
    const ctx = ctxWithIp('unknown');
    ctx.metadata['xForwardedFor'] = '1.2.3.4, 10.0.0.1, 192.168.0.1';
    const result = await mw.evaluate(ctx);
    expect(result?.verdict).toBe('block');
  });

  it('should extract IP from X-Real-IP header', async () => {
    const mw = new IpAccessMiddleware(defaultOpts({ blocklist: ['5.6.7.8'] }));
    const ctx = ctxWithIp('unknown');
    ctx.metadata['xRealIp'] = '5.6.7.8';
    const result = await mw.evaluate(ctx);
    expect(result?.verdict).toBe('block');
  });

  // ─── Multiple CIDR entries ────────────────────────────────────

  it('should handle multiple blocklist entries', async () => {
    const mw = new IpAccessMiddleware(defaultOpts({
      blocklist: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'],
    }));
    const ctx = ctxWithIp('172.16.100.50');
    ctx.metadata['clientIp'] = '172.16.100.50';
    const result = await mw.evaluate(ctx);
    expect(result?.verdict).toBe('block');
  });

  it('should handle multiple allowlist entries', async () => {
    const mw = new IpAccessMiddleware(defaultOpts({
      allowlist: ['10.0.0.0/8', '192.168.0.0/16'],
    }));
    const ctx = ctxWithIp('10.10.10.10');
    ctx.metadata['clientIp'] = '10.10.10.10';
    const result = await mw.evaluate(ctx);
    expect(result).toBeNull();
  });

  // ─── Edge cases ──────────────────────────────────────────────

  it('should handle /0 CIDR (match everything)', async () => {
    const mw = new IpAccessMiddleware(defaultOpts({ blocklist: ['0.0.0.0/0'] }));
    const ctx = ctxWithIp('8.8.8.8');
    ctx.metadata['clientIp'] = '8.8.8.8';
    const result = await mw.evaluate(ctx);
    expect(result?.verdict).toBe('block');
  });

  it('should handle /24 CIDR correctly', async () => {
    const mw = new IpAccessMiddleware(defaultOpts({ blocklist: ['192.168.1.0/24'] }));
    // 192.168.1.255 is in the /24 range
    const ctx = ctxWithIp('192.168.1.255');
    ctx.metadata['clientIp'] = '192.168.1.255';
    const result = await mw.evaluate(ctx);
    expect(result?.verdict).toBe('block');
  });

  it('should NOT match IP outside /24 CIDR', async () => {
    const mw = new IpAccessMiddleware(defaultOpts({ blocklist: ['192.168.1.0/24'] }));
    const ctx = ctxWithIp('192.168.2.1');
    ctx.metadata['clientIp'] = '192.168.2.1';
    const result = await mw.evaluate(ctx);
    // Not in allowlist either, but allowlist is empty so there's no deny by default
    // Wait — if allowlist is [] and defaultDeny is true, should it block?
    // No, allowlist check only runs when allowlist.length > 0
    expect(result).toBeNull();
  });

  it('should handle geo block via metadata', async () => {
    const mw = new IpAccessMiddleware(defaultOpts({ geoBlock: ['CN', 'RU'] }));
    const ctx = ctxWithIp('1.1.1.1');
    ctx.metadata['clientIp'] = '1.1.1.1';
    ctx.metadata['geoCountry'] = 'CN';
    const result = await mw.evaluate(ctx);
    expect(result?.verdict).toBe('block');
    expect(result?.reason).toContain('country');
  });

  it('should NOT block non-geo-blocked countries', async () => {
    const mw = new IpAccessMiddleware(defaultOpts({ geoBlock: ['CN', 'RU'] }));
    const ctx = ctxWithIp('8.8.8.8');
    ctx.metadata['clientIp'] = '8.8.8.8';
    ctx.metadata['geoCountry'] = 'US';
    const result = await mw.evaluate(ctx);
    expect(result).toBeNull();
  });
});

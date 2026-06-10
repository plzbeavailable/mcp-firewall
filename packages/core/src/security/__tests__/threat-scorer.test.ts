import { describe, it, expect } from 'vitest';
import { ThreatScorerMiddleware, type ThreatScorerWeights } from '../../security/threat-scorer';
import { createPipelineContext } from '../../pipeline/context';

describe('ThreatScorerMiddleware', () => {
  const defaultWeights: ThreatScorerWeights = {
    injectionDetection: 0.3, rateLimiting: 0.15, contentFilter: 0.25,
    ipReputation: 0.1, replayDetection: 0.1, concurrency: 0.1,
  };

  const mk = (opts: Partial<{ enabled: boolean; blockThreshold: number; warnThreshold: number; weights: ThreatScorerWeights }> = {}) =>
    new ThreatScorerMiddleware({
      enabled: true, blockThreshold: 80, warnThreshold: 50, weights: defaultWeights, ...opts,
    });

  const ctx = (events: Array<{ middleware: string; category: string; severity: string; message: string }>) => {
    const c = createPipelineContext({
      clientId: 'test', serverName: 'test', method: 'tools/call',
      request: { jsonrpc: '2.0', id: '1', method: 'tools/call' },
    });
    c.securityEvents = events.map((e) => ({ timestamp: new Date().toISOString(), ...e }));
    return c;
  };

  it('passes with no security events', async () => {
    const r = await mk().evaluate(ctx([]));
    expect(r).toBeNull();
  });

  it('passes when score is below warn threshold', async () => {
    const r = await mk({ warnThreshold: 50 }).evaluate(ctx([
      { middleware: 'content-filter', category: 'content-filter', severity: 'warn', message: 'Low risk' },
    ]));
    expect(r).toBeNull();
  });

  it('warns when score crosses warn threshold', async () => {
    // 5 content-filter events: 100 (capped) * 0.25 = 25
    // 3 injection events: 45 * 0.3 = 13.5
    // Total ≈ 38.5 → cross warnThreshold=30
    const mw = mk({ warnThreshold: 30, blockThreshold: 90 });
    const c = ctx([
      { middleware: 'content-filter', category: 'content-filter', severity: 'warn', message: 'P1' },
      { middleware: 'content-filter', category: 'content-filter', severity: 'warn', message: 'P2' },
      { middleware: 'content-filter', category: 'content-filter', severity: 'warn', message: 'P3' },
      { middleware: 'content-filter', category: 'content-filter', severity: 'warn', message: 'P4' },
      { middleware: 'content-filter', category: 'content-filter', severity: 'warn', message: 'P5' },
      { middleware: 'parameter-validation', category: 'validation', severity: 'warn', message: 'SQL injection' },
      { middleware: 'parameter-validation', category: 'validation', severity: 'warn', message: 'Command injection' },
      { middleware: 'parameter-validation', category: 'validation', severity: 'warn', message: 'XSS detected' },
    ]);
    const r = await mw.evaluate(c);
    expect(r?.verdict).toBe('warn');
    expect(c.metadata['threatScore']).toBeGreaterThanOrEqual(30);
  });

  it('blocks when score crosses block threshold', async () => {
    // 8 content-filter crit = 100 (capped) * 0.25 = 25
    // 5 injection crit = 75 * 0.3 = 22.5
    // 3 rate-limit crit = 100 (capped) * 0.15 = 15
    // 2 ip-access crit = 50 * 0.1 = 5
    // Total ≈ 67.5 → crosses blockThreshold=60
    const mw = mk({ blockThreshold: 60, warnThreshold: 20 });
    const events = [
      ...Array(8).fill(0).map((_, i) => ({ middleware: 'content-filter', category: 'content-filter', severity: 'critical', message: `P${i}` })),
      ...Array(5).fill(0).map((_, i) => ({ middleware: 'parameter-validation', category: 'validation', severity: 'critical', message: `injection ${i}` })),
      ...Array(3).fill(0).map((_, i) => ({ middleware: 'rate-limiter', category: 'rate-limit', severity: 'critical', message: `rate ${i}` })),
      ...Array(2).fill(0).map((_, i) => ({ middleware: 'ip-access', category: 'ip-access', severity: 'critical', message: `ip ${i}` })),
    ];
    const r = await mw.evaluate(ctx(events));
    expect(r?.verdict).toBe('block');
    expect(r?.reason).toContain('block threshold');
  });

  it('stores threat score and breakdown in context metadata', async () => {
    const mw = mk({ warnThreshold: 5 });
    const c = ctx([
      { middleware: 'content-filter', category: 'content-filter', severity: 'warn', message: 'Pattern match' },
    ]);
    await mw.evaluate(c);
    expect(c.metadata['threatScore']).toBeDefined();
    expect(typeof c.metadata['threatScore']).toBe('number');
    expect(c.metadata['threatScoreBreakdown']).toBeDefined();
  });

  it('passes when disabled', async () => {
    const mw = mk({ enabled: false, blockThreshold: 1 });
    const c = ctx([
      { middleware: 'content-filter', category: 'content-filter', severity: 'critical', message: 'D!' },
      { middleware: 'content-filter', category: 'content-filter', severity: 'critical', message: 'D2!' },
      { middleware: 'content-filter', category: 'content-filter', severity: 'critical', message: 'D3!' },
    ]);
    expect(await mw.evaluate(c)).toBeNull();
  });

  it('caps individual layer scores at 100', async () => {
    const mw = mk({ warnThreshold: 30 });
    // 20 content-filter events — should cap at 100
    const events = Array.from({ length: 20 }, (_, i) => ({
      middleware: 'content-filter', category: 'content-filter' as const,
      severity: 'critical' as const, message: `P${i}`,
    }));
    const c = ctx(events);
    await mw.evaluate(c);
    const breakdown = c.metadata['threatScoreBreakdown'] as Record<string, number>;
    expect(breakdown.contentFilter).toBeLessThanOrEqual(100);
  });

  it('uses custom weights correctly', async () => {
    const customWeights: ThreatScorerWeights = {
      injectionDetection: 1.0, rateLimiting: 0, contentFilter: 0,
      ipReputation: 0, replayDetection: 0, concurrency: 0,
    };
    const mw = mk({ weights: customWeights, warnThreshold: 10 });
    const c = ctx([
      { middleware: 'parameter-validation', category: 'validation', severity: 'warn', message: 'injection' },
      { middleware: 'content-filter', category: 'content-filter', severity: 'critical', message: 'CF1' },
      { middleware: 'content-filter', category: 'content-filter', severity: 'critical', message: 'CF2' },
    ]);
    await mw.evaluate(c);
    // injection: 1 event * 15 = 15 * 1.0 = 15
    // content-filter has weight 0, so contributes 0
    expect(c.metadata['threatScore']).toBe(15);
  });

  it('works in response phase', async () => {
    const mw = mk({ warnThreshold: 5 });
    const c = createPipelineContext({
      clientId: 'test', serverName: 'test', method: 'tools/call',
      request: { jsonrpc: '2.0', id: '1', method: 'tools/call' },
    });
    c.response = { jsonrpc: '2.0', id: '1', result: { ok: true } };
    c.securityEvents = [
      { timestamp: new Date().toISOString(), middleware: 'sensitive-data', category: 'sensitive-data', severity: 'warn', message: 'Sensitive data masked' },
    ];
    await mw.evaluate(c);
    expect(c.metadata['threatScore']).toBeDefined();
  });
});

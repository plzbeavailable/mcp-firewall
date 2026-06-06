import { describe, it, expect } from 'vitest';
import { Pipeline } from '../../pipeline/pipeline';
import { createPipelineContext } from '../../pipeline/context';
import type { SecurityMiddleware, PipelineContext, SecurityDecision } from '../../pipeline/types';

// ─── Test middleware ───────────────────────────────────────────

function makeMiddleware(
  name: string,
  priority: number,
  decision: SecurityDecision | null,
): SecurityMiddleware {
  return {
    name,
    priority,
    phase: 'request',
    evaluate: async (_ctx: PipelineContext) => decision,
  };
}

function makeRequestContext(overrides?: Partial<Parameters<typeof createPipelineContext>[0]>): PipelineContext {
  return createPipelineContext({
    clientId: 'test-client',
    serverName: 'test-server',
    method: 'tools/call',
    toolName: 'test_tool',
    request: { jsonrpc: '2.0', id: '1', method: 'tools/call', params: { name: 'test_tool' } },
    ...overrides,
  });
}

// ─── Tests ────────────────────────────────────────────────────

describe('Pipeline', () => {
  it('should allow requests when no middleware is registered', async () => {
    const pipeline = new Pipeline();
    const ctx = makeRequestContext();
    const result = await pipeline.evaluateRequest(ctx);
    expect(result.verdict).toBe('allow');
    expect(result.warnings).toHaveLength(0);
  });

  it('should pass through when middleware returns null', async () => {
    const pipeline = new Pipeline();
    pipeline.register(makeMiddleware('pass', 10, null));
    const result = await pipeline.evaluateRequest(makeRequestContext());
    expect(result.verdict).toBe('allow');
  });

  it('should allow when middleware returns allow verdict', async () => {
    const pipeline = new Pipeline();
    pipeline.register(
      makeMiddleware('allow-all', 10, { verdict: 'allow', reason: 'ok' }),
    );
    const result = await pipeline.evaluateRequest(makeRequestContext());
    expect(result.verdict).toBe('allow');
  });

  it('should block when middleware returns block verdict', async () => {
    const pipeline = new Pipeline();
    pipeline.register(
      makeMiddleware('block-all', 10, {
        verdict: 'block',
        reason: 'access denied',
        errorCode: -32001,
      }),
    );
    const result = await pipeline.evaluateRequest(makeRequestContext());
    expect(result.verdict).toBe('block');
    expect(result.blockDecision?.reason).toBe('access denied');
    expect(result.blockDecision?.errorCode).toBe(-32001);
  });

  it('should collect warnings', async () => {
    const pipeline = new Pipeline();
    pipeline.register(
      makeMiddleware('warn-1', 10, { verdict: 'warn', reason: 'warning 1' }),
    );
    pipeline.register(
      makeMiddleware('warn-2', 20, { verdict: 'warn', reason: 'warning 2' }),
    );
    const result = await pipeline.evaluateRequest(makeRequestContext());
    expect(result.verdict).toBe('allow');
    expect(result.warnings).toHaveLength(2);
    expect(result.warnings[0]!.reason).toBe('warning 1');
    expect(result.warnings[1]!.reason).toBe('warning 2');
  });

  it('should short-circuit on first block', async () => {
    const pipeline = new Pipeline();
    pipeline.register(
      makeMiddleware('block-early', 10, {
        verdict: 'block',
        reason: 'blocked early',
      }),
    );
    pipeline.register(
      makeMiddleware('warn-late', 20, { verdict: 'warn', reason: 'never runs' }),
    );
    const result = await pipeline.evaluateRequest(makeRequestContext());
    expect(result.verdict).toBe('block');
    expect(result.warnings).toHaveLength(0);
  });

  it('should run middlewares in priority order', async () => {
    const pipeline = new Pipeline();
    const order: string[] = [];

    pipeline.register({
      name: 'third',
      priority: 30,
      phase: 'request',
      evaluate: async () => {
        order.push('third');
        return null;
      },
    });

    pipeline.register({
      name: 'first',
      priority: 10,
      phase: 'request',
      evaluate: async () => {
        order.push('first');
        return null;
      },
    });

    pipeline.register({
      name: 'second',
      priority: 20,
      phase: 'request',
      evaluate: async () => {
        order.push('second');
        return null;
      },
    });

    await pipeline.evaluateRequest(makeRequestContext());
    expect(order).toEqual(['first', 'second', 'third']);
  });

  it('should only run request-phase middleware for evaluateRequest', async () => {
    const pipeline = new Pipeline();
    let requestRan = false;
    let responseRan = false;

    pipeline.register({
      name: 'req-only',
      priority: 10,
      phase: 'request',
      evaluate: async () => {
        requestRan = true;
        return null;
      },
    });

    pipeline.register({
      name: 'resp-only',
      priority: 20,
      phase: 'response',
      evaluate: async () => {
        responseRan = true;
        return null;
      },
    });

    await pipeline.evaluateRequest(makeRequestContext());
    expect(requestRan).toBe(true);
    expect(responseRan).toBe(false);
  });

  it('should record security events on block', async () => {
    const pipeline = new Pipeline();
    pipeline.register(
      makeMiddleware('blocker', 10, {
        verdict: 'block',
        reason: 'security violation',
        metadata: { detail: 'injection attempt' },
      }),
    );

    const ctx = makeRequestContext();
    const result = await pipeline.evaluateRequest(ctx);

    expect(result.verdict).toBe('block');
    expect(ctx.securityEvents).toHaveLength(1);
    expect(ctx.securityEvents[0]!.middleware).toBe('blocker');
    expect(ctx.securityEvents[0]!.severity).toBe('critical');
    expect(ctx.securityEvents[0]!.message).toBe('security violation');
  });
});

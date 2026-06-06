import { describe, it, expect } from 'vitest';
import { MethodAllowlistMiddleware } from '../method-allowlist';
import { createPipelineContext } from '../../pipeline/context';

function makeCtx(method: string) {
  return createPipelineContext({
    clientId: 'test',
    serverName: 'test',
    method,
    request: { jsonrpc: '2.0', id: '1', method },
  });
}

describe('MethodAllowlistMiddleware', () => {
  it('should allow methods in the allowlist', async () => {
    const mw = new MethodAllowlistMiddleware(['tools/call', 'tools/list']);
    const result = await mw.evaluate(makeCtx('tools/call'));
    expect(result).toBeNull();
  });

  it('should block unknown methods when blockUnknown is true', async () => {
    const mw = new MethodAllowlistMiddleware(['tools/list'], true);
    const result = await mw.evaluate(makeCtx('tools/call'));
    expect(result?.verdict).toBe('block');
  });

  it('should warn on unknown methods when blockUnknown is false', async () => {
    const mw = new MethodAllowlistMiddleware(['tools/list'], false);
    const result = await mw.evaluate(makeCtx('tools/call'));
    expect(result?.verdict).toBe('warn');
  });
});

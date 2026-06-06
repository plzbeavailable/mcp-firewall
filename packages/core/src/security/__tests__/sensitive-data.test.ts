import { describe, it, expect } from 'vitest';
import { SensitiveDataMiddleware, type SensitiveDataRule } from '../../security/sensitive-data';
import { createPipelineContext, cloneContextForResponse } from '../../pipeline/context';

function makeCtxWithResponse(responseText: string) {
  const ctx = createPipelineContext({
    clientId: 'test',
    serverName: 'test',
    method: 'tools/call',
    toolName: 'get_data',
    request: { jsonrpc: '2.0', id: '1', method: 'tools/call', params: { name: 'get_data' } },
  });
  return cloneContextForResponse(ctx, {
    jsonrpc: '2.0',
    id: '1',
    result: { content: [{ type: 'text', text: responseText }] },
  });
}

describe('SensitiveDataMiddleware', () => {
  it('should pass when no sensitive data is present', async () => {
    const mw = new SensitiveDataMiddleware([
      { type: 'credit-card', action: 'block' },
    ]);
    const ctx = makeCtxWithResponse('Hello, world! No sensitive data here.');
    const result = await mw.evaluate(ctx);
    expect(result).toBeNull();
  });

  it('should detect credit card numbers', async () => {
    const mw = new SensitiveDataMiddleware([
      { type: 'credit-card', action: 'block' },
    ]);
    const ctx = makeCtxWithResponse('My card is 4111-1111-1111-1111');
    const result = await mw.evaluate(ctx);
    expect(result?.verdict).toBe('block');
    expect(result?.reason).toContain('credit-card');
  });

  it('should detect API keys', async () => {
    const mw = new SensitiveDataMiddleware([
      { type: 'api-key', action: 'block' },
    ]);
    const ctx = makeCtxWithResponse('API key: sk-abcdefghijklmnopqrstuvwxyz123456');
    const result = await mw.evaluate(ctx);
    expect(result?.verdict).toBe('block');
  });

  it('should detect JWT tokens', async () => {
    const mw = new SensitiveDataMiddleware([
      { type: 'jwt', action: 'block' },
    ]);
    const ctx = makeCtxWithResponse(
      'Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U',
    );
    const result = await mw.evaluate(ctx);
    expect(result?.verdict).toBe('block');
  });

  it('should mask sensitive data when action is mask', async () => {
    const mw = new SensitiveDataMiddleware([
      { type: 'credit-card', action: 'mask' },
    ]);
    const ctx = makeCtxWithResponse('Card: 4111-1111-1111-1111');
    const result = await mw.evaluate(ctx);
    expect(result?.verdict).toBe('warn');
    expect(result?.metadata?.action).toBe('mask');
    expect(result?.metadata?.maskedResponse).toContain('***REDACTED***');
  });

  it('should log (warn) when action is log', async () => {
    const mw = new SensitiveDataMiddleware([
      { type: 'email', action: 'log' },
    ]);
    const ctx = makeCtxWithResponse('Contact: user@example.com');
    const result = await mw.evaluate(ctx);
    expect(result?.verdict).toBe('warn');
    expect(result?.metadata?.action).toBe('log');
  });

  it('should mask response with maskResponse method', () => {
    const mw = new SensitiveDataMiddleware([
      { type: 'credit-card', action: 'mask' },
      { type: 'credit-card', action: 'mask' },
    ]);
    const result = mw.maskResponse('Cards: 4111-1111-1111-1111 and 5555-5555-5555-4444');
    // Both card numbers should be masked (count the redacted entries)
    const matches = result.match(/\*\*\*REDACTED\*\*\*/g);
    expect(matches?.length).toBe(2);
    expect(result).toContain('***REDACTED***');
  });

  it('should support custom patterns', async () => {
    const mw = new SensitiveDataMiddleware([
      { type: 'custom', name: 'internal-secret', pattern: 'SECRET_[A-Z]{8}', action: 'block' },
    ]);
    const ctx = makeCtxWithResponse('The secret is SECRET_ABCDEFGH');
    const result = await mw.evaluate(ctx);
    expect(result?.verdict).toBe('block');
  });
});

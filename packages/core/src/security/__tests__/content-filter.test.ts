import { describe, it, expect } from 'vitest';
import { ContentFilterMiddleware, type ContentFilterRuleDef } from '../../security/content-filter';
import { createPipelineContext, cloneContextForResponse } from '../../pipeline/context';

describe('ContentFilterMiddleware', () => {
  it('should pass when no rules match', async () => {
    const mw = new ContentFilterMiddleware([
      { pattern: 'rm -rf', action: 'block', phase: 'input' },
    ]);
    const ctx = createPipelineContext({
      clientId: 'test',
      serverName: 'test',
      method: 'tools/call',
      toolName: 'safe_tool',
      request: {
        jsonrpc: '2.0',
        id: '1',
        method: 'tools/call',
        params: { name: 'safe_tool', arguments: { path: '/tmp/foo.txt' } },
      },
    });
    const result = await mw.evaluate(ctx);
    expect(result).toBeNull();
  });

  it('should block input with dangerous pattern', async () => {
    const mw = new ContentFilterMiddleware([
      { pattern: 'rm -rf', action: 'block', phase: 'input' },
    ]);
    const ctx = createPipelineContext({
      clientId: 'test',
      serverName: 'test',
      method: 'tools/call',
      toolName: 'shell_exec',
      request: {
        jsonrpc: '2.0',
        id: '1',
        method: 'tools/call',
        params: { name: 'shell_exec', arguments: { command: 'sudo rm -rf /' } },
      },
    });
    const result = await mw.evaluate(ctx);
    expect(result?.verdict).toBe('block');
  });

  it('should block output with dangerous pattern', async () => {
    const mw = new ContentFilterMiddleware([
      { pattern: 'password', action: 'block', phase: 'output' },
    ]);
    const ctx = createPipelineContext({
      clientId: 'test',
      serverName: 'test',
      method: 'tools/call',
      toolName: 'read_secrets',
      request: {
        jsonrpc: '2.0',
        id: '1',
        method: 'tools/call',
        params: { name: 'read_secrets' },
      },
    });
    const ctxResp = cloneContextForResponse(ctx, {
      jsonrpc: '2.0',
      id: '1',
      result: { content: [{ text: 'password: hunter2' }] },
    });
    const result = await mw.evaluate(ctxResp);
    expect(result?.verdict).toBe('block');
  });

  it('should warn (log) when action is log', async () => {
    const mw = new ContentFilterMiddleware([
      { pattern: 'secret', action: 'log', phase: 'both' },
    ]);
    const ctx = createPipelineContext({
      clientId: 'test',
      serverName: 'test',
      method: 'tools/call',
      request: {
        jsonrpc: '2.0',
        id: '1',
        method: 'tools/call',
        params: { arguments: { text: 'the secret is 42' } },
      },
    });
    const result = await mw.evaluate(ctx);
    expect(result?.verdict).toBe('warn');
    expect(result?.metadata?.action).toBe('log');
  });

  it('should skip output-phase rules for request evaluation', async () => {
    const mw = new ContentFilterMiddleware([
      { pattern: 'error', action: 'block', phase: 'output' },
    ]);
    const ctx = createPipelineContext({
      clientId: 'test',
      serverName: 'test',
      method: 'tools/call',
      request: {
        jsonrpc: '2.0',
        id: '1',
        method: 'tools/call',
        params: { arguments: { text: 'this contains error info' } },
      },
    });
    // This is a request (no response attached), so output-phase rules should be skipped
    const result = await mw.evaluate(ctx);
    expect(result).toBeNull();
  });
});

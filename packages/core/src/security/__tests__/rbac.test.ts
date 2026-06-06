import { describe, it, expect } from 'vitest';
import { RbacMiddleware } from '../rbac';
import { createPipelineContext } from '../../pipeline/context';

describe('RbacMiddleware', () => {
  it('should pass when no rules are configured', async () => {
    const mw = new RbacMiddleware([]);
    const ctx = createPipelineContext({
      clientId: 'admin',
      serverName: 'filesystem',
      method: 'tools/call',
      toolName: 'write_file',
      request: { jsonrpc: '2.0', id: '1', method: 'tools/call', params: { name: 'write_file' } },
    });
    const result = await mw.evaluate(ctx);
    expect(result).toBeNull();
  });

  it('should allow matching client and tool with allow rule', async () => {
    const mw = new RbacMiddleware([
      {
        name: 'allow-admin',
        principals: [{ type: 'client-id', pattern: 'admin*' }],
        targets: [{ toolName: 'write_*' }],
        permission: 'allow',
      },
    ]);
    const ctx = createPipelineContext({
      clientId: 'admin',
      serverName: 'filesystem',
      method: 'tools/call',
      toolName: 'write_file',
      request: { jsonrpc: '2.0', id: '1', method: 'tools/call', params: { name: 'write_file' } },
    });
    const result = await mw.evaluate(ctx);
    expect(result).toBeNull();
  });

  it('should deny when a deny rule matches', async () => {
    const mw = new RbacMiddleware([
      {
        name: 'deny-write',
        principals: [{ type: 'client-id', pattern: 'guest*' }],
        targets: [{ toolName: 'write_*' }],
        permission: 'deny',
      },
    ]);
    const ctx = createPipelineContext({
      clientId: 'guest',
      serverName: 'filesystem',
      method: 'tools/call',
      toolName: 'write_file',
      request: { jsonrpc: '2.0', id: '1', method: 'tools/call', params: { name: 'write_file' } },
    });
    const result = await mw.evaluate(ctx);
    expect(result?.verdict).toBe('block');
    expect(result?.reason).toContain('deny-write');
  });

  it('should not match when client pattern does not match (default-deny)', async () => {
    const mw = new RbacMiddleware([
      {
        name: 'allow-admin',
        principals: [{ type: 'client-id', pattern: 'admin' }],
        targets: [{ toolName: '*' }],
        permission: 'allow',
      },
    ], false); // defaultAllow = false
    const ctx = createPipelineContext({
      clientId: 'guest',
      serverName: 'filesystem',
      method: 'tools/call',
      toolName: 'read_file',
      request: { jsonrpc: '2.0', id: '1', method: 'tools/call', params: { name: 'read_file' } },
    });
    const result = await mw.evaluate(ctx);
    // Default-deny means no match = block
    expect(result?.verdict).toBe('block');
  });

  it('should match server name in targets', async () => {
    const mw = new RbacMiddleware([
      {
        name: 'allow-filesystem',
        principals: [{ type: 'client-id', pattern: '*' }],
        targets: [{ serverName: 'filesystem' }],
        permission: 'allow',
      },
    ]);
    const ctx = createPipelineContext({
      clientId: 'admin',
      serverName: 'filesystem',
      method: 'tools/list',
      request: { jsonrpc: '2.0', id: '1', method: 'tools/list' },
    });
    const result = await mw.evaluate(ctx);
    expect(result).toBeNull();
  });

  it('should not match different server name (default-deny)', async () => {
    const mw = new RbacMiddleware([
      {
        name: 'allow-filesystem',
        principals: [{ type: 'client-id', pattern: '*' }],
        targets: [{ serverName: 'filesystem' }],
        permission: 'allow',
      },
    ], false); // defaultAllow = false
    const ctx = createPipelineContext({
      clientId: 'admin',
      serverName: 'database',
      method: 'tools/list',
      request: { jsonrpc: '2.0', id: '1', method: 'tools/list' },
    });
    const result = await mw.evaluate(ctx);
    expect(result?.verdict).toBe('block');
  });
});

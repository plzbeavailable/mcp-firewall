import { describe, it, expect } from 'vitest';
import { ParameterValidationMiddleware, ToolSchemaCache } from '../../security/parameter-validator';
import { createPipelineContext } from '../../pipeline/context';

describe('ParameterValidationMiddleware', () => {
  const defaultOpts = { enabled: true, maxStringLength: 1000 };

  it('should pass for non-tool-call methods', async () => {
    const mw = new ParameterValidationMiddleware(defaultOpts);
    const ctx = createPipelineContext({
      clientId: 'test',
      serverName: 'test',
      method: 'tools/list',
      request: { jsonrpc: '2.0', id: '1', method: 'tools/list' },
    });
    const result = await mw.evaluate(ctx);
    expect(result).toBeNull();
  });

  it('should block tools/call with no params', async () => {
    const mw = new ParameterValidationMiddleware(defaultOpts);
    const ctx = createPipelineContext({
      clientId: 'test',
      serverName: 'test',
      method: 'tools/call',
      request: { jsonrpc: '2.0', id: '1', method: 'tools/call' },
    });
    const result = await mw.evaluate(ctx);
    expect(result?.verdict).toBe('block');
  });

  it('should pass for valid params', async () => {
    const mw = new ParameterValidationMiddleware(defaultOpts);
    const ctx = createPipelineContext({
      clientId: 'test',
      serverName: 'test',
      method: 'tools/call',
      request: {
        jsonrpc: '2.0',
        id: '1',
        method: 'tools/call',
        params: { name: 'read', arguments: { path: '/tmp/foo.txt' } },
      },
    });
    const result = await mw.evaluate(ctx);
    expect(result).toBeNull();
  });

  it('should block path traversal', async () => {
    const mw = new ParameterValidationMiddleware(defaultOpts);
    const ctx = createPipelineContext({
      clientId: 'test',
      serverName: 'test',
      method: 'tools/call',
      request: {
        jsonrpc: '2.0',
        id: '1',
        method: 'tools/call',
        params: { name: 'read', arguments: { path: '../../../etc/passwd' } },
      },
    });
    const result = await mw.evaluate(ctx);
    expect(result?.verdict).toBe('block');
    expect(result?.reason).toContain('traversal');
  });

  it('should block null byte injection', async () => {
    const mw = new ParameterValidationMiddleware(defaultOpts);
    // Build params with an actual null byte character
    const maliciousText = 'foo' + String.fromCharCode(0) + '.txt';
    const ctx = createPipelineContext({
      clientId: 'test',
      serverName: 'test',
      method: 'tools/call',
      request: {
        jsonrpc: '2.0',
        id: '1',
        method: 'tools/call',
        params: { name: 'read', arguments: { path: maliciousText } },
      },
    });
    const result = await mw.evaluate(ctx);
    expect(result?.verdict).toBe('block');
  });

  it('should block long strings', async () => {
    const mw = new ParameterValidationMiddleware({ enabled: true, maxStringLength: 10 });
    const ctx = createPipelineContext({
      clientId: 'test',
      serverName: 'test',
      method: 'tools/call',
      request: {
        jsonrpc: '2.0',
        id: '1',
        method: 'tools/call',
        params: { name: 'write', arguments: { content: 'a'.repeat(100) } },
      },
    });
    const result = await mw.evaluate(ctx);
    expect(result?.verdict).toBe('block');
  });

  it('should block SQL injection patterns', async () => {
    const mw = new ParameterValidationMiddleware(defaultOpts);
    const ctx = createPipelineContext({
      clientId: 'test',
      serverName: 'test',
      method: 'tools/call',
      request: {
        jsonrpc: '2.0',
        id: '1',
        method: 'tools/call',
        params: { name: 'query', arguments: { sql: "SELECT * FROM users WHERE id = '1'; --" } },
      },
    });
    const result = await mw.evaluate(ctx);
    expect(result?.verdict).toBe('block');
    expect(result?.reason).toContain('SQL injection');
  });

  it('should pass when disabled', async () => {
    const mw = new ParameterValidationMiddleware({ enabled: false });
    const ctx = createPipelineContext({
      clientId: 'test',
      serverName: 'test',
      method: 'tools/call',
      request: {
        jsonrpc: '2.0',
        id: '1',
        method: 'tools/call',
        params: { name: 'read', arguments: { path: '../../../secret' } },
      },
    });
    const result = await mw.evaluate(ctx);
    expect(result).toBeNull();
  });
});

describe('ToolSchemaCache', () => {
  it('should register and retrieve a schema', () => {
    const cache = new ToolSchemaCache();
    cache.registerTool('filesystem', 'read_file', {
      type: 'object',
      properties: {
        path: { type: 'string' },
      },
      required: ['path'],
    });
    expect(cache.hasSchema('filesystem', 'read_file')).toBe(true);
    expect(cache.size).toBe(1);
  });

  it('should compile a validator for subsequent use', () => {
    const cache = new ToolSchemaCache();
    cache.registerTool('filesystem', 'read_file', {
      type: 'object',
      properties: { path: { type: 'string' } },
      required: ['path'],
    });

    const validator = cache.getValidator('filesystem', 'read_file');
    expect(validator).not.toBeNull();
    expect(validator!({ path: '/tmp/test.txt' })).toBe(true);
    expect(validator!({ wrongKey: 42 })).toBe(false);
  });

  it('should return null for unregistered tools', () => {
    const cache = new ToolSchemaCache();
    expect(cache.getValidator('unknown', 'tool')).toBeNull();
  });

  it('should bulk-register tools from tools/list response', () => {
    const cache = new ToolSchemaCache();
    cache.registerTools('filesystem', [
      { name: 'read_file', inputSchema: { type: 'object', properties: { path: { type: 'string' } } } },
      { name: 'write_file', inputSchema: { type: 'object', properties: { path: { type: 'string' }, content: { type: 'string' } } } },
    ]);
    expect(cache.size).toBe(2);
    expect(cache.hasSchema('filesystem', 'read_file')).toBe(true);
    expect(cache.hasSchema('filesystem', 'write_file')).toBe(true);
  });

  it('should clear all schemas', () => {
    const cache = new ToolSchemaCache();
    cache.registerTool('srv', 'tool', { type: 'object' });
    cache.clear();
    expect(cache.size).toBe(0);
  });
});

describe('AJV-enhanced ParameterValidationMiddleware', () => {
  it('should validate with AJV when schema is registered', async () => {
    const cache = new ToolSchemaCache();
    cache.registerTool('filesystem', 'read_file', {
      type: 'object',
      properties: {
        path: { type: 'string', minLength: 1 },
      },
      required: ['path'],
    });

    const mw = new ParameterValidationMiddleware({
      enabled: true,
      schemaCache: cache,
    });

    const ctx = createPipelineContext({
      clientId: 'test',
      serverName: 'filesystem',
      method: 'tools/call',
      toolName: 'read_file',
      request: {
        jsonrpc: '2.0',
        id: '1',
        method: 'tools/call',
        params: { name: 'read_file', arguments: { path: '/tmp/test.txt' } },
      },
    });

    const result = await mw.evaluate(ctx);
    expect(result).toBeNull();
  });

  it('should block when AJV validation fails', async () => {
    const cache = new ToolSchemaCache();
    cache.registerTool('filesystem', 'read_file', {
      type: 'object',
      properties: {
        path: { type: 'string', minLength: 1 },
      },
      required: ['path'],
    });

    const mw = new ParameterValidationMiddleware({
      enabled: true,
      schemaCache: cache,
    });

    const ctx = createPipelineContext({
      clientId: 'test',
      serverName: 'filesystem',
      method: 'tools/call',
      toolName: 'read_file',
      request: {
        jsonrpc: '2.0',
        id: '1',
        method: 'tools/call',
        params: { name: 'read_file', arguments: { not_path: 123 } },
      },
    });

    const result = await mw.evaluate(ctx);
    expect(result?.verdict).toBe('block');
    expect(result?.reason).toContain('validation failed');
  });
});

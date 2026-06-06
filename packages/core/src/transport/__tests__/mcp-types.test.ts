import { describe, it, expect } from 'vitest';
import { parseMessage, serializeMessage, isRequest, isResponse, createErrorResponse } from '../mcp-types';

describe('MCP Types', () => {
  describe('parseMessage', () => {
    it('should parse a valid JSON-RPC request', () => {
      const msg = parseMessage('{"jsonrpc":"2.0","id":"1","method":"tools/call"}');
      expect(msg).not.toBeNull();
      expect(isRequest(msg!)).toBe(true);
    });

    it('should return null for malformed input', () => {
      expect(parseMessage('not json')).toBeNull();
    });

    it('should return null for non-JSON-RPC JSON', () => {
      expect(parseMessage('{"foo":"bar"}')).toBeNull();
    });
  });

  describe('serializeMessage', () => {
    it('should serialize a message with newline', () => {
      const result = serializeMessage({ jsonrpc: '2.0', id: '1', method: 'ping' });
      expect(result).toContain('\n');
      const parsed = JSON.parse(result.trim());
      expect(parsed.method).toBe('ping');
    });
  });

  describe('isRequest', () => {
    it('should identify a request', () => {
      expect(isRequest({ jsonrpc: '2.0', id: '1', method: 'tools/call' })).toBe(true);
    });

    it('should not identify a response as a request', () => {
      expect(
        isResponse({ jsonrpc: '2.0', id: '1', result: { ok: true } }),
      ).toBe(true);
    });
  });

  describe('createErrorResponse', () => {
    it('should create a valid error response', () => {
      const resp = createErrorResponse('1', -32600, 'Invalid Request', { detail: 'missing id' });
      expect(resp.jsonrpc).toBe('2.0');
      expect(resp.error.code).toBe(-32600);
      expect(resp.error.message).toBe('Invalid Request');
      expect(resp.error.data).toEqual({ detail: 'missing id' });
    });
  });
});

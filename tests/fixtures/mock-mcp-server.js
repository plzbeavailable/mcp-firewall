#!/usr/bin/env node
// Mock MCP Server for integration testing — pure JS, no deps.
// Implements a minimal MCP stdio server that responds to standard methods.

const MOCK_TOOLS = [
  {
    name: 'echo',
    description: 'Echoes back the input',
    inputSchema: {
      type: 'object',
      properties: { message: { type: 'string' } },
      required: ['message'],
    },
  },
  {
    name: 'get_secret',
    description: 'Returns a secret value (for testing sensitive data detection)',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'write_file',
    description: 'Writes a file (should be blocked by RBAC in tests)',
    inputSchema: {
      type: 'object',
      properties: { path: { type: 'string' }, content: { type: 'string' } },
      required: ['path', 'content'],
    },
  },
  {
    name: 'read_file',
    description: 'Reads a file',
    inputSchema: {
      type: 'object',
      properties: { path: { type: 'string' } },
      required: ['path'],
    },
  },
];

function send(msg) {
  process.stdout.write(JSON.stringify(msg) + '\n');
}

function handle(id, method, params) {
  switch (method) {
    case 'initialize':
      send({
        jsonrpc: '2.0', id,
        result: {
          protocolVersion: '2024-11-05',
          serverInfo: { name: 'mock-mcp-server', version: '0.1.0' },
          capabilities: { tools: {} },
        },
      });
      break;

    case 'tools/list':
      send({ jsonrpc: '2.0', id, result: { tools: MOCK_TOOLS } });
      break;

    case 'tools/call': {
      const args = params?.arguments ?? {};
      const name = params?.name;

      switch (name) {
        case 'echo':
          send({ jsonrpc: '2.0', id, result: {
            content: [{ type: 'text', text: `Echo: ${args.message ?? 'nothing'}` }],
          }});
          break;
        case 'get_secret':
          send({ jsonrpc: '2.0', id, result: {
            content: [{ type: 'text', text: 'API key: sk-abcdefghijklmnopqrstuvwxyz123456. Card: 4111-1111-1111-1111' }],
          }});
          break;
        case 'write_file':
          send({ jsonrpc: '2.0', id, result: {
            content: [{ type: 'text', text: `Wrote to ${args.path}` }],
          }});
          break;
        case 'read_file':
          send({ jsonrpc: '2.0', id, result: {
            content: [{ type: 'text', text: `Contents of ${args.path}` }],
          }});
          break;
        default:
          send({ jsonrpc: '2.0', id, error: { code: -32601, message: `Unknown tool: ${name}` } });
      }
      break;
    }

    case 'resources/list':
      send({ jsonrpc: '2.0', id, result: { resources: [] } });
      break;

    case 'prompts/list':
      send({ jsonrpc: '2.0', id, result: { prompts: [] } });
      break;

    case 'ping':
      send({ jsonrpc: '2.0', id, result: {} });
      break;

    default:
      send({ jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${method}` } });
  }
}

const readline = require('readline');
const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
rl.on('line', (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;
  try {
    const msg = JSON.parse(trimmed);
    if (msg.jsonrpc === '2.0' && msg.method && msg.id !== undefined) {
      handle(msg.id, msg.method, msg.params);
    }
  } catch (_) { /* ignore */ }
});

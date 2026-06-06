// Mock MCP Server for integration testing
// Implements a minimal MCP stdio server that responds to standard methods.
// Used by integration tests to verify mcp-firewall proxy behavior.

const MOCK_TOOLS = [
  {
    name: 'echo',
    description: 'Echoes back the input',
    inputSchema: {
      type: 'object',
      properties: {
        message: { type: 'string', description: 'The message to echo' },
      },
      required: ['message'],
    },
  },
  {
    name: 'get_secret',
    description: 'Returns a secret value (for testing sensitive data detection)',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
  {
    name: 'write_file',
    description: 'Writes a file (should be blocked by RBAC in tests)',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string' },
        content: { type: 'string' },
      },
      required: ['path', 'content'],
    },
  },
  {
    name: 'long_running',
    description: 'Simulates a slow operation',
    inputSchema: {
      type: 'object',
      properties: {
        delay_ms: { type: 'number' },
      },
    },
  },
];

function sendMessage(msg: unknown): void {
  process.stdout.write(JSON.stringify(msg) + '\n');
}

function handleRequest(request: { id: string | number; method: string; params?: Record<string, unknown> }): void {
  const { id, method, params } = request;

  switch (method) {
    case 'initialize':
      sendMessage({
        jsonrpc: '2.0',
        id,
        result: {
          protocolVersion: '2024-11-05',
          serverInfo: { name: 'mock-mcp-server', version: '0.1.0' },
          capabilities: { tools: {} },
        },
      });
      break;

    case 'tools/list':
      sendMessage({
        jsonrpc: '2.0',
        id,
        result: { tools: MOCK_TOOLS },
      });
      break;

    case 'tools/call': {
      const toolName = params?.name as string;
      const args = (params?.arguments as Record<string, unknown>) ?? {};

      switch (toolName) {
        case 'echo':
          sendMessage({
            jsonrpc: '2.0',
            id,
            result: {
              content: [{ type: 'text', text: `Echo: ${args.message ?? 'nothing'}` }],
            },
          });
          break;

        case 'get_secret':
          // Returns sensitive data to test firewall detection
          sendMessage({
            jsonrpc: '2.0',
            id,
            result: {
              content: [
                {
                  type: 'text',
                  text: 'API key: sk-abcdefghijklmnopqrstuvwxyz123456. Card: 4111-1111-1111-1111',
                },
              ],
            },
          });
          break;

        case 'write_file':
          sendMessage({
            jsonrpc: '2.0',
            id,
            result: {
              content: [
                { type: 'text', text: `Wrote ${args.content?.toString().length ?? 0} bytes to ${args.path}` },
              ],
            },
          });
          break;

        case 'long_running': {
          const delay = (args.delay_ms as number) ?? 100;
          setTimeout(() => {
            sendMessage({
              jsonrpc: '2.0',
              id,
              result: {
                content: [{ type: 'text', text: `Completed after ${delay}ms` }],
              },
            });
          }, delay);
          return; // Async response — don't send immediately
        }

        default:
          sendMessage({
            jsonrpc: '2.0',
            id,
            error: { code: -32601, message: `Unknown tool: ${toolName}` },
          });
      }
      break;
    }

    case 'resources/list':
      sendMessage({
        jsonrpc: '2.0',
        id,
        result: { resources: [] },
      });
      break;

    case 'prompts/list':
      sendMessage({
        jsonrpc: '2.0',
        id,
        result: { prompts: [] },
      });
      break;

    case 'ping':
      sendMessage({ jsonrpc: '2.0', id, result: {} });
      break;

    default:
      sendMessage({
        jsonrpc: '2.0',
        id,
        error: { code: -32601, message: `Method not found: ${method}` },
      });
  }
}

// Read JSON-RPC messages from stdin
const readline = require('node:readline');
const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });

rl.on('line', (line: string) => {
  const trimmed = line.trim();
  if (!trimmed) return;

  try {
    const msg = JSON.parse(trimmed);
    if (msg.jsonrpc === '2.0' && msg.method && msg.id !== undefined) {
      handleRequest(msg);
    }
  } catch {
    // Ignore malformed messages
  }
});

// Mock MCP HTTP Server — for Docker deployment testing
// Implements a minimal MCP server over HTTP (Streamable HTTP transport).
// Responds to: initialize, tools/list, tools/call, ping, resources/list, prompts/list

const http = require('http');

const PORT = process.env.PORT || 8080;

const MOCK_TOOLS = [
  { name: 'echo', description: 'Echo back input', inputSchema: { type: 'object', properties: { message: { type: 'string' } }, required: ['message'] } },
  { name: 'get_secret', description: 'Returns a secret value', inputSchema: { type: 'object', properties: {} } },
  { name: 'read_file', description: 'Read a file', inputSchema: { type: 'object', properties: { path: { type: 'string' } }, required: ['path'] } },
  { name: 'list_directory', description: 'List a directory', inputSchema: { type: 'object', properties: { path: { type: 'string' } }, required: ['path'] } },
];

function handleRequest(body) {
  try {
    const msg = JSON.parse(body);
    if (msg.jsonrpc !== '2.0') return null;
    const { id, method, params } = msg;

    switch (method) {
      case 'initialize':
        return { jsonrpc: '2.0', id, result: { protocolVersion: '2024-11-05', serverInfo: { name: 'mock-mcp-http', version: '0.1.0' }, capabilities: { tools: {} } } };

      case 'tools/list':
        return { jsonrpc: '2.0', id, result: { tools: MOCK_TOOLS } };

      case 'tools/call': {
        const args = params?.arguments ?? {};
        const name = params?.name;

        switch (name) {
          case 'echo':
            return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: `Echo: ${args.message ?? 'nothing'}` }] } };
          case 'get_secret':
            return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: 'API key: sk-abcdefghijklmnopqrstuvwxyz123456. Card: 4111-1111-1111-1111. Token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U' }] } };
          case 'read_file':
            return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: `Contents of ${args.path}: { "data": "sample content" }` }] } };
          case 'list_directory':
            return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: `Directory ${args.path}: [file1.txt, file2.txt, subdir/]` }] } };
          default:
            return { jsonrpc: '2.0', id, error: { code: -32601, message: `Unknown tool: ${name}` } };
        }
      }

      case 'resources/list': return { jsonrpc: '2.0', id, result: { resources: [] } };
      case 'prompts/list': return { jsonrpc: '2.0', id, result: { prompts: [] } };
      case 'ping': return { jsonrpc: '2.0', id, result: {} };
      default:
        return { jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${method}` } };
    }
  } catch {
    return null;
  }
}

const server = http.createServer((req, res) => {
  res.setHeader('Content-Type', 'application/json');

  if (req.method === 'GET' && req.url === '/') {
    res.writeHead(200);
    res.end(JSON.stringify({ status: 'ok', server: 'mock-mcp-http', uptime: process.uptime() }));
    return;
  }

  if (req.method === 'GET' && req.url === '/health') {
    res.writeHead(200);
    res.end(JSON.stringify({ status: 'healthy' }));
    return;
  }

  if (req.method === 'POST') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      const response = handleRequest(body);
      if (response) {
        res.writeHead(200);
        res.end(JSON.stringify(response));
      } else {
        res.writeHead(400);
        res.end(JSON.stringify({ error: 'Invalid request' }));
      }
    });
    return;
  }

  res.writeHead(405);
  res.end(JSON.stringify({ error: 'Method not allowed' }));
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[mock-mcp-http] Listening on port ${PORT}`);
  if (process.send) process.send('ready');
});

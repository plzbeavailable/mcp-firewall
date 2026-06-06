import { createServer, Server, IncomingMessage, ServerResponse } from 'node:http';
import { parseMessage, serializeMessage, JSONRPCMessage, createErrorResponse, isResponse } from './mcp-types';

export interface HttpProxyOptions {
  /** Host to listen on */
  host?: string;
  /** Port to listen on */
  port: number;
  /** Upstream MCP server URL */
  upstreamUrl: string;
  /** Extra headers to forward to upstream */
  upstreamHeaders?: Record<string, string>;
  /** CORS configuration */
  cors?: {
    enabled: boolean;
    origins: string[];
  };
  /** Intercept request before forwarding */
  onRequest?: (msg: JSONRPCMessage) => Promise<JSONRPCMessage | null>;
  /** Intercept response before returning */
  onResponse?: (msg: JSONRPCMessage) => Promise<JSONRPCMessage | null>;
  /** Callback on proxy errors */
  onError?: (err: Error) => void;
}

/**
 * HttpProxy implements an HTTP-based MCP proxy using the Streamable HTTP
 * transport (MCP spec 2025-03-26).
 *
 * The firewall listens on a port and forwards requests to the upstream
 * MCP server endpoint. This enables centralized team deployments where
 * multiple clients connect through a single firewall instance.
 *
 * Architecture:
 *
 *   AI Clients (HTTP POST) ──► MCP Firewall :port ──► Upstream MCP Server
 */

// Standard JSON-RPC error codes
const JSONRPC_ERRORS = {
  PARSE_ERROR: -32700,
  INVALID_REQUEST: -32600,
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS: -32602,
  INTERNAL_ERROR: -32603,
  SERVER_ERROR: -32000,
} as const;

export class HttpProxy {
  private server: Server | null = null;
  private options: Required<Omit<HttpProxyOptions, 'host'>> & { host: string };

  constructor(options: HttpProxyOptions) {
    this.options = {
      host: options.host ?? '127.0.0.1',
      port: options.port,
      upstreamUrl: options.upstreamUrl.replace(/\/$/, ''),
      upstreamHeaders: options.upstreamHeaders ?? {},
      cors: options.cors ?? { enabled: false, origins: [] },
      onRequest: options.onRequest ?? (async (msg) => msg),
      onResponse: options.onResponse ?? (async (msg) => msg),
      onError: options.onError ?? (() => {}),
    };
  }

  /**
   * Start the HTTP proxy server.
   */
  start(): Promise<void> {
    return new Promise((resolve) => {
      this.server = createServer((req, res) => this.handleRequest(req, res));
      this.server.listen(this.options.port, this.options.host, () => {
        resolve();
      });
    });
  }

  /**
   * Gracefully stop the proxy server.
   */
  async stop(): Promise<void> {
    return new Promise((resolve, reject) => {
      if (!this.server) {
        resolve();
        return;
      }
      this.server.close((err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }

  get address(): string {
    return `http://${this.options.host}:${this.options.port}`;
  }

  private async handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    // ── CORS ────────────────────────────────────────────────
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, Accept');
    res.setHeader('Access-Control-Max-Age', '86400');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    // Streamable HTTP transport uses POST for messages and
    // GET/DELETE for session management
    if (req.method === 'POST') {
      await this.handlePost(req, res);
    } else if (req.method === 'GET') {
      // SSE support: the client may request an SSE stream for server→client messages
      await this.handleGet(req, res);
    } else if (req.method === 'DELETE') {
      // Session termination
      res.writeHead(200);
      res.end();
    } else {
      res.writeHead(405, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Method not allowed' }));
    }
  }

  private async handlePost(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await readBody(req);

    if (!body) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify(
          createErrorResponse('', JSONRPC_ERRORS.PARSE_ERROR, 'Empty request body'),
        ),
      );
      return;
    }

    const msg = parseMessage(body);
    if (!msg) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify(
          createErrorResponse('', JSONRPC_ERRORS.PARSE_ERROR, 'Invalid JSON-RPC message'),
        ),
      );
      return;
    }

    try {
      // Run request interceptor
      const processed = await this.options.onRequest(msg);
      if (processed === null) {
        // Blocked
        if (isResponse(msg)) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(serializeMessage(msg).trim());
          return;
        }
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify(
            createErrorResponse(
              (msg as { id?: string | number }).id ?? '',
              -32001,
              'Request blocked by firewall',
            ),
          ),
        );
        return;
      }

      // Forward to upstream
      const upstreamResponse = await fetch(this.options.upstreamUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...this.options.upstreamHeaders,
        },
        body: serializeMessage(processed).trim(),
      });

      if (!upstreamResponse.ok) {
        res.writeHead(upstreamResponse.status, {
          'Content-Type': 'application/json',
        });
        const errorBody = await upstreamResponse.text();
        res.end(errorBody);
        return;
      }

      const responseBody = await upstreamResponse.text();
      const responseMsg = parseMessage(responseBody);

      if (!responseMsg) {
        res.writeHead(upstreamResponse.status, {
          'Content-Type': 'application/json',
        });
        res.end(responseBody);
        return;
      }

      // Run response interceptor
      const processedResponse = await this.options.onResponse(responseMsg);
      if (processedResponse === null) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify(
            createErrorResponse(
              (responseMsg as { id?: string | number }).id ?? '',
              JSONRPC_ERRORS.INTERNAL_ERROR,
              'Response blocked by firewall',
            ),
          ),
        );
        return;
      }

      // Copy relevant upstream headers
      const mcpSessionId = upstreamResponse.headers.get('mcp-session-id');
      if (mcpSessionId) {
        res.setHeader('mcp-session-id', mcpSessionId);
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(serializeMessage(processedResponse).trim());
    } catch (err) {
      this.options.onError(err instanceof Error ? err : new Error(String(err)));
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify(
          createErrorResponse(
            '',
            JSONRPC_ERRORS.INTERNAL_ERROR,
            'Internal firewall error',
          ),
        ),
      );
    }
  }

  private async handleGet(_req: IncomingMessage, res: ServerResponse): Promise<void> {
    // For SSE support, we establish an SSE stream from the upstream.
    // This is a simplified implementation — full SSE proxying would
    // maintain a persistent connection to upstream.
    try {
      const upstreamRes = await fetch(this.options.upstreamUrl, {
        method: 'GET',
        headers: {
          Accept: 'text/event-stream',
          ...this.options.upstreamHeaders,
        },
      });

      if (!upstreamRes.ok || !upstreamRes.body) {
        res.writeHead(upstreamRes.status);
        res.end();
        return;
      }

      // Set SSE headers
      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        Connection: 'keep-alive',
      });

      // Relay SSE events from upstream to client
      const reader = upstreamRes.body.getReader();
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          res.write(value);
        }
      } finally {
        reader.releaseLock();
      }

      res.end();
    } catch (err) {
      this.options.onError(err instanceof Error ? err : new Error(String(err)));
      if (!res.headersSent) {
        res.writeHead(500);
      }
      res.end();
    }
  }
}

/**
 * Read the full request body as a string.
 */
function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
    req.on('error', reject);
  });
}

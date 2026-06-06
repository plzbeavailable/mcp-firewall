import { createServer, Server, IncomingMessage, ServerResponse } from 'node:http';
import { parseMessage, serializeMessage, JSONRPCMessage, createErrorResponse } from './mcp-types';

export interface SseProxyOptions {
  host?: string;
  port: number;
  upstreamBaseUrl: string;
  upstreamHeaders?: Record<string, string>;
  cors?: { enabled: boolean; origins: string[] };
  onRequest?: (msg: JSONRPCMessage) => Promise<JSONRPCMessage | null>;
  onResponse?: (msg: JSONRPCMessage) => Promise<JSONRPCMessage | null>;
  onError?: (err: Error) => void;
}

/**
 * SseProxy implements the legacy HTTP+SSE transport (MCP spec 2024-11-05).
 *
 * In this transport:
 * - GET /sse  → establishes an SSE stream for server→client messages
 * - POST /messages?sessionId=... → sends client→server messages
 *
 * This proxy intercepts messages on the POST /messages endpoint.
 */
export class SseProxy {
  private server: Server | null = null;
  private options: Required<Omit<SseProxyOptions, 'host'>> & { host: string };

  // Track SSE client connections to forward server events
  private sseClients: Map<string, ServerResponse> = new Map();
  private upstreamSessionId: string | null = null;

  constructor(options: SseProxyOptions) {
    this.options = {
      host: options.host ?? '127.0.0.1',
      port: options.port,
      upstreamBaseUrl: options.upstreamBaseUrl.replace(/\/$/, ''),
      upstreamHeaders: options.upstreamHeaders ?? {},
      cors: options.cors ?? { enabled: false, origins: [] },
      onRequest: options.onRequest ?? (async (msg) => msg),
      onResponse: options.onResponse ?? (async (msg) => msg),
      onError: options.onError ?? (() => {}),
    };
  }

  start(): Promise<void> {
    return new Promise((resolve) => {
      this.server = createServer((req, res) => this.handleRequest(req, res));
      this.server.listen(this.options.port, this.options.host, () => resolve());
    });
  }

  async stop(): Promise<void> {
    return new Promise((resolve, reject) => {
      if (!this.server) { resolve(); return; }
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
    // CORS
    if (this.options.cors.enabled) {
      const origin = req.headers.origin;
      if (origin && this.options.cors.origins.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
      }
    }

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    const url = new URL(req.url ?? '/', `http://${req.headers.host}`);
    const path = url.pathname;

    if (req.method === 'GET' && path === '/sse') {
      await this.handleSseConnect(req, res);
    } else if (req.method === 'POST' && path === '/messages') {
      const sessionId = url.searchParams.get('sessionId');
      await this.handleMessage(req, res, sessionId);
    } else {
      res.writeHead(404);
      res.end();
    }
  }

  private async handleSseConnect(req: IncomingMessage, res: ServerResponse): Promise<void> {
    // Connect to upstream SSE
    try {
      const upstreamRes = await fetch(`${this.options.upstreamBaseUrl}/sse`, {
        headers: { Accept: 'text/event-stream', ...this.options.upstreamHeaders },
      });

      if (!upstreamRes.ok) {
        res.writeHead(502);
        res.end('Failed to connect to upstream SSE');
        return;
      }

      // Extract session ID from the endpoint event
      const reader = upstreamRes.body!.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      // Set SSE headers on client response
      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        Connection: 'keep-alive',
      });

      // Read the endpoint event to find the session ID,
      // then relay everything to the client
      const relayLoop = async () => {
        try {
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;

            buffer += decoder.decode(value, { stream: true });

            // Check for the endpoint event which contains session ID
            const endpointMatch = buffer.match(/event: endpoint\ndata: (.+)\n\n/);
            if (endpointMatch) {
              const endpointUrl = endpointMatch[1]!;
              const endpointParsed = new URL(endpointUrl);
              this.upstreamSessionId = endpointParsed.searchParams.get('sessionId') ?? '';

              // Register this client
              if (this.upstreamSessionId) {
                this.sseClients.set(this.upstreamSessionId, res);
              }
            }

            // Relay to client
            res.write(value);
          }
          res.end();
        } catch {
          // Connection closed
        } finally {
          reader.releaseLock();
          if (this.upstreamSessionId) {
            this.sseClients.delete(this.upstreamSessionId);
          }
        }
      };

      relayLoop();

      req.on('close', () => {
        reader.cancel();
        if (this.upstreamSessionId) {
          this.sseClients.delete(this.upstreamSessionId);
        }
      });
    } catch (err) {
      this.options.onError(err instanceof Error ? err : new Error(String(err)));
      res.writeHead(502);
      res.end('Failed to connect to upstream');
    }
  }

  private async handleMessage(req: IncomingMessage, res: ServerResponse, _sessionId: string | null): Promise<void> {
    const body = await readBody(req);

    if (!body) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(createErrorResponse('', -32700, 'Empty body')));
      return;
    }

    const msg = parseMessage(body);
    if (!msg) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(createErrorResponse('', -32700, 'Invalid JSON-RPC')));
      return;
    }

    try {
      const processed = await this.options.onRequest!(msg);
      if (processed === null) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(
          createErrorResponse((msg as { id?: string | number }).id ?? '', -32001, 'Blocked by firewall'),
        ));
        return;
      }

      const upstreamRes = await fetch(
        `${this.options.upstreamBaseUrl}/messages?sessionId=${this.upstreamSessionId ?? ''}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', ...this.options.upstreamHeaders },
          body: serializeMessage(processed).trim(),
        },
      );

      const responseBody = await upstreamRes.text();
      const responseMsg = parseMessage(responseBody);

      if (responseMsg) {
        const processedResponse = await this.options.onResponse!(responseMsg);
        if (processedResponse) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(serializeMessage(processedResponse).trim());
          return;
        }
      }

      res.writeHead(upstreamRes.status, { 'Content-Type': 'application/json' });
      res.end(responseBody);
    } catch (err) {
      this.options.onError(err instanceof Error ? err : new Error(String(err)));
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(createErrorResponse('', -32603, 'Internal firewall error')));
    }
  }
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
    req.on('error', reject);
  });
}

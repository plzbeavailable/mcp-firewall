import type { FirewallConfig } from '@mcp-firewall/config';
import { loadConfig, type LoadResult } from '@mcp-firewall/config';
import { PolicyEngine } from './policy/engine';
import { Pipeline } from './pipeline/pipeline';
import { createPipelineContext, cloneContextForResponse } from './pipeline/context';
import { StdioProxy, HttpProxy, SseProxy } from './transport';
import { MetricsCollector } from './observability/metrics';
import { AuditLogger, TokenTracker, Tracer, HealthChecker } from './observability/audit-log';
import {
  isRequest,
  isResponse,
  createErrorResponse,
  serializeMessage,
  type JSONRPCMessage,
} from './transport/mcp-types';

export interface FirewallOptions {
  /** Path to config file, or a pre-loaded config object */
  config: string | FirewallConfig;
  /** Enable hot-reload for config file changes (when passing a path) */
  hotReload?: boolean;
}

/**
 * MCPFirewall is the main entry point for running the firewall.
 *
 * It wires together the proxy engine, security pipeline, and
 * observability components based on the loaded configuration.
 *
 * Usage:
 * ```typescript
 * const firewall = new MCPFirewall({ config: './mcp-firewall.yaml' });
 * await firewall.start();
 * ```
 */
export class MCPFirewall {
  private config: FirewallConfig;
  private policyEngine: PolicyEngine;
  private metrics: MetricsCollector;
  private auditLogger: AuditLogger;
  private tokenTracker: TokenTracker;
  private tracer: Tracer;
  private healthChecker: HealthChecker;

  private stdioProxy: StdioProxy | null = null;
  private httpProxy: HttpProxy | null = null;
  private sseProxy: SseProxy | null = null;

  private running = false;

  constructor(options: FirewallOptions) {
    // Load config
    if (typeof options.config === 'string') {
      const result: LoadResult = loadConfig(options.config);
      this.config = result.config;
    } else {
      this.config = options.config;
    }

    // Initialize core components
    this.policyEngine = new PolicyEngine(this.config);
    this.metrics = new MetricsCollector();
    this.auditLogger = new AuditLogger({
      output: this.config.observability.auditLog.output as 'stdout' | 'file' | 'sqlite' | 'postgres',
      filePath: this.config.observability.auditLog.file,
      format: this.config.observability.auditLog.format,
    });
    this.tokenTracker = new TokenTracker(this.metrics);
    this.tracer = new Tracer(this.config.observability.tracing.enabled);
    this.healthChecker = new HealthChecker(this.metrics);
  }

  /**
   * Start the firewall proxy.
   */
  async start(): Promise<void> {
    if (this.running) {
      throw new Error('Firewall is already running');
    }

    const { mode, upstreams, observability } = this.config;

    // Set up health checks for all upstreams
    for (const upstream of upstreams) {
      if (upstream.healthCheck?.enabled) {
        const intervalMs = parseDuration(upstream.healthCheck.interval);
        if (upstream.transport === 'stdio') {
          // For stdio, the health check is implied by the process being alive
          this.healthChecker.registerServer(upstream.name, async () => true, intervalMs);
        } else {
          // For HTTP upstreams, ping the /health endpoint
          const url = upstream.url;
          this.healthChecker.registerServer(
            upstream.name,
            async () => {
              try {
                const res = await fetch(new URL('/health', url).href, {
                  signal: AbortSignal.timeout(5000),
                });
                return res.ok;
              } catch {
                return false;
              }
            },
            intervalMs,
          );
        }
      }
    }

    // Start metrics HTTP endpoint if enabled
    if (observability.metrics.enabled) {
      await this.startMetricsEndpoint();
    }

    // Start dashboard API if enabled
    if (this.config.dashboard.enabled) {
      await this.startDashboardApi();
    }

    // Start the appropriate proxy based on mode
    switch (mode) {
      case 'stdio':
        await this.startStdioProxy();
        break;
      case 'http':
        await this.startHttpProxy();
        break;
      default:
        throw new Error(`Unsupported mode: ${mode}`);
    }

    this.running = true;
  }

  /**
   * Gracefully stop the firewall.
   */
  async stop(): Promise<void> {
    if (this.stdioProxy) await this.stdioProxy.stop();
    if (this.httpProxy) await this.httpProxy.stop();
    if (this.sseProxy) await this.sseProxy.stop();
    this.healthChecker.destroy();
    this.running = false;
  }

  /**
   * Get the metrics collector for external access.
   */
  getMetrics(): MetricsCollector {
    return this.metrics;
  }

  /**
   * Get the current config.
   */
  getConfig(): FirewallConfig {
    return this.config;
  }

  // ─── Private: Proxy setup ─────────────────────────────────

  private async startStdioProxy(): Promise<void> {
    const upstream = this.config.upstreams[0];
    if (!upstream) {
      throw new Error('At least one upstream server must be configured for stdio mode');
    }

    if (upstream.transport !== 'stdio') {
      throw new Error('Stdio mode requires a stdio upstream');
    }

    const pipeline = this.policyEngine.getPipeline();

    this.stdioProxy = new StdioProxy({
      command: upstream.command,
      args: upstream.args,
      env: upstream.env,
      onRequest: async (msg: JSONRPCMessage) => {
        return this.processRequest(msg, upstream.name, pipeline);
      },
      onResponse: async (msg: JSONRPCMessage) => {
        return this.processResponse(msg, upstream.name, pipeline);
      },
      onExit: (code, signal) => {
        console.error(`[mcp-firewall] Upstream "${upstream.name}" exited with code ${code}, signal ${signal}`);
      },
      onError: (err) => {
        console.error(`[mcp-firewall] Proxy error: ${err.message}`);
      },
    });

    console.error(`[mcp-firewall] Starting stdio proxy → upstream "${upstream.name}" (${upstream.command} ${upstream.args?.join(' ') ?? ''})`);
    this.stdioProxy.start();
  }

  private async startHttpProxy(): Promise<void> {
    const pipeline = this.policyEngine.getPipeline();
    const { server } = this.config;

    // If there's only one upstream, use it directly.
    // For multi-upstream HTTP mode, we'd need routing — simplified
    // for Phase 1: use the first HTTP upstream.
    const upstream = this.config.upstreams.find(
      (u) => u.transport === 'streamable-http' || u.transport === 'sse',
    );
    if (!upstream || (upstream.transport !== 'streamable-http' && upstream.transport !== 'sse')) {
      throw new Error('HTTP mode requires at least one streamable-http or sse upstream');
    }

    if (upstream.transport === 'sse') {
      this.sseProxy = new SseProxy({
        host: server.host,
        port: server.port,
        upstreamBaseUrl: upstream.url,
        upstreamHeaders: upstream.headers,
        cors: server.cors,
        onRequest: async (msg: JSONRPCMessage) => {
          return this.processRequest(msg, upstream.name, pipeline);
        },
        onResponse: async (msg: JSONRPCMessage) => {
          return this.processResponse(msg, upstream.name, pipeline);
        },
        onError: (err) => {
          console.error(`[mcp-firewall] Proxy error: ${err.message}`);
        },
      });
      await this.sseProxy.start();
      console.error(`[mcp-firewall] SSE proxy listening on ${this.sseProxy.address} → upstream ${upstream.name} (${upstream.url})`);
    } else {
      this.httpProxy = new HttpProxy({
        host: server.host,
        port: server.port,
        upstreamUrl: upstream.url,
        upstreamHeaders: upstream.headers,
        cors: server.cors,
        onRequest: async (msg: JSONRPCMessage) => {
          return this.processRequest(msg, upstream.name, pipeline);
        },
        onResponse: async (msg: JSONRPCMessage) => {
          return this.processResponse(msg, upstream.name, pipeline);
        },
        onError: (err) => {
          console.error(`[mcp-firewall] Proxy error: ${err.message}`);
        },
      });
      await this.httpProxy.start();
      console.error(`[mcp-firewall] HTTP proxy listening on ${this.httpProxy.address} → upstream ${upstream.name} (${upstream.url})`);
    }
  }

  // ─── Private: Request/Response processing ──────────────────

  private async processRequest(
    msg: JSONRPCMessage,
    serverName: string,
    pipeline: Pipeline,
  ): Promise<JSONRPCMessage | null> {
    if (!isRequest(msg)) return msg; // Pass through notifications and responses

    const ctx = createPipelineContext({
      clientId: 'default',
      authType: 'none',
      serverName,
      method: msg.method,
      toolName: msg.params && typeof msg.params === 'object' && 'name' in msg.params
        ? (msg.params as Record<string, unknown>).name as string
        : undefined,
      request: msg,
    });

    // Start tracing span
    const span = this.tracer.startSpan(`mcp-firewall.proxy.${msg.method}`, ctx.spanId);
    this.tracer.setAttribute(span, 'server.name', serverName);
    this.tracer.setAttribute(span, 'mcp.method', msg.method);

    // Run request pipeline
    const result = await pipeline.evaluateRequest(ctx);

    this.metrics.counterIncrement('mcp_requests_total', {
      method: msg.method,
      server_name: serverName,
      verdict: result.verdict,
    });

    if (result.verdict === 'block') {
      this.metrics.counterIncrement('mcp_blocks_total', {
        reason: result.blockDecision?.reason ?? 'unknown',
        middleware: result.blockDecision?.metadata?.['middleware'] as string ?? 'unknown',
      });

      this.tracer.endSpan(span, 'error');
      this.auditLogger.log(ctx);

      // Return a JSON-RPC error — write it directly to stdout
      // since the proxy won't forward null results
      const errorResp = createErrorResponse(
        msg.id,
        result.blockDecision?.errorCode ?? -32001,
        result.blockDecision?.reason ?? 'Request blocked by firewall',
      );
      process.stdout.write(serializeMessage(errorResp));

      // Return null so the proxy doesn't forward to child
      return null;
    }

    // Store context for matching response
    ctx.metadata['_span'] = span;
    this.metrics.incrementConnections();

    // Forward the request
    return msg;
  }

  private async processResponse(
    msg: JSONRPCMessage,
    serverName: string,
    pipeline: Pipeline,
  ): Promise<JSONRPCMessage | null> {
    if (!isResponse(msg)) return msg;

    // Find matching request context (simplified: use the latest)
    // In production, we'd maintain a request map keyed by JSON-RPC id.

    const ctx = createPipelineContext({
      clientId: 'default',
      serverName,
      method: 'tools/call', // Approximate; real impl tracks this
      request: { jsonrpc: '2.0', id: msg.id, method: '' },
    });

    const ctxWithResponse = cloneContextForResponse(ctx, msg);

    // Run response pipeline
    const result = await pipeline.evaluateResponse(ctxWithResponse);

    if (result.verdict === 'block') {
      this.metrics.counterIncrement('mcp_blocks_total', {
        reason: result.blockDecision?.reason ?? 'unknown',
        middleware: 'response-pipeline',
      });

      this.auditLogger.log(ctxWithResponse);

      return createErrorResponse(
        msg.id,
        result.blockDecision?.errorCode ?? -32001,
        result.blockDecision?.reason ?? 'Response blocked by firewall',
      );
    }

    // Track token usage
    const usage = this.tokenTracker.tryExtractUsage(
      'result' in msg ? msg.result : null,
    );
    if (usage) {
      ctxWithResponse.tokenUsage = usage;
    } else {
      const estimated = this.tokenTracker.estimateTokens(ctxWithResponse);
      ctxWithResponse.tokenUsage = {
        inputTokens: estimated.inputTokens,
        outputTokens: estimated.outputTokens,
        model: 'unknown',
      };
    }

    // Record latency
    const duration = Date.now() - ctx.startTime;
    this.metrics.histogramObserve('mcp_request_duration_seconds', duration / 1000);

    this.metrics.decrementConnections();
    this.auditLogger.log(ctxWithResponse);

    // Handle warning verdicts that include masked content
    if (result.warnings.length > 0) {
      const maskWarning = result.warnings.find(
        (w) => w.metadata?.action === 'mask' && w.metadata?.maskedResponse,
      );
      if (maskWarning?.metadata?.maskedResponse) {
        try {
          return JSON.parse(maskWarning.metadata.maskedResponse as string) as JSONRPCMessage;
        } catch {
          return msg; // Return original if masking fails
        }
      }
    }

    return msg;
  }

  // ─── Private: Metrics endpoint ─────────────────────────────

  private async startMetricsEndpoint(): Promise<void> {
    const { port, path } = this.config.observability.metrics;
    const http = await import('node:http');

    const server = http.createServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end(this.metrics.toPrometheusText());
    });

    server.listen(port, () => {
      console.error(`[mcp-firewall] Metrics endpoint: http://localhost:${port}${path}`);
    });
  }

  // ─── Private: Dashboard API ─────────────────────────────

  private async startDashboardApi(): Promise<void> {
    const { host, port } = this.config.dashboard;
    const http = await import('node:http');

    const server = http.createServer((_req, res) => {
      const snapshot = this.metrics.toJSON();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        status: 'ok',
        uptime: this.metrics.uptimeSeconds,
        version: '0.1.0',
        metrics: snapshot,
      }));
    });

    server.listen(port, host, () => {
      console.error(`[mcp-firewall] Dashboard API: http://${host}:${port}/api/health`);
    });
  }
}

// ─── Helpers ─────────────────────────────────────────────────

function parseDuration(duration: string): number {
  const match = duration.match(/^(\d+)(s|m|h)$/);
  if (!match) return 30000; // Default 30s
  const value = parseInt(match[1]!, 10);
  switch (match[2]) {
    case 's': return value * 1000;
    case 'm': return value * 60_000;
    case 'h': return value * 3_600_000;
    default: return 30000;
  }
}

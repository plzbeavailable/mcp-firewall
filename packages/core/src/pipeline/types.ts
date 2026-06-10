import type { JSONRPCRequest, JSONRPCResponse } from '../transport/mcp-types.js';

// ─── Core pipeline types ───────────────────────────────────────

/**
 * Unique identifier for each request flowing through the pipeline.
 */
export type RequestId = string;

/**
 * The verdicts the security pipeline can produce.
 * - allow: pass through normally
 * - block: reject with an error response
 * - warn: allow but flag in audit log
 */
export type SecurityVerdict = 'allow' | 'block' | 'warn';

/**
 * A security decision produced by a middleware.
 */
export interface SecurityDecision {
  /** The verdict for this request/response */
  verdict: SecurityVerdict;
  /** Human-readable reason for the decision */
  reason: string;
  /** Optional opaque metadata recorded in the audit log */
  metadata?: Record<string, unknown>;
  /** If verdict is 'block', the JSON-RPC error code to return */
  errorCode?: number;
}

/**
 * A security event that occurred during pipeline processing.
 * Stored in the audit log entry.
 */
export interface SecurityEvent {
  /** Timestamp (ISO 8601) */
  timestamp: string;
  /** Which middleware produced this event */
  middleware: string;
  /** Event category */
  category: 'auth' | 'rbac' | 'rate-limit' | 'validation' | 'content-filter' | 'sensitive-data' | 'sandbox' | 'ip-access' | 'response-limit' | 'concurrency' | 'replay' | 'threat';
  /** Human-readable description */
  message: string;
  /** Severity */
  severity: 'info' | 'warn' | 'critical';
  /** Arbitrary metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Metadata about the client that initiated the request.
 */
export interface ClientIdentity {
  /** Unique client identifier */
  clientId: string;
  /** Authentication method used */
  authType: 'api-key' | 'jwt' | 'none';
  /** Optional: original JWT claims if OAuth2 */
  claims?: Record<string, unknown>;
}

/**
 * Token usage estimation for an MCP tool call.
 */
export interface TokenUsage {
  inputTokens: number;
  outputTokens: number;
  model: string;
}

// ─── Pipeline context ──────────────────────────────────────────

/**
 * The PipelineContext carries all metadata about a request as it
 * flows through the security and observability pipelines.
 */
export interface PipelineContext {
  /** Unique request ID (UUID v4) */
  requestId: RequestId;

  /** OpenTelemetry trace ID */
  traceId: string;

  /** OpenTelemetry span ID for this specific request */
  spanId: string;

  /** Identity of the authenticated client */
  client: ClientIdentity;

  /** Name of the upstream MCP server being called */
  serverName: string;

  /** JSON-RPC method being invoked (e.g., 'tools/call', 'resources/read') */
  method: string;

  /** Tool name if method is 'tools/call', otherwise undefined */
  toolName?: string;

  /** The raw JSON-RPC request */
  request: JSONRPCRequest;

  /** The JSON-RPC response (only available in the response phase) */
  response?: JSONRPCResponse;

  /** Timestamp when the request entered the firewall (epoch ms) */
  startTime: number;

  /** Timestamp when the upstream server responded (epoch ms) */
  upstreamResponseTime?: number;

  /** Security events accumulated during processing */
  securityEvents: SecurityEvent[];

  /** Estimated token usage (populated after response) */
  tokenUsage?: TokenUsage;

  /** Arbitrary data that middlewares can attach */
  metadata: Record<string, unknown>;
}

// ─── Middleware interface ──────────────────────────────────────

/**
 * When the middleware should execute.
 */
export type MiddlewarePhase = 'request' | 'response' | 'both';

/**
 * A security middleware that evaluates requests and/or responses.
 * Middlewares are ordered by priority (lower = earlier execution).
 */
export interface SecurityMiddleware {
  /** Unique name for this middleware */
  readonly name: string;

  /** Execution order (lower = earlier) */
  readonly priority: number;

  /** When to run: before forwarding, after receiving response, or both */
  readonly phase: MiddlewarePhase;

  /**
   * Evaluate a request or response.
   * @returns A SecurityDecision (allow/block/warn) or null to pass through.
   */
  evaluate(ctx: PipelineContext): Promise<SecurityDecision | null>;
}

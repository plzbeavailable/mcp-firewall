import { randomUUID } from 'node:crypto';
import type { PipelineContext, ClientIdentity } from './types';
import type { JSONRPCRequest, JSONRPCResponse } from '../transport/mcp-types';

/**
 * Create a new PipelineContext for an incoming request.
 */
export function createPipelineContext(params: {
  clientId: string;
  authType?: ClientIdentity['authType'];
  claims?: Record<string, unknown>;
  serverName: string;
  method: string;
  toolName?: string;
  request: JSONRPCRequest;
}): PipelineContext {
  const traceId = randomUUID();
  const spanId = randomUUID().slice(0, 16);

  return {
    requestId: randomUUID(),
    traceId,
    spanId,
    client: {
      clientId: params.clientId,
      authType: params.authType ?? 'none',
      claims: params.claims,
    },
    serverName: params.serverName,
    method: params.method,
    toolName: params.toolName,
    request: params.request,
    startTime: Date.now(),
    securityEvents: [],
    metadata: {},
  };
}

/**
 * Clone a PipelineContext for the response phase.
 * Carries over all request-phase metadata and adds the response.
 */
export function cloneContextForResponse(
  ctx: PipelineContext,
  response: JSONRPCResponse,
): PipelineContext {
  return {
    ...ctx,
    response,
    upstreamResponseTime: Date.now(),
    securityEvents: [...ctx.securityEvents],
    metadata: { ...ctx.metadata },
  };
}

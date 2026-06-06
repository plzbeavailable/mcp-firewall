// ─── MCP JSON-RPC types ───────────────────────────────────────
// Based on the Model Context Protocol specification
// https://spec.modelcontextprotocol.io/

/**
 * Standard JSON-RPC 2.0 request.
 */
export interface JSONRPCRequest {
  jsonrpc: '2.0';
  id: string | number;
  method: string;
  params?: Record<string, unknown>;
}

/**
 * Standard JSON-RPC 2.0 success response.
 */
export interface JSONRPCSuccessResponse {
  jsonrpc: '2.0';
  id: string | number;
  result: unknown;
}

/**
 * Standard JSON-RPC 2.0 error response.
 */
export interface JSONRPCErrorResponse {
  jsonrpc: '2.0';
  id: string | number;
  error: {
    code: number;
    message: string;
    data?: unknown;
  };
}

export type JSONRPCResponse = JSONRPCSuccessResponse | JSONRPCErrorResponse;

/**
 * Standard JSON-RPC 2.0 notification (no id).
 */
export interface JSONRPCNotification {
  jsonrpc: '2.0';
  method: string;
  params?: Record<string, unknown>;
}

export type JSONRPCMessage = JSONRPCRequest | JSONRPCResponse | JSONRPCNotification;

/**
 * Check if a message is a request (has id and method, not error/result).
 */
export function isRequest(msg: JSONRPCMessage): msg is JSONRPCRequest {
  return 'method' in msg && 'id' in msg && !('result' in msg) && !('error' in msg);
}

/**
 * Check if a message is a response (has id and either result or error).
 */
export function isResponse(msg: JSONRPCMessage): msg is JSONRPCResponse {
  return 'id' in msg && !('method' in msg) && ('result' in msg || 'error' in msg);
}

/**
 * Check if a message is a notification (has method, no id).
 */
export function isNotification(msg: JSONRPCMessage): msg is JSONRPCNotification {
  return 'method' in msg && !('id' in msg);
}

/**
 * Check if a response is an error response.
 */
export function isErrorResponse(
  msg: JSONRPCResponse,
): msg is JSONRPCErrorResponse {
  return 'error' in msg;
}

/**
 * Create a standard JSON-RPC error response.
 */
export function createErrorResponse(
  id: string | number,
  code: number,
  message: string,
  data?: unknown,
): JSONRPCErrorResponse {
  return {
    jsonrpc: '2.0',
    id,
    error: { code, message, ...(data ? { data } : {}) },
  };
}

// ─── MCP-specific method constants ─────────────────────────────

export const MCP_METHODS = {
  INITIALIZE: 'initialize',
  PING: 'ping',
  TOOLS_LIST: 'tools/list',
  TOOLS_CALL: 'tools/call',
  RESOURCES_LIST: 'resources/list',
  RESOURCES_READ: 'resources/read',
  RESOURCE_TEMPLATES_LIST: 'resources/templates/list',
  PROMPTS_LIST: 'prompts/list',
  PROMPTS_GET: 'prompts/get',
  COMPLETION_COMPLETE: 'completion/complete',
  LOGGING_SET_LEVEL: 'logging/setLevel',
  NOTIFICATIONS_INITIALIZED: 'notifications/initialized',
  NOTIFICATIONS_TOOLS_LIST_CHANGED: 'notifications/tools/list_changed',
  NOTIFICATIONS_RESOURCES_LIST_CHANGED: 'notifications/resources/list_changed',
  NOTIFICATIONS_PROMPTS_LIST_CHANGED: 'notifications/prompts/list_changed',
  NOTIFICATIONS_CANCELLED: 'notifications/cancelled',
  NOTIFICATIONS_PROGRESS: 'notifications/progress',
} as const;

export type MCPMethod = (typeof MCP_METHODS)[keyof typeof MCP_METHODS];

/**
 * Parse a raw JSON-RPC message from a string.
 * Returns null if the message is malformed.
 */
export function parseMessage(raw: string): JSONRPCMessage | null {
  try {
    const obj = JSON.parse(raw);
    if (obj && typeof obj === 'object' && obj.jsonrpc === '2.0') {
      return obj as JSONRPCMessage;
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Serialize a JSON-RPC message to a string with newline delimiter.
 */
export function serializeMessage(msg: JSONRPCMessage): string {
  return JSON.stringify(msg) + '\n';
}

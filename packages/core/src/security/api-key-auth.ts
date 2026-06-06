import type { SecurityMiddleware, PipelineContext, SecurityDecision } from '../pipeline/types';

export interface ApiKeyEntry {
  key: string;
  clientId: string;
}

/**
 * Middleware that authenticates clients using API keys.
 *
 * In stdio mode, the API key is typically embedded in the config
 * and the client is presumed to be the configured one.
 *
 * In HTTP mode, the API key is extracted from the Authorization header
 * and validated against the configured keys.
 *
 * Priority: 20 (runs right after method allowlist)
 */
export class ApiKeyAuthMiddleware implements SecurityMiddleware {
  readonly name = 'api-key-auth';
  readonly priority = 20;
  readonly phase = 'request' as const;

  private keys: Map<string, string>; // key → clientId
  private enabled: boolean;

  constructor(entries: ApiKeyEntry[], enabled = true) {
    this.enabled = enabled;
    this.keys = new Map(entries.map((e) => [e.key, e.clientId]));
  }

  async evaluate(ctx: PipelineContext): Promise<SecurityDecision | null> {
    if (!this.enabled) return null;

    // In stdio mode, the client identity is pre-set.
    // The middleware just validates it exists and is allowed.
    if (ctx.client.authType === 'api-key') {
      // Already authenticated upstream (e.g., via HTTP header extraction)
      return null;
    }

    // For stdio mode without pre-auth, we check if there's
    // an API key configured in the context metadata
    const apiKey = ctx.metadata['apiKey'] as string | undefined;
    if (!apiKey) {
      // No API key provided; allow if auth is disabled
      if (this.keys.size === 0) return null;

      return {
        verdict: 'block',
        reason: 'API key required but not provided',
        errorCode: -32001,
      };
    }

    const clientId = this.keys.get(apiKey);
    if (!clientId) {
      return {
        verdict: 'block',
        reason: 'Invalid API key',
        errorCode: -32001,
      };
    }

    // Update client identity
    ctx.client.clientId = clientId;
    ctx.client.authType = 'api-key';

    return null; // Pass
  }

  /**
   * Extract an API key from an HTTP Authorization header value.
   * Returns null if the header doesn't contain a valid key.
   */
  static extractFromHeader(authHeader: string): string | null {
    // Bearer <key>
    const bearerMatch = authHeader.match(/^Bearer\s+(.+)$/i);
    if (bearerMatch) return bearerMatch[1]!;

    // <key> directly
    const directMatch = authHeader.match(/^[\w-]{20,}$/);
    if (directMatch) return directMatch[0]!;

    return null;
  }
}

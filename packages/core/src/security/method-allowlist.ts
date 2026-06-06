import type { SecurityMiddleware, PipelineContext, SecurityDecision } from '../pipeline/types';

/**
 * Middleware that enforces an allowlist of MCP JSON-RPC methods.
 * Any method not in the list is blocked (when blockUnknown is true).
 *
 * Priority: 10 (first middleware to run)
 */
export class MethodAllowlistMiddleware implements SecurityMiddleware {
  readonly name = 'method-allowlist';
  readonly priority = 10;
  readonly phase = 'request' as const;

  private allowedMethods: Set<string>;
  private blockUnknown: boolean;

  constructor(allowedMethods: string[], blockUnknown = true) {
    this.allowedMethods = new Set(allowedMethods);
    this.blockUnknown = blockUnknown;
  }

  async evaluate(ctx: PipelineContext): Promise<SecurityDecision | null> {
    if (this.allowedMethods.has(ctx.method)) {
      return null; // Pass
    }

    if (this.blockUnknown) {
      return {
        verdict: 'block',
        reason: `Method "${ctx.method}" is not in the allowed list`,
        errorCode: -32601, // METHOD_NOT_FOUND
        metadata: { allowedMethods: [...this.allowedMethods] },
      };
    }

    // Warn but allow
    return {
      verdict: 'warn',
      reason: `Method "${ctx.method}" is not in the recommended allowlist`,
      metadata: { allowedMethods: [...this.allowedMethods] },
    };
  }
}

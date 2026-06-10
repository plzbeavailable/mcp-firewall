import type { SecurityMiddleware, PipelineContext, SecurityDecision } from '../pipeline/types';

/**
 * Request replay detection middleware.
 *
 * Prevents replay attacks by requiring a timestamp and nonce
 * with each request. The nonce is tracked for the configured TTL
 * and any repeated nonce within that window triggers a block.
 *
 * Also validates that the request timestamp is within an acceptable
 * clock skew window to prevent delayed replay attacks.
 *
 * Priority: 8 (runs after IP check, before method allowlist)
 */
export class ReplayDetectorMiddleware implements SecurityMiddleware {
  readonly name = 'replay-detector';
  readonly priority = 8;
  readonly phase = 'request' as const;

  private enabled: boolean;
  private nonceTtlMs: number;
  private maxClockSkewMs: number;
  private requireNonce: boolean;

  // Track seen nonces with their expiry timestamps
  private seenNonces = new Map<string, number>();

  // Periodic cleanup of expired nonces
  private cleanupInterval: ReturnType<typeof setInterval>;

  constructor(options: {
    enabled: boolean;
    nonceTtlSeconds: number;
    maxClockSkew: number;
    requireNonce: boolean;
  }) {
    this.enabled = options.enabled;
    this.nonceTtlMs = options.nonceTtlSeconds * 1000;
    this.maxClockSkewMs = options.maxClockSkew * 1000;
    this.requireNonce = options.requireNonce;

    // Clean up expired nonces every 60 seconds
    this.cleanupInterval = setInterval(() => this.cleanup(), 60_000);
  }

  async evaluate(ctx: PipelineContext): Promise<SecurityDecision | null> {
    if (!this.enabled) return null;

    const params = ctx.request.params as Record<string, unknown> | undefined;
    const meta = params?._meta as Record<string, unknown> | undefined;

    const nonce = (meta?.nonce as string) ??
                  (ctx.metadata['nonce'] as string | undefined);
    const clientTimestamp = (meta?.timestamp as number) ??
                            (ctx.metadata['timestamp'] as number | undefined);

    // 1. Check nonce presence
    if (this.requireNonce && !nonce) {
      return {
        verdict: 'block',
        reason: 'Nonce required for replay protection but not provided',
        errorCode: -32001,
        metadata: { requireNonce: true },
      };
    }

    // If no nonce and not required, skip checks
    if (!nonce) return null;

    // 2. Validate nonce format (must be a reasonable string)
    if (typeof nonce !== 'string' || nonce.length < 8 || nonce.length > 256) {
      return {
        verdict: 'block',
        reason: 'Invalid nonce format',
        errorCode: -32001,
        metadata: { nonceLength: typeof nonce === 'string' ? nonce.length : 0 },
      };
    }

    // 3. Check timestamp validity
    if (clientTimestamp !== undefined) {
      const now = Date.now();
      const skew = Math.abs(now - clientTimestamp);

      if (skew > this.maxClockSkewMs) {
        return {
          verdict: 'block',
          reason: `Request timestamp skew (${skew}ms) exceeds maximum (${this.maxClockSkewMs}ms)`,
          errorCode: -32001,
          metadata: {
            requestTimestamp: new Date(clientTimestamp).toISOString(),
            serverTimestamp: new Date(now).toISOString(),
            skewMs: skew,
            maxSkewMs: this.maxClockSkewMs,
          },
        };
      }
    }

    // 4. Check if nonce has been seen before
    const nonceKey = `${ctx.client.clientId}:${nonce}`;
    const existingExpiry = this.seenNonces.get(nonceKey);

    if (existingExpiry !== undefined && existingExpiry > Date.now()) {
      return {
        verdict: 'block',
        reason: 'Duplicate nonce detected — possible replay attack',
        errorCode: -32001,
        metadata: {
          nonceHash: simpleHash(nonce),
          clientId: ctx.client.clientId,
        },
      };
    }

    // 5. Record the nonce
    this.seenNonces.set(nonceKey, Date.now() + this.nonceTtlMs);

    return null;
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [key, expiry] of this.seenNonces) {
      if (expiry <= now) {
        this.seenNonces.delete(key);
      }
    }
  }

  /**
   * Clear all tracked nonces (useful for testing or config reload).
   */
  reset(): void {
    this.seenNonces.clear();
  }

  destroy(): void {
    clearInterval(this.cleanupInterval);
    this.seenNonces.clear();
  }
}

/**
 * Simple non-cryptographic hash for nonce display in metadata.
 * We deliberately don't store the raw nonce in audit logs.
 */
function simpleHash(input: string): string {
  let hash = 0;
  for (let i = 0; i < input.length; i++) {
    const char = input.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash; // Convert to 32bit integer
  }
  return Math.abs(hash).toString(16).padStart(8, '0');
}

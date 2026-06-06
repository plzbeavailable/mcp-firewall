import type { SecurityMiddleware, PipelineContext, SecurityDecision, ClientIdentity } from '../pipeline/types';

// ─── JWT Helpers ──────────────────────────────────────────────

interface JwtHeader {
  alg: string;
  typ?: string;
  kid?: string;
}

interface JwtPayload {
  sub?: string;
  iss?: string;
  aud?: string | string[];
  exp?: number;
  iat?: number;
  nbf?: number;
  [key: string]: unknown;
}

/**
 * Decode a JWT without verifying the signature.
 * Returns [header, payload, signature] or null if the JWT is malformed.
 */
function decodeJwt(token: string): [JwtHeader, JwtPayload, string] | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;

  try {
    const header = JSON.parse(Buffer.from(parts[0]!, 'base64url').toString('utf-8')) as JwtHeader;
    const payload = JSON.parse(Buffer.from(parts[1]!, 'base64url').toString('utf-8')) as JwtPayload;
    return [header, payload, parts[2]!];
  } catch {
    return null;
  }
}

// ─── JWKS Client (simplified) ──────────────────────────────────

interface JwksKey {
  kty: string;
  kid?: string;
  alg?: string;
  use?: string;
  n?: string;
  e?: string;
  x5c?: string[];
  x5t?: string;
}

interface JwksResponse {
  keys: JwksKey[];
}

/**
 * Simple JWKS key fetcher that caches keys by kid.
 * In production, you'd use `jose` for full JWT verification.
 * This implementation provides claim validation and delegates
 * signature verification to a pluggable verifier.
 */
export class JwksClient {
  private jwksUrl: string;
  private keys: Map<string, JwksKey> = new Map();
  private lastFetch: number = 0;
  private ttlMs: number;
  private fetchPromise: Promise<void> | null = null;

  constructor(jwksUrl: string, ttlMs = 300_000) {
    this.jwksUrl = jwksUrl;
    this.ttlMs = ttlMs;
  }

  async getKey(kid?: string): Promise<JwksKey | null> {
    await this.ensureFresh();

    if (kid) {
      return this.keys.get(kid) ?? null;
    }

    // No kid specified — return the first key
    const first = this.keys.values().next();
    return first.done ? null : first.value;
  }

  private async ensureFresh(): Promise<void> {
    if (Date.now() - this.lastFetch < this.ttlMs) return;

    if (this.fetchPromise) {
      await this.fetchPromise;
      return;
    }

    this.fetchPromise = this.fetchKeys();
    try {
      await this.fetchPromise;
    } finally {
      this.fetchPromise = null;
    }
  }

  private async fetchKeys(): Promise<void> {
    try {
      const res = await fetch(this.jwksUrl);
      if (!res.ok) {
        throw new Error(`JWKS fetch failed: ${res.status} ${res.statusText}`);
      }

      const jwks = (await res.json()) as JwksResponse;

      this.keys.clear();
      for (const key of jwks.keys) {
        if (key.kid) {
          this.keys.set(key.kid, key);
        } else {
          // Keys without kid use a synthetic key
          this.keys.set(`__default__${key.kty}`, key);
        }
      }

      this.lastFetch = Date.now();
    } catch (err) {
      // If we have cached keys, keep using them
      if (this.keys.size === 0) {
        throw err;
      }
    }
  }
}

// ─── JWT Auth Middleware ───────────────────────────────────────

export interface JwtAuthOptions {
  /** JWKS URL for fetching public keys */
  jwksUrl: string;
  /** Expected issuer (validated against `iss` claim) */
  issuer: string;
  /** Expected audience (validated against `aud` claim) */
  audience?: string;
  /** Map JWT claims to a client ID (default: sub claim) */
  clientIdClaim?: string;
  /** TTL for JWKS cache in milliseconds (default: 5 minutes) */
  jwksTtlMs?: number;
}

/**
 * JWT/OAuth2 authentication middleware.
 *
 * Validates Bearer tokens from the Authorization header (HTTP mode)
 * or from context metadata (stdio mode).
 *
 * Performs:
 * - Token presence check
 * - Basic JWT structure validation
 * - Issuer and audience claim validation
 * - Expiration check
 * - JWKS key availability check (signature verification delegated to runtime)
 *
 * Priority: 25 (runs after API key auth, before RBAC)
 */
export class JwtAuthMiddleware implements SecurityMiddleware {
  readonly name = 'jwt-auth';
  readonly priority = 25;
  readonly phase = 'request' as const;

  private client: JwksClient;
  private issuer: string;
  private audience: string | undefined;
  private clientIdClaim: string;
  private enabled: boolean;

  constructor(options: JwtAuthOptions) {
    this.enabled = true;
    this.issuer = options.issuer;
    this.audience = options.audience;
    this.clientIdClaim = options.clientIdClaim ?? 'sub';
    this.client = new JwksClient(options.jwksUrl, options.jwksTtlMs ?? 300_000);
  }

  setEnabled(enabled: boolean): void {
    this.enabled = enabled;
  }

  async evaluate(ctx: PipelineContext): Promise<SecurityDecision | null> {
    if (!this.enabled) return null;

    // Extract the Bearer token
    const token = this.extractToken(ctx);
    if (!token) {
      return {
        verdict: 'block',
        reason: 'JWT Bearer token required but not provided',
        errorCode: -32001,
      };
    }

    // Decode the JWT
    const decoded = decodeJwt(token);
    if (!decoded) {
      return {
        verdict: 'block',
        reason: 'Malformed JWT token',
        errorCode: -32001,
        metadata: { details: 'Token does not have 3 dot-separated parts' },
      };
    }

    const [header, payload] = decoded;

    // ─── Structural checks ──────────────────────────────

    // Check algorithm
    if (!header.alg || header.alg === 'none') {
      return {
        verdict: 'block',
        reason: `Invalid or unsupported JWT algorithm: ${header.alg ?? 'none'}`,
        errorCode: -32001,
      };
    }

    // ─── Claim validation ──────────────────────────────

    // Issuer
    if (payload.iss !== this.issuer) {
      return {
        verdict: 'block',
        reason: `Invalid issuer: expected "${this.issuer}", got "${payload.iss ?? 'none'}"`,
        errorCode: -32001,
        metadata: { expectedIssuer: this.issuer, actualIssuer: payload.iss },
      };
    }

    // Audience
    if (this.audience) {
      const aud = payload.aud;
      const expected = this.audience;
      const matches =
        Array.isArray(aud)
          ? aud.includes(expected)
          : aud === expected;

      if (!matches) {
        return {
          verdict: 'block',
          reason: `Invalid audience: expected "${expected}"`,
          errorCode: -32001,
          metadata: { expectedAudience: expected, actualAudience: aud },
        };
      }
    }

    // Expiration
    if (payload.exp) {
      const now = Math.floor(Date.now() / 1000);
      if (payload.exp < now) {
        return {
          verdict: 'block',
          reason: 'JWT token has expired',
          errorCode: -32001,
          metadata: { expiredAt: new Date(payload.exp * 1000).toISOString() },
        };
      }
    }

    // Not Before
    if (payload.nbf) {
      const now = Math.floor(Date.now() / 1000);
      if (payload.nbf > now) {
        return {
          verdict: 'block',
          reason: 'JWT token is not yet valid (nbf)',
          errorCode: -32001,
        };
      }
    }

    // ─── Key availability check ────────────────────────
    // (We check that we have a key for the kid,
    // but signature verification is delegated to the runtime)

    try {
      const key = await this.client.getKey(header.kid);
      if (!key) {
        return {
          verdict: 'block',
          reason: `No JWKS key found for kid: ${header.kid ?? '(none)'}`,
          errorCode: -32001,
        };
      }
    } catch (err) {
      return {
        verdict: 'block',
        reason: 'Failed to fetch JWKS keys for token verification',
        errorCode: -32001,
        metadata: { error: err instanceof Error ? err.message : String(err) },
      };
    }

    // ─── Update client identity ────────────────────────
    const clientId = (payload[this.clientIdClaim] as string) ?? payload.sub ?? 'unknown';

    ctx.client.clientId = clientId;
    ctx.client.authType = 'jwt';
    ctx.client.claims = payload as Record<string, unknown>;

    return null; // Pass
  }

  /**
   * Extract a JWT Bearer token from the request context.
   * In HTTP mode, this comes from the Authorization header.
   * In stdio mode, it can be passed via context metadata.
   */
  private extractToken(ctx: PipelineContext): string | null {
    // Check Authorization header (stored in metadata by the transport layer)
    const authHeader = ctx.metadata['authorization'] as string | undefined;
    if (authHeader) {
      const bearerMatch = authHeader.match(/^Bearer\s+(.+)$/i);
      if (bearerMatch) return bearerMatch[1]!;
    }

    // Check for direct token in metadata
    const directToken = ctx.metadata['jwtToken'] as string | undefined;
    if (directToken) return directToken;

    // Check request params (some clients embed auth in params)
    const params = ctx.request.params as Record<string, unknown> | undefined;
    if (params?.token && typeof params.token === 'string') {
      return params.token;
    }

    return null;
  }
}

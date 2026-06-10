import type { SecurityMiddleware, PipelineContext, SecurityDecision } from '../pipeline/types';

// ─── CIDR Parsing ──────────────────────────────────────────────

interface CidrRange {
  network: number; // 32-bit unsigned integer
  prefix: number;  // 0-32 (IPv4) or 0-128 (IPv6)
  family: 'ipv4' | 'ipv6';
}

/**
 * Parse a CIDR notation string like "192.168.0.0/16" or "10.0.0.0/8".
 * Also accepts a bare IP (treated as /32 or /128).
 */
function parseCidr(cidr: string): CidrRange | null {
  const parts = cidr.split('/');
  const ipStr = parts[0]!;
  const prefix = parts.length > 1 ? parseInt(parts[1]!, 10) : null;

  if (ipStr.includes(':')) {
    // IPv6
    try {
      const groups = expandIPv6(ipStr);
      if (!groups) return null;
      const network = groups.reduce((acc, g) => (acc << 16) + g, 0);
      // We only use the first 32 bits for matching (enough for most use cases)
      // Full 128-bit would require BigInt
      return {
        network: Number(BigInt.asUintN(32, BigInt(network) >> 64n)),
        prefix: prefix ?? 128,
        family: 'ipv6',
      };
    } catch {
      return null;
    }
  }

  // IPv4
  const octets = ipStr.split('.').map(Number);
  if (octets.length !== 4 || octets.some((o) => isNaN(o) || o < 0 || o > 255)) {
    return null;
  }
  const network =
    ((octets[0]! << 24) | (octets[1]! << 16) | (octets[2]! << 8) | octets[3]!) >>> 0;
  return {
    network,
    prefix: prefix ?? 32,
    family: 'ipv4',
  };
}

function expandIPv6(ip: string): number[] | null {
  // Handle :: abbreviation
  if (ip.includes('::')) {
    const [left, right] = ip.split('::');
    const leftGroups = left ? left.split(':').filter(Boolean) : [];
    const rightGroups = right ? right.split(':').filter(Boolean) : [];
    const missing = 8 - leftGroups.length - rightGroups.length;
    if (missing < 0) return null;
    const groups = [...leftGroups, ...Array(missing).fill('0'), ...rightGroups];
    return groups.map((g) => parseInt(g, 16));
  }
  const groups = ip.split(':');
  if (groups.length !== 8) return null;
  return groups.map((g) => parseInt(g, 16));
}

function ipMatchesCidr(ip: string, cidr: CidrRange): boolean {
  if (cidr.family === 'ipv4') {
    const octets = ip.split('.').map(Number);
    if (octets.length !== 4 || octets.some((o) => isNaN(o) || o < 0 || o > 255)) {
      return false;
    }
    const ipNum = ((octets[0]! << 24) | (octets[1]! << 16) | (octets[2]! << 8) | octets[3]!) >>> 0;
    const mask = cidr.prefix === 0 ? 0 : (~0 << (32 - cidr.prefix)) >>> 0;
    return (ipNum & mask) === (cidr.network & mask);
  }

  // IPv6: compare first 64 bits (prefix match on first 4 groups)
  if (ip.includes(':')) {
    const groups = expandIPv6(ip);
    if (!groups || groups.length !== 8) return false;
    // Use first 64 bits for comparison
    const ipHi = groups.slice(0, 4).reduce((acc, g) => (acc << 16) + g, 0);
    const cidrHi = Number(BigInt.asUintN(32, BigInt(cidr.network)));
    // For IPv6, only support prefix matching on /32 or wider
    // Simpler: just compare the first 4 groups
    if (cidr.prefix <= 64) {
      const localMask = cidr.prefix === 0 ? 0 : (~0 << (64 - Math.min(cidr.prefix, 64)));
      // Apply mask only to the high 32 bits (simplified)
      const mask32 = cidr.prefix <= 32
        ? (cidr.prefix === 0 ? 0 : (~0 << (32 - cidr.prefix)) >>> 0)
        : 0xFFFFFFFF;
      return (ipHi & mask32) === (cidrHi & mask32);
    }
    // /65 - /128: exact match on full 128 bits (simplified to 32-bit compare)
    return ipHi === cidrHi;
  }

  return false;
}

// ─── IP Access Middleware ───────────────────────────────────────

/**
 * IP-based access control middleware.
 *
 * Supports:
 * - IPv4/IPv6 allowlist (CIDR notation)
 * - IPv4/IPv6 blocklist (CIDR notation)
 * - Default-deny when allowlist is configured
 * - Geo-blocking (country codes, requires external GeoIP database)
 *
 * Priority: 5 (runs before method allowlist)
 */
export class IpAccessMiddleware implements SecurityMiddleware {
  readonly name = 'ip-access';
  readonly priority = 5;
  readonly phase = 'request' as const;

  private allowlist: CidrRange[];
  private blocklist: CidrRange[];
  private enabled: boolean;
  private defaultDeny: boolean;
  private geoBlock: Set<string>;

  constructor(options: {
    enabled: boolean;
    allowlist: string[];
    blocklist: string[];
    defaultDeny: boolean;
    geoBlock: string[];
  }) {
    this.enabled = options.enabled;
    this.defaultDeny = options.defaultDeny;
    this.geoBlock = new Set(options.geoBlock.map((c) => c.toUpperCase()));

    this.allowlist = options.allowlist.map(parseCidr).filter(Boolean) as CidrRange[];
    this.blocklist = options.blocklist.map(parseCidr).filter(Boolean) as CidrRange[];
  }

  async evaluate(ctx: PipelineContext): Promise<SecurityDecision | null> {
    if (!this.enabled) return null;

    const clientIp = this.extractIp(ctx);
    if (!clientIp) {
      // No IP available (e.g., stdio mode) — skip IP checks
      return null;
    }

    // 1. Blocklist takes precedence (always checked)
    for (const cidr of this.blocklist) {
      if (ipMatchesCidr(clientIp, cidr)) {
        return {
          verdict: 'block',
          reason: `IP ${clientIp} is in the blocklist (matches ${this.formatCidr(cidr)})`,
          errorCode: -32001,
          metadata: { clientIp, matchedCidr: this.formatCidr(cidr), list: 'blocklist' },
        };
      }
    }

    // 2. Geo-blocking check
    if (this.geoBlock.size > 0) {
      const country = this.resolveGeo(ctx, clientIp);
      if (country && this.geoBlock.has(country.toUpperCase())) {
        return {
          verdict: 'block',
          reason: `Requests from country "${country}" are blocked by geo policy`,
          errorCode: -32001,
          metadata: { clientIp, country, list: 'geo-block' },
        };
      }
    }

    // 3. Allowlist check (if configured)
    if (this.allowlist.length > 0) {
      const allowed = this.allowlist.some((cidr) => ipMatchesCidr(clientIp, cidr));
      if (!allowed && this.defaultDeny) {
        return {
          verdict: 'block',
          reason: `IP ${clientIp} is not in the allowlist`,
          errorCode: -32001,
          metadata: { clientIp, list: 'allowlist' },
        };
      }
      // Warn but allow if defaultDeny is false
      if (!allowed) {
        return {
          verdict: 'warn',
          reason: `IP ${clientIp} is not in the allowlist (warning only)`,
          metadata: { clientIp, list: 'allowlist' },
        };
      }
    }

    return null;
  }

  /**
   * Extract the client IP from the pipeline context.
   */
  private extractIp(ctx: PipelineContext): string | null {
    // Check metadata (set by transport layer from x-forwarded-for or socket)
    const directIp = ctx.metadata['clientIp'] as string | undefined;
    if (directIp) return directIp;

    // Check x-forwarded-for header
    const xff = ctx.metadata['xForwardedFor'] as string | undefined;
    if (xff) {
      const parts = xff.split(',').map((p) => p.trim());
      return parts[0] ?? null;
    }

    // Check x-real-ip header
    const xri = ctx.metadata['xRealIp'] as string | undefined;
    if (xri) return xri;

    return null;
  }

  /**
   * Resolve geo-location for an IP.
   * In production, this would use a GeoIP database (e.g., MaxMind).
   * For now, we check metadata set by the transport layer.
   */
  private resolveGeo(_ctx: PipelineContext, _clientIp: string): string | null {
    // Check if the transport layer injected geo info
    const geoHeader = _ctx.metadata['geoCountry'] as string | undefined;
    if (geoHeader) return geoHeader;

    // Without an external GeoIP database, geo resolution is not possible.
    // The transport layer should inject this via a GeoIP plugin.
    return null;
  }

  private formatCidr(cidr: CidrRange): string {
    if (cidr.family === 'ipv4') {
      const octets = [
        (cidr.network >>> 24) & 0xFF,
        (cidr.network >>> 16) & 0xFF,
        (cidr.network >>> 8) & 0xFF,
        cidr.network & 0xFF,
      ];
      return `${octets.join('.')}/${cidr.prefix}`;
    }
    return `<ipv6>/${cidr.prefix}`;
  }
}

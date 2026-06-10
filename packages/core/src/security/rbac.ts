import type { SecurityMiddleware, PipelineContext, SecurityDecision } from '../pipeline/types';
import type { RBACRule } from '@ziwansi/mcp-firewall-config';

// Re-define the types we need locally to avoid Zod inference issues
type PrincipalType = 'api-key' | 'jwt-claim' | 'client-id';
type Permission = 'allow' | 'deny';

interface LocalPrincipalMatcher {
  type: PrincipalType;
  pattern: string;
}

interface LocalTargetMatcher {
  serverName?: string;
  toolName?: string;
  method?: string;
}

/**
 * RBAC (Role-Based Access Control) middleware.
 *
 * Evaluates each request against a set of RBAC rules.
 * Each rule defines:
 * - principals: who the rule applies to (matched by client-id, api-key, or jwt-claim)
 * - targets: what the rule covers (matched by serverName, toolName, method)
 * - permission: 'allow' or 'deny'
 *
 * Rules are evaluated in order. The first matching 'deny' rule wins.
 * If no rule matches, the default is 'allow' (unless a default-deny
 * configuration is set).
 *
 * Priority: 30
 */
export class RbacMiddleware implements SecurityMiddleware {
  readonly name = 'rbac';
  readonly priority = 30;
  readonly phase = 'request' as const;

  private rules: CompiledRbacRule[];
  private defaultAllow: boolean;

  constructor(rules: RBACRule[], defaultAllow = true) {
    this.defaultAllow = defaultAllow;
    this.rules = rules.map(compileRule);
  }

  async evaluate(ctx: PipelineContext): Promise<SecurityDecision | null> {
    if (this.rules.length === 0) return null;

    let matchedAny = false;

    for (const rule of this.rules) {
      // Check if this principal matches
      const principalMatch = rule.principals.some((p) => matchPrincipal(p, ctx));
      if (!principalMatch) continue;

      // Check if this target matches
      const targetMatch = rule.targets.some((t) => matchTarget(t, ctx));
      if (!targetMatch) continue;

      matchedAny = true;

      if (rule.permission === 'deny') {
        return {
          verdict: 'block',
          reason: `Access denied by RBAC rule "${rule.name}"`,
          errorCode: -32001,
          metadata: { ruleName: rule.name },
        };
      }

      // 'allow' — note the match and continue checking (a later deny could override)
    }

    if (!matchedAny && !this.defaultAllow) {
      return {
        verdict: 'block',
        reason: `No RBAC rule matches and default is deny`,
        errorCode: -32001,
      };
    }

    return null; // Pass
  }
}

// ─── Compiled rule types ──────────────────────────────────────

interface CompiledRbacRule {
  name: string;
  principals: CompiledPrincipalMatcher[];
  targets: CompiledTargetMatcher[];
  permission: 'allow' | 'deny';
}

interface CompiledPrincipalMatcher {
  type: PrincipalType;
  regex: RegExp;
}

interface CompiledTargetMatcher {
  serverNameRegex?: RegExp;
  toolNameRegex?: RegExp;
  methodRegex?: RegExp;
}

// ─── Rule compilation ─────────────────────────────────────────

function compileRule(rule: RBACRule): CompiledRbacRule {
  return {
    name: rule.name,
    principals: rule.principals.map(compilePrincipal),
    targets: rule.targets.map(compileTarget),
    permission: rule.permission,
  };
}

function compilePrincipal(p: { type: PrincipalType; pattern: string }): CompiledPrincipalMatcher {
  return {
    type: p.type,
    regex: globToRegex(p.pattern),
  };
}

function compileTarget(t: { serverName?: string; toolName?: string; method?: string }): CompiledTargetMatcher {
  return {
    serverNameRegex: t.serverName ? globToRegex(t.serverName) : undefined,
    toolNameRegex: t.toolName ? globToRegex(t.toolName) : undefined,
    methodRegex: t.method ? globToRegex(t.method) : undefined,
  };
}

// ─── Matching ─────────────────────────────────────────────────

function matchPrincipal(p: CompiledPrincipalMatcher, ctx: PipelineContext): boolean {
  switch (p.type) {
    case 'client-id':
      return p.regex.test(ctx.client.clientId);
    case 'api-key':
      // API key matching is done via the api-key auth middleware;
      // here we match on the extracted client ID
      return ctx.client.authType === 'api-key' && p.regex.test(ctx.client.clientId);
    case 'jwt-claim': {
      if (!ctx.client.claims) return false;
      // Check if any claim value matches the pattern
      return Object.values(ctx.client.claims).some((v) => {
        if (typeof v === 'string') return p.regex.test(v);
        return false;
      });
    }
    default:
      return false;
  }
}

function matchTarget(t: CompiledTargetMatcher, ctx: PipelineContext): boolean {
  if (t.serverNameRegex && !t.serverNameRegex.test(ctx.serverName)) return false;
  if (t.toolNameRegex && (!ctx.toolName || !t.toolNameRegex.test(ctx.toolName))) return false;
  if (t.methodRegex && !t.methodRegex.test(ctx.method)) return false;
  return true;
}

// ─── Glob → Regex ─────────────────────────────────────────────

/**
 * Convert a glob pattern (with * and ** wildcards) to a RegExp.
 */
function globToRegex(pattern: string): RegExp {
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&') // Escape regex special chars
    .replace(/\*\*/g, '__DOUBLE_STAR__') // Placeholder for **
    .replace(/\*/g, '[^/]*') // * matches anything except /
    .replace(/__DOUBLE_STAR__/g, '.*'); // ** matches everything
  return new RegExp(`^${escaped}$`);
}

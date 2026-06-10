import { z } from 'zod';

// ─── Transport mode ────────────────────────────────────────────

export const TransportMode = z.enum(['stdio', 'http']);
export type TransportMode = z.infer<typeof TransportMode>;

// ─── HTTP server config ────────────────────────────────────────

export const ServerConfig = z.object({
  host: z.string().default('127.0.0.1'),
  port: z.number().int().min(1).max(65535).default(9020),
  cors: z
    .object({
      enabled: z.boolean().default(false),
      origins: z.array(z.string()).default(['http://localhost:5173']),
    })
    .default({}),
});
export type ServerConfig = z.infer<typeof ServerConfig>;

// ─── Upstream MCP server config ────────────────────────────────

export const UpstreamTransport = z.discriminatedUnion('transport', [
  z.object({
    transport: z.literal('stdio'),
    name: z.string(),
    command: z.string(),
    args: z.array(z.string()).default([]),
    env: z.record(z.string(), z.string()).default({}),
    healthCheck: z
      .object({
        enabled: z.boolean().default(true),
        interval: z.string().default('30s'),
      })
      .default({}),
  }),
  z.object({
    transport: z.literal('streamable-http'),
    name: z.string(),
    url: z.string().url(),
    headers: z.record(z.string(), z.string()).default({}),
    healthCheck: z
      .object({
        enabled: z.boolean().default(true),
        interval: z.string().default('15s'),
      })
      .default({}),
  }),
  z.object({
    transport: z.literal('sse'),
    name: z.string(),
    url: z.string().url(),
    headers: z.record(z.string(), z.string()).default({}),
    healthCheck: z
      .object({
        enabled: z.boolean().default(true),
        interval: z.string().default('15s'),
      })
      .default({}),
  }),
]);
export type UpstreamTransport = z.infer<typeof UpstreamTransport>;

// ─── Authentication config ─────────────────────────────────────

export const AuthConfig = z.object({
  enabled: z.boolean().default(false),
  providers: z
    .array(
      z.discriminatedUnion('type', [
        z.object({
          type: z.literal('api-key'),
          keys: z
            .array(
              z.object({
                key: z.string(),
                clientId: z.string(),
              }),
            )
            .default([]),
        }),
        z.object({
          type: z.literal('oauth2'),
          jwksUrl: z.string().url(),
          issuer: z.string(),
          audience: z.string(),
        }),
      ]),
    )
    .default([]),
});
export type AuthConfig = z.infer<typeof AuthConfig>;

// ─── Policy config ─────────────────────────────────────────────

export const GlobPattern = z.string();

export const PrincipalMatcher = z.object({
  type: z.enum(['api-key', 'jwt-claim', 'client-id']),
  pattern: GlobPattern,
});

export const TargetMatcher = z.object({
  serverName: GlobPattern.optional(),
  toolName: GlobPattern.optional(),
  method: z.string().optional(),
});

export const RBACRule = z.object({
  name: z.string(),
  principals: z.array(PrincipalMatcher).min(1),
  targets: z.array(TargetMatcher).min(1),
  permission: z.enum(['allow', 'deny']),
});
export type RBACRule = z.infer<typeof RBACRule>;

export const RateLimitRule = z.object({
  name: z.string(),
  window: z.string().default('1m'),
  maxRequests: z.number().int().positive().default(100),
  keyBy: z.array(z.enum(['client-id', 'api-key', 'tool-name', 'server-name'])).min(1),
  strategy: z.enum(['sliding-window', 'token-bucket']).default('sliding-window'),
  burstMultiplier: z.number().min(1).default(1),
});
export type RateLimitRule = z.infer<typeof RateLimitRule>;

export const ContentFilterRule = z.object({
  pattern: z.string(),
  action: z.enum(['block', 'mask', 'log']),
  phase: z.enum(['input', 'output', 'both']),
});

export const SensitiveDataDetector = z.object({
  type: z.enum(['credit-card', 'api-key', 'email', 'jwt', 'phone', 'ssn', 'private-key', 'connection-string', 'custom']),
  action: z.enum(['block', 'mask', 'log']),
  name: z.string().optional(),
  pattern: z.string().optional(),
});

export const PolicyConfig = z.object({
  methodAllowlist: z
    .object({
      enabled: z.boolean().default(true),
      allowedMethods: z
        .array(z.string())
        .default([
          'initialize',
          'ping',
          'tools/list',
          'tools/call',
          'resources/list',
          'resources/read',
          'prompts/list',
          'prompts/get',
        ]),
      blockUnknown: z.boolean().default(true),
    })
    .default({}),
  rbac: z
    .object({
      enabled: z.boolean().default(false),
      rules: z.array(RBACRule).default([]),
      defaultDeny: z.boolean().default(false),
    })
    .default({}),
  rateLimiting: z
    .object({
      enabled: z.boolean().default(false),
      rules: z.array(RateLimitRule).default([]),
    })
    .default({}),
  parameterValidation: z
    .object({
      enabled: z.boolean().default(true),
      strictMode: z.boolean().default(false),
      maxDepth: z.number().int().min(1).max(50).default(10),
      maxStringLength: z.number().int().min(1).default(1_048_576),
    })
    .default({}),
  contentFilter: z
    .object({
      enabled: z.boolean().default(false),
      rules: z.array(ContentFilterRule).default([]),
    })
    .default({}),
  sensitiveData: z
    .object({
      enabled: z.boolean().default(true),
      detectors: z.array(SensitiveDataDetector).default([]),
    })
    .default({}),
  ipAccess: z
    .object({
      enabled: z.boolean().default(false),
      allowlist: z.array(z.string()).default([]),
      blocklist: z.array(z.string()).default([]),
      /** Block by default when only allowlist is configured (default: true) */
      defaultDeny: z.boolean().default(true),
      /** Enable geolocation-based blocking (requires GeoIP database) */
      geoBlock: z.array(z.string()).default([]),
    })
    .default({}),
  responseLimits: z
    .object({
      enabled: z.boolean().default(false),
      /** Maximum response size in bytes (default: 10 MB) */
      maxResponseSize: z.number().int().positive().default(10_485_760),
      /** Max number of items in a list result (default: 1000) */
      maxItems: z.number().int().positive().default(1000),
      /** Max nesting depth of response objects (default: 20) */
      maxResponseDepth: z.number().int().min(1).max(100).default(20),
    })
    .default({}),
  concurrencyLimit: z
    .object({
      enabled: z.boolean().default(false),
      /** Max concurrent requests per client (default: 10) */
      maxConcurrent: z.number().int().positive().default(10),
      /** Max concurrent requests per tool (default: 50) */
      maxConcurrentPerTool: z.number().int().positive().default(50),
      /** Queue excess requests instead of rejecting (default: false) */
      queueEnabled: z.boolean().default(false),
      /** Max queue size per client (default: 100) */
      maxQueueSize: z.number().int().positive().default(100),
    })
    .default({}),
  replayDetection: z
    .object({
      enabled: z.boolean().default(false),
      /** Nonce TTL in seconds (default: 300 = 5 minutes) */
      nonceTtlSeconds: z.number().int().positive().default(300),
      /** Max clock skew in seconds for timestamp validation (default: 30) */
      maxClockSkew: z.number().int().min(0).default(30),
      /** Require nonce in every tools/call request */
      requireNonce: z.boolean().default(true),
    })
    .default({}),
  threatScoring: z
    .object({
      enabled: z.boolean().default(false),
      /** Score at which the request is blocked (default: 80 out of 100) */
      blockThreshold: z.number().int().min(1).max(100).default(80),
      /** Score at which a warning is issued (default: 50) */
      warnThreshold: z.number().int().min(1).max(100).default(50),
      /** Weight for each security layer in the aggregate score */
      weights: z
        .object({
          injectionDetection: z.number().min(0).max(1).default(0.3),
          rateLimiting: z.number().min(0).max(1).default(0.15),
          contentFilter: z.number().min(0).max(1).default(0.25),
          ipReputation: z.number().min(0).max(1).default(0.1),
          replayDetection: z.number().min(0).max(1).default(0.1),
          concurrency: z.number().min(0).max(1).default(0.1),
        })
        .default({}),
    })
    .default({}),
});
export type PolicyConfig = z.infer<typeof PolicyConfig>;
// Convenience type aliases for sub-configs
export type IpAccessConfig = PolicyConfig['ipAccess'];
export type ResponseLimitsConfig = PolicyConfig['responseLimits'];
export type ConcurrencyLimitConfig = PolicyConfig['concurrencyLimit'];
export type ReplayDetectionConfig = PolicyConfig['replayDetection'];
export type ThreatScoringConfig = PolicyConfig['threatScoring'];

// ─── Observability config ──────────────────────────────────────

export const ObservabilityConfig = z.object({
  metrics: z
    .object({
      enabled: z.boolean().default(true),
      port: z.number().int().min(1).max(65535).default(9090),
      path: z.string().default('/metrics'),
    })
    .default({}),
  tracing: z
    .object({
      enabled: z.boolean().default(false),
      exporter: z.enum(['otlp', 'console', 'none']).default('otlp'),
      endpoint: z.string().default('http://localhost:4318/v1/traces'),
      sampleRate: z.number().min(0).max(1).default(0.1),
    })
    .default({}),
  auditLog: z
    .object({
      enabled: z.boolean().default(true),
      output: z.enum(['stdout', 'file', 'sqlite', 'postgres']).default('stdout'),
      file: z.string().default('audit.log'),
      format: z.enum(['jsonl', 'json']).default('jsonl'),
    })
    .default({}),
  tokenTracking: z
    .object({
      enabled: z.boolean().default(true),
      estimationMode: z.enum(['conservative', 'aggressive', 'custom']).default('conservative'),
    })
    .default({}),
});
export type ObservabilityConfig = z.infer<typeof ObservabilityConfig>;

// ─── Database config ───────────────────────────────────────────

export const DatabaseConfig = z.object({
  type: z.enum(['sqlite', 'postgres']).default('sqlite'),
  sqlite: z
    .object({
      path: z.string().default('./data/mcp-firewall.db'),
    })
    .default({}),
  postgres: z
    .object({
      host: z.string().default('localhost'),
      port: z.number().int().min(1).max(65535).default(5432),
      database: z.string().default('mcp_firewall'),
      user: z.string().default('mcp_firewall'),
      password: z.string().default(''),
      pool: z
        .object({
          min: z.number().int().min(1).default(2),
          max: z.number().int().min(1).default(10),
        })
        .default({}),
    })
    .default({}),
});
export type DatabaseConfig = z.infer<typeof DatabaseConfig>;

// ─── Sandbox config ────────────────────────────────────────────

export const SandboxConfig = z.object({
  enabled: z.boolean().default(false),
  provider: z.enum(['docker']).default('docker'),
  image: z.string().default('mcp-firewall/sandbox:latest'),
  network: z.string().default('none'),
  memoryLimit: z.string().default('512m'),
  cpuLimit: z.string().default('1.0'),
  timeout: z.string().default('30s'),
  volumeMounts: z.array(z.string()).default([]),
});
export type SandboxConfig = z.infer<typeof SandboxConfig>;

// ─── Dashboard config ──────────────────────────────────────────

export const DashboardConfig = z.object({
  enabled: z.boolean().default(true),
  host: z.string().default('127.0.0.1'),
  port: z.number().int().min(1).max(65535).default(9021),
  authToken: z.string().optional(),
});
export type DashboardConfig = z.infer<typeof DashboardConfig>;

// ─── Root config schema ────────────────────────────────────────

export const FirewallConfigSchema = z.object({
  version: z.literal('1'),
  mode: TransportMode.default('stdio'),
  server: ServerConfig.default({}),
  upstreams: z.array(UpstreamTransport).min(1),
  auth: AuthConfig.default({}),
  policies: PolicyConfig.default({}),
  observability: ObservabilityConfig.default({}),
  database: DatabaseConfig.default({}),
  sandbox: SandboxConfig.default({}),
  dashboard: DashboardConfig.default({}),
});
export type FirewallConfig = z.infer<typeof FirewallConfigSchema>;

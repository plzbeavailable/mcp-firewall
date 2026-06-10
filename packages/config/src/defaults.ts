import { FirewallConfig } from './schema';

/**
 * Sensible defaults for a production-adjacent configuration.
 * These get merged with user-provided config during loading.
 */
export const DEFAULT_CONFIG: Partial<FirewallConfig> = {
  mode: 'stdio',
  server: {
    host: '127.0.0.1',
    port: 9020,
    cors: {
      enabled: false,
      origins: ['http://localhost:5173'],
    },
  },
  auth: {
    enabled: false,
    providers: [],
  },
  policies: {
    methodAllowlist: {
      enabled: true,
      allowedMethods: [
        'initialize',
        'ping',
        'tools/list',
        'tools/call',
        'resources/list',
        'resources/read',
        'prompts/list',
        'prompts/get',
      ],
      blockUnknown: true,
    },
    rbac: {
      enabled: false,
      rules: [],
      defaultDeny: false,
    },
    rateLimiting: {
      enabled: false,
      rules: [],
    },
    parameterValidation: {
      enabled: true,
      strictMode: false,
      maxDepth: 10,
      maxStringLength: 1_048_576,
    },
    contentFilter: {
      enabled: false,
      rules: [],
    },
    sensitiveData: {
      enabled: true,
      detectors: [
        { type: 'credit-card', action: 'mask' },
        { type: 'api-key', action: 'mask' },
        { type: 'jwt', action: 'mask' },
        { type: 'email', action: 'mask' },
        { type: 'phone', action: 'mask' },
        { type: 'ssn', action: 'mask' },
        { type: 'private-key', action: 'block' },
        { type: 'connection-string', action: 'block' },
      ],
    },
    ipAccess: {
      enabled: false,
      allowlist: [],
      blocklist: [],
      defaultDeny: true,
      geoBlock: [],
    },
    responseLimits: {
      enabled: false,
      maxResponseSize: 10_485_760,
      maxItems: 1000,
      maxResponseDepth: 20,
    },
    concurrencyLimit: {
      enabled: false,
      maxConcurrent: 10,
      maxConcurrentPerTool: 50,
      queueEnabled: false,
      maxQueueSize: 100,
    },
    replayDetection: {
      enabled: false,
      nonceTtlSeconds: 300,
      maxClockSkew: 30,
      requireNonce: true,
    },
    threatScoring: {
      enabled: false,
      blockThreshold: 80,
      warnThreshold: 50,
      weights: {
        injectionDetection: 0.3,
        rateLimiting: 0.15,
        contentFilter: 0.25,
        ipReputation: 0.1,
        replayDetection: 0.1,
        concurrency: 0.1,
      },
    },
  },
  observability: {
    metrics: {
      enabled: true,
      port: 9090,
      path: '/metrics',
    },
    tracing: {
      enabled: false,
      exporter: 'otlp',
      endpoint: 'http://localhost:4318/v1/traces',
      sampleRate: 0.1,
    },
    auditLog: {
      enabled: true,
      output: 'stdout',
      file: 'audit.log',
      format: 'jsonl',
    },
    tokenTracking: {
      enabled: true,
      estimationMode: 'conservative',
    },
  },
  database: {
    type: 'sqlite',
    sqlite: {
      path: './data/mcp-firewall.db',
    },
    postgres: {
      host: 'localhost',
      port: 5432,
      database: 'mcp_firewall',
      user: 'mcp_firewall',
      password: '',
      pool: {
        min: 2,
        max: 10,
      },
    },
  },
  sandbox: {
    enabled: false,
    provider: 'docker',
    image: 'mcp-firewall/sandbox:latest',
    network: 'none',
    memoryLimit: '512m',
    cpuLimit: '1.0',
    timeout: '30s',
    volumeMounts: [],
  },
  dashboard: {
    enabled: true,
    host: '127.0.0.1',
    port: 9021,
  },
};

/**
 * Generate a minimal default firewall config for `mcp-firewall init`.
 */
export function generateDefaultConfig(upstreamName: string, upstreamCommand: string): FirewallConfig {
  return {
    version: '1',
    mode: 'stdio',
    server: {
      host: '127.0.0.1',
      port: 9020,
      cors: {
        enabled: false,
        origins: ['http://localhost:5173'],
      },
    },
    upstreams: [
      {
        transport: 'stdio' as const,
        name: upstreamName,
        command: upstreamCommand,
        args: [],
        env: {},
        healthCheck: {
          enabled: true,
          interval: '30s',
        },
      },
    ],
    auth: { enabled: false, providers: [] },
    policies: DEFAULT_CONFIG.policies!,
    observability: DEFAULT_CONFIG.observability!,
    database: DEFAULT_CONFIG.database!,
    sandbox: DEFAULT_CONFIG.sandbox!,
    dashboard: DEFAULT_CONFIG.dashboard!,
  };
}

export { FirewallConfigSchema, type FirewallConfig } from './schema';
export type {
  TransportMode,
  ServerConfig,
  UpstreamTransport,
  AuthConfig,
  RBACRule,
  RateLimitRule,
  ContentFilterRule,
  SensitiveDataDetector,
  PolicyConfig,
  ObservabilityConfig,
  DatabaseConfig,
  SandboxConfig,
  DashboardConfig,
  PrincipalMatcher,
  TargetMatcher,
} from './schema';

export { DEFAULT_CONFIG, generateDefaultConfig } from './defaults';
export { loadConfig, loadConfigFromString, validateConfig, type LoadResult } from './loader';
export { interpolateEnv } from './interpolate';
export { createConfigWatcher, onConfigReload, type HotReloadEvents } from './hot-reload';

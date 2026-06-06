import type { FirewallConfig } from '@mcp-firewall/config';
import { MethodAllowlistMiddleware } from '../security/method-allowlist';
import { ApiKeyAuthMiddleware, ApiKeyEntry } from '../security/api-key-auth';
import { RbacMiddleware } from '../security/rbac';
import { RateLimiterMiddleware } from '../security/rate-limiter';
import { ParameterValidationMiddleware, ToolSchemaCache } from '../security/parameter-validator';
import { ContentFilterMiddleware } from '../security/content-filter';
import { SensitiveDataMiddleware } from '../security/sensitive-data';
import { Pipeline } from '../pipeline/pipeline';

/**
 * The PolicyEngine compiles user-facing FirewallConfig into
 * an optimized, ready-to-run Pipeline with all middlewares registered.
 *
 * Call `engine.reload(newConfig)` to hot-reload policies.
 */
export class PolicyEngine {
  private pipeline: Pipeline;
  private rateLimiter: RateLimiterMiddleware | null = null;
  private sensitiveData: SensitiveDataMiddleware | null = null;
  private toolSchemaCache: ToolSchemaCache;

  constructor(config: FirewallConfig, toolSchemaCache?: ToolSchemaCache) {
    this.pipeline = new Pipeline();
    this.toolSchemaCache = toolSchemaCache ?? new ToolSchemaCache();
    this.compile(config);
  }

  /**
   * Get the underlying Pipeline for request/response evaluation.
   */
  getPipeline(): Pipeline {
    return this.pipeline;
  }

  /**
   * Hot-reload: recompile all policies from a new config
   * and atomically swap the active pipeline.
   */
  reload(config: FirewallConfig): void {
    // Clean up old rate limiter
    if (this.rateLimiter) {
      this.rateLimiter.destroy();
    }

    const newPipeline = new Pipeline();
    this.compileInto(config, newPipeline);
    this.pipeline = newPipeline;
  }

  /**
   * Get the tool schema cache for registering schemas from tools/list.
   */
  getToolSchemaCache(): ToolSchemaCache {
    return this.toolSchemaCache;
  }

  /**
   * Get the current rate limiter for stats queries (may be null).
   */
  getRateLimiter(): RateLimiterMiddleware | null {
    return this.rateLimiter;
  }

  /**
   * Get the sensitive data middleware for manual masking (may be null).
   */
  getSensitiveData(): SensitiveDataMiddleware | null {
    return this.sensitiveData;
  }

  private compile(config: FirewallConfig): void {
    this.compileInto(config, this.pipeline);
  }

  private compileInto(config: FirewallConfig, pipeline: Pipeline): void {
    const policies = config.policies;

    // 1. Method Allowlist (priority 10)
    if (policies.methodAllowlist.enabled) {
      pipeline.register(
        new MethodAllowlistMiddleware(
          policies.methodAllowlist.allowedMethods,
          policies.methodAllowlist.blockUnknown,
        ),
      );
    }

    // 2. API Key Auth (priority 20)
    if (config.auth.enabled) {
      const apiKeyProvider = config.auth.providers.find((p) => p.type === 'api-key');
      if (apiKeyProvider && apiKeyProvider.type === 'api-key') {
        const entries: ApiKeyEntry[] = apiKeyProvider.keys.map((k) => ({
          key: k.key,
          clientId: k.clientId,
        }));
        pipeline.register(new ApiKeyAuthMiddleware(entries, true));
      }
    }

    // 3. RBAC (priority 30)
    if (policies.rbac.enabled && policies.rbac.rules.length > 0) {
      pipeline.register(new RbacMiddleware(policies.rbac.rules));
    }

    // 4. Rate Limiting (priority 40)
    if (policies.rateLimiting.enabled && policies.rateLimiting.rules.length > 0) {
      this.rateLimiter = new RateLimiterMiddleware(policies.rateLimiting.rules);
      pipeline.register(this.rateLimiter);
    }

    // 5. Parameter Validation (priority 50)
    if (policies.parameterValidation.enabled) {
      pipeline.register(
        new ParameterValidationMiddleware({
          enabled: true,
          strictMode: policies.parameterValidation.strictMode,
          maxStringLength: policies.parameterValidation.maxStringLength,
          schemaCache: this.toolSchemaCache,
        }),
      );
    }

    // 6. Content Filter (priority 60)
    if (policies.contentFilter.enabled && policies.contentFilter.rules.length > 0) {
      pipeline.register(
        new ContentFilterMiddleware(
          policies.contentFilter.rules.map((r) => ({
            pattern: r.pattern,
            action: r.action,
            phase: r.phase,
          })),
        ),
      );
    }

    // 7. Sensitive Data Detection (priority 120 — response phase)
    if (policies.sensitiveData.enabled && policies.sensitiveData.detectors.length > 0) {
      this.sensitiveData = new SensitiveDataMiddleware(
        policies.sensitiveData.detectors.map((d) => ({
          type: d.type,
          action: d.action,
          name: d.name,
          pattern: d.pattern,
        })),
      );
      pipeline.register(this.sensitiveData);
    }
  }
}

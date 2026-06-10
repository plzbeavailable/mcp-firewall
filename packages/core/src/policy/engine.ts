import type { FirewallConfig } from '@ziwansi/mcp-firewall-config';
import { MethodAllowlistMiddleware } from '../security/method-allowlist';
import { ApiKeyAuthMiddleware, ApiKeyEntry } from '../security/api-key-auth';
import { RbacMiddleware } from '../security/rbac';
import { RateLimiterMiddleware } from '../security/rate-limiter';
import { ParameterValidationMiddleware, ToolSchemaCache } from '../security/parameter-validator';
import { ContentFilterMiddleware } from '../security/content-filter';
import { SensitiveDataMiddleware } from '../security/sensitive-data';
import { IpAccessMiddleware } from '../security/ip-access';
import { ResponseLimiterMiddleware } from '../security/response-limiter';
import { ConcurrencyLimiterMiddleware } from '../security/concurrency-limiter';
import { ReplayDetectorMiddleware } from '../security/replay-detector';
import { ThreatScorerMiddleware } from '../security/threat-scorer';
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
  private concurrencyLimiter: ConcurrencyLimiterMiddleware | null = null;
  private replayDetector: ReplayDetectorMiddleware | null = null;
  private responseLimiter: ResponseLimiterMiddleware | null = null;
  private threatScorer: ThreatScorerMiddleware | null = null;
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
    // Clean up old replay detector
    if (this.replayDetector) {
      this.replayDetector.destroy();
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

  /**
   * Get the concurrency limiter for stats and release (may be null).
   */
  getConcurrencyLimiter(): ConcurrencyLimiterMiddleware | null {
    return this.concurrencyLimiter;
  }

  /**
   * Get the response limiter for stats queries (may be null).
   */
  getResponseLimiter(): ResponseLimiterMiddleware | null {
    return this.responseLimiter;
  }

  /**
   * Get the threat scorer for stats queries (may be null).
   */
  getThreatScorer(): ThreatScorerMiddleware | null {
    return this.threatScorer;
  }

  private compile(config: FirewallConfig): void {
    this.compileInto(config, this.pipeline);
  }

  private compileInto(config: FirewallConfig, pipeline: Pipeline): void {
    const policies = config.policies;

    // 0. IP Access Control (priority 5)
    if (policies.ipAccess.enabled) {
      pipeline.register(
        new IpAccessMiddleware({
          enabled: policies.ipAccess.enabled,
          allowlist: policies.ipAccess.allowlist,
          blocklist: policies.ipAccess.blocklist,
          defaultDeny: policies.ipAccess.defaultDeny,
          geoBlock: policies.ipAccess.geoBlock,
        }),
      );
    }

    // 0b. Replay Detection (priority 8)
    if (policies.replayDetection.enabled) {
      this.replayDetector = new ReplayDetectorMiddleware({
        enabled: policies.replayDetection.enabled,
        nonceTtlSeconds: policies.replayDetection.nonceTtlSeconds,
        maxClockSkew: policies.replayDetection.maxClockSkew,
        requireNonce: policies.replayDetection.requireNonce,
      });
      pipeline.register(this.replayDetector);
    }

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
      pipeline.register(new RbacMiddleware(policies.rbac.rules, !policies.rbac.defaultDeny));
    }

    // 4. Concurrency Limiter (priority 35)
    if (policies.concurrencyLimit.enabled) {
      this.concurrencyLimiter = new ConcurrencyLimiterMiddleware({
        enabled: policies.concurrencyLimit.enabled,
        maxConcurrent: policies.concurrencyLimit.maxConcurrent,
        maxConcurrentPerTool: policies.concurrencyLimit.maxConcurrentPerTool,
        queueEnabled: policies.concurrencyLimit.queueEnabled,
        maxQueueSize: policies.concurrencyLimit.maxQueueSize,
      });
      pipeline.register(this.concurrencyLimiter);
    }

    // 5. Rate Limiting (priority 40)
    if (policies.rateLimiting.enabled && policies.rateLimiting.rules.length > 0) {
      this.rateLimiter = new RateLimiterMiddleware(policies.rateLimiting.rules);
      pipeline.register(this.rateLimiter);
    }

    // 6. Parameter Validation (priority 50)
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

    // 7. Content Filter (priority 60)
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

    // 8. Response Limiter (priority 110 — response phase)
    if (policies.responseLimits.enabled) {
      this.responseLimiter = new ResponseLimiterMiddleware({
        enabled: policies.responseLimits.enabled,
        maxResponseSize: policies.responseLimits.maxResponseSize,
        maxItems: policies.responseLimits.maxItems,
        maxResponseDepth: policies.responseLimits.maxResponseDepth,
      });
      pipeline.register(this.responseLimiter);
    }

    // 9. Sensitive Data Detection (priority 120 — response phase)
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

    // 10. Threat Scoring (priority 199 — runs last, aggregates all layers)
    if (policies.threatScoring.enabled) {
      this.threatScorer = new ThreatScorerMiddleware({
        enabled: policies.threatScoring.enabled,
        blockThreshold: policies.threatScoring.blockThreshold,
        warnThreshold: policies.threatScoring.warnThreshold,
        weights: policies.threatScoring.weights,
      });
      pipeline.register(this.threatScorer);
    }
  }
}

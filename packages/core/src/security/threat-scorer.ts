import type { SecurityMiddleware, PipelineContext, SecurityDecision } from '../pipeline/types';

/**
 * Threat scoring engine middleware.
 *
 * Aggregates risk scores from each security layer into a composite
 * threat score (0-100). When the score exceeds the block threshold,
 * the request is blocked. When it exceeds the warn threshold,
 * a warning is issued.
 *
 * Each layer contributes to the score based on configurable weights.
 * Layer scores are derived from the security events and decisions
 * recorded on the pipeline context during processing.
 *
 * Priority: 199 (runs last — after all other middlewares have recorded events)
 */
export class ThreatScorerMiddleware implements SecurityMiddleware {
  readonly name = 'threat-scorer';
  readonly priority = 199;
  readonly phase = 'both' as const;

  private enabled: boolean;
  private blockThreshold: number;
  private warnThreshold: number;
  private weights: ThreatScorerWeights;

  constructor(options: {
    enabled: boolean;
    blockThreshold: number;
    warnThreshold: number;
    weights: ThreatScorerWeights;
  }) {
    this.enabled = options.enabled;
    this.blockThreshold = options.blockThreshold;
    this.warnThreshold = options.warnThreshold;
    this.weights = options.weights;
  }

  async evaluate(ctx: PipelineContext): Promise<SecurityDecision | null> {
    if (!this.enabled) return null;

    const scores = this.computeLayerScores(ctx);
    const totalScore = this.computeTotalScore(scores);

    // Store the score in the context for audit logging
    ctx.metadata['threatScore'] = totalScore;
    ctx.metadata['threatScoreBreakdown'] = scores;

    if (totalScore >= this.blockThreshold) {
      return {
        verdict: 'block',
        reason: `Threat score ${totalScore}/100 exceeds block threshold (${this.blockThreshold})`,
        errorCode: -32001,
        metadata: {
          threatScore: totalScore,
          blockThreshold: this.blockThreshold,
          breakdown: scores,
        },
      };
    }

    if (totalScore >= this.warnThreshold) {
      return {
        verdict: 'warn',
        reason: `Threat score ${totalScore}/100 exceeds warn threshold (${this.warnThreshold})`,
        metadata: {
          threatScore: totalScore,
          warnThreshold: this.warnThreshold,
          breakdown: scores,
        },
      };
    }

    return null;
  }

  private computeLayerScores(ctx: PipelineContext): ThreatScoreBreakdown {
    const events = ctx.securityEvents;

    return {
      injectionDetection: this.scoreInjection(events, ctx),
      rateLimiting: this.scoreRateLimit(events),
      contentFilter: this.scoreContentFilter(events),
      ipReputation: this.scoreIpReputation(events),
      replayDetection: this.scoreReplay(events),
      concurrency: this.scoreConcurrency(events),
    };
  }

  /**
   * Injection detection score: based on parameter validation warnings/errors.
   * Each suspicious pattern found adds 15 points, capped at 100.
   */
  private scoreInjection(events: Context['securityEvents'], ctx: PipelineContext): number {
    const injectionEvents = events.filter(
      (e) =>
        e.category === 'validation' &&
        (e.message.includes('injection') ||
          e.message.includes('pattern') ||
          e.message.includes('Path traversal') ||
          e.message.includes('Null byte') ||
          e.message.includes('deep nesting')),
    );

    // Also check if any injection patterns were detected
    const metadata = ctx.metadata;
    const injectionPatterns = (metadata['_injectionPatterns'] as number) ?? 0;
    const totalHits = injectionEvents.length + injectionPatterns;

    return Math.min(100, totalHits * 15);
  }

  /**
   * Rate limiting score: based on how close we are to the limit.
   * Gets the current usage ratio from metadata set by the rate limiter.
   */
  private scoreRateLimit(events: Context['securityEvents']): number {
    const rateEvents = events.filter((e) => e.category === 'rate-limit');

    // Rate limit warnings indicate near-threshold usage
    const warningCount = rateEvents.filter((e) => e.severity === 'warn').length;
    const criticalCount = rateEvents.filter((e) => e.severity === 'critical').length;

    return Math.min(100, warningCount * 20 + criticalCount * 40);
  }

  /**
   * Content filter score: patterns matched in request/response content.
   * Each match adds 20 points.
   */
  private scoreContentFilter(events: Context['securityEvents']): number {
    const contentEvents = events.filter((e) => e.category === 'content-filter');
    return Math.min(100, contentEvents.length * 20);
  }

  /**
   * IP reputation score: based on IP-related events.
   * Warnings from IP access middleware add points.
   */
  private scoreIpReputation(events: Context['securityEvents']): number {
    const ipEvents = events.filter(
      (e) =>
        e.middleware === 'ip-access' ||
        e.message.includes('IP') ||
        e.message.includes('geo'),
    );
    return Math.min(100, ipEvents.length * 25);
  }

  /**
   * Replay detection score: duplicate nonce or timestamp issues.
   */
  private scoreReplay(events: Context['securityEvents']): number {
    const replayEvents = events.filter(
      (e) =>
        e.middleware === 'replay-detector' ||
        e.message.includes('replay') ||
        e.message.includes('nonce') ||
        e.message.includes('timestamp skew'),
    );
    return Math.min(100, replayEvents.length * 30);
  }

  /**
   * Concurrency score: based on current load indicators.
   */
  private scoreConcurrency(events: Context['securityEvents']): number {
    const concurrencyEvents = events.filter(
      (e) =>
        e.category === 'rate-limit' &&
        (e.message.includes('concurrent') || e.message.includes('queue')),
    );
    return Math.min(100, concurrencyEvents.length * 25);
  }

  private computeTotalScore(scores: ThreatScoreBreakdown): number {
    return Math.min(
      100,
      Math.round(
        scores.injectionDetection * this.weights.injectionDetection +
        scores.rateLimiting * this.weights.rateLimiting +
        scores.contentFilter * this.weights.contentFilter +
        scores.ipReputation * this.weights.ipReputation +
        scores.replayDetection * this.weights.replayDetection +
        scores.concurrency * this.weights.concurrency,
      ),
    );
  }
}

type Context = {
  securityEvents: Array<{
    category: string;
    middleware: string;
    severity: string;
    message: string;
    metadata?: Record<string, unknown>;
  }>;
  metadata: Record<string, unknown>;
};

export interface ThreatScorerWeights {
  injectionDetection: number;
  rateLimiting: number;
  contentFilter: number;
  ipReputation: number;
  replayDetection: number;
  concurrency: number;
}

export interface ThreatScoreBreakdown {
  injectionDetection: number;
  rateLimiting: number;
  contentFilter: number;
  ipReputation: number;
  replayDetection: number;
  concurrency: number;
}

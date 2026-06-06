import type { SecurityMiddleware, PipelineContext, SecurityDecision, SecurityVerdict, SecurityEvent } from './types';

export interface PipelineResult {
  /** Final verdict after all middleware evaluation */
  verdict: SecurityVerdict;
  /** The blocking decision if verdict is 'block' */
  blockDecision?: SecurityDecision;
  /** All warnings generated during evaluation */
  warnings: SecurityDecision[];
}

/**
 * The Pipeline orchestrator runs a sequence of SecurityMiddleware
 * against an incoming request or outgoing response.
 *
 * Execution:
 * - Middlewares run in priority order (lower = first).
 * - When a middleware returns a 'block' verdict, the pipeline
 *   short-circuits immediately and returns the block decision.
 * - 'warn' decisions are collected and continue.
 * - 'allow' and null results pass through silently.
 */
export class Pipeline {
  private middlewares: SecurityMiddleware[] = [];

  /**
   * Register a middleware with the pipeline.
   * Middlewares are automatically sorted by priority.
   */
  register(middleware: SecurityMiddleware): void {
    this.middlewares.push(middleware);
    this.middlewares.sort((a, b) => a.priority - b.priority);
  }

  /**
   * Register multiple middlewares at once.
   */
  registerAll(middlewares: SecurityMiddleware[]): void {
    for (const mw of middlewares) {
      this.middlewares.push(mw);
    }
    this.middlewares.sort((a, b) => a.priority - b.priority);
  }

  /**
   * Remove a middleware by name.
   */
  unregister(name: string): boolean {
    const idx = this.middlewares.findIndex((mw) => mw.name === name);
    if (idx >= 0) {
      this.middlewares.splice(idx, 1);
      return true;
    }
    return false;
  }

  /**
   * Get read-only access to registered middlewares.
   */
  getAll(): ReadonlyArray<SecurityMiddleware> {
    return this.middlewares;
  }

  /**
   * Evaluate a request through the pipeline.
   * Only runs middlewares configured for the 'request' or 'both' phase.
   */
  async evaluateRequest(ctx: PipelineContext): Promise<PipelineResult> {
    return this.evaluate(ctx, 'request');
  }

  /**
   * Evaluate a response through the pipeline.
   * Only runs middlewares configured for the 'response' or 'both' phase.
   */
  async evaluateResponse(ctx: PipelineContext): Promise<PipelineResult> {
    return this.evaluate(ctx, 'response');
  }

  private async evaluate(ctx: PipelineContext, phase: 'request' | 'response'): Promise<PipelineResult> {
    const warnings: SecurityDecision[] = [];

    for (const mw of this.middlewares) {
      if (mw.phase !== phase && mw.phase !== 'both') continue;

      try {
        const decision = await mw.evaluate(ctx);

        if (decision === null) continue;

        switch (decision.verdict) {
          case 'block':
            // Record security event
            ctx.securityEvents.push({
              timestamp: new Date().toISOString(),
              middleware: mw.name,
              category: this.inferCategory(mw.name),
              message: decision.reason,
              severity: 'critical',
              metadata: decision.metadata,
            });
            return { verdict: 'block', blockDecision: decision, warnings };

          case 'warn':
            ctx.securityEvents.push({
              timestamp: new Date().toISOString(),
              middleware: mw.name,
              category: this.inferCategory(mw.name),
              message: decision.reason,
              severity: 'warn',
              metadata: decision.metadata,
            });
            warnings.push(decision);
            break;

          case 'allow':
            // Allow is the default; no side effects
            break;
        }
      } catch (err) {
        // A middleware throwing is treated as a block for safety
        const message = err instanceof Error ? err.message : String(err);
        ctx.securityEvents.push({
          timestamp: new Date().toISOString(),
          middleware: mw.name,
          category: this.inferCategory(mw.name),
          message: `Middleware error: ${message}`,
          severity: 'critical',
        });
        return {
          verdict: 'block',
          blockDecision: {
            verdict: 'block',
            reason: `Middleware "${mw.name}" failed: ${message}`,
            errorCode: -32603,
          },
          warnings,
        };
      }
    }

    return { verdict: 'allow', warnings };
  }

  private inferCategory(mwName: string): SecurityEvent['category'] {
    const lower = mwName.toLowerCase();
    if (lower.includes('auth')) return 'auth';
    if (lower.includes('rbac')) return 'rbac';
    if (lower.includes('rate')) return 'rate-limit';
    if (lower.includes('valid') || lower.includes('param')) return 'validation';
    if (lower.includes('content') || lower.includes('filter')) return 'content-filter';
    if (lower.includes('sensitive') || lower.includes('pii') || lower.includes('secret')) return 'sensitive-data';
    if (lower.includes('sandbox')) return 'sandbox';
    return 'validation';
  }
}

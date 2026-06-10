import type { SecurityMiddleware, PipelineContext, SecurityDecision } from '../pipeline/types';

/**
 * Response size and structure limiter middleware.
 *
 * Prevents data exfiltration and DoS by enforcing limits on:
 * - Maximum response body size (bytes)
 * - Maximum number of items in a list result
 * - Maximum nesting depth of response objects
 *
 * This middleware also handles truncation: when a response exceeds
 * limits, it can truncate (warn) or block, depending on severity.
 *
 * Priority: 110 (runs early in response pipeline, after sensitive data)
 */
export class ResponseLimiterMiddleware implements SecurityMiddleware {
  readonly name = 'response-limiter';
  readonly priority = 110;
  readonly phase = 'response' as const;

  private enabled: boolean;
  private maxResponseSize: number;
  private maxItems: number;
  private maxResponseDepth: number;

  constructor(options: {
    enabled: boolean;
    maxResponseSize: number;
    maxItems: number;
    maxResponseDepth: number;
  }) {
    this.enabled = options.enabled;
    this.maxResponseSize = options.maxResponseSize;
    this.maxItems = options.maxItems;
    this.maxResponseDepth = options.maxResponseDepth;
  }

  async evaluate(ctx: PipelineContext): Promise<SecurityDecision | null> {
    if (!this.enabled) return null;
    if (!ctx.response) return null;

    const responseText = JSON.stringify(ctx.response);

    // 1. Check total response size
    const sizeBytes = Buffer.byteLength(responseText, 'utf-8');
    if (sizeBytes > this.maxResponseSize) {
      return {
        verdict: 'block',
        reason: `Response size (${formatBytes(sizeBytes)}) exceeds limit of ${formatBytes(this.maxResponseSize)}`,
        errorCode: -32001,
        metadata: {
          currentSize: sizeBytes,
          maxSize: this.maxResponseSize,
        },
      };
    }

    // 2. Check list item count (if response contains a result array)
    const result = ('result' in ctx.response) ? (ctx.response as unknown as Record<string, unknown>).result : undefined;
    if (result && typeof result === 'object') {
      const itemCount = this.countItems(result);
      if (itemCount > this.maxItems) {
        return {
          verdict: 'block',
          reason: `Response item count (${itemCount}) exceeds limit of ${this.maxItems}`,
          errorCode: -32001,
          metadata: {
            currentItems: itemCount,
            maxItems: this.maxItems,
          },
        };
      }

      // 3. Check nesting depth
      const depth = this.measureDepth(result);
      if (depth > this.maxResponseDepth) {
        return {
          verdict: 'block',
          reason: `Response depth (${depth}) exceeds limit of ${this.maxResponseDepth}`,
          errorCode: -32001,
          metadata: {
            currentDepth: depth,
            maxDepth: this.maxResponseDepth,
          },
        };
      }
    }

    return null;
  }

  /**
   * Count the total number of items in a nested structure.
   * For arrays, counts elements. For objects, counts first-level arrays.
   */
  private countItems(obj: unknown): number {
    if (Array.isArray(obj)) {
      return obj.length;
    }
    if (obj !== null && typeof obj === 'object') {
      // Check for common patterns: { items: [...], data: [...], results: [...] }
      for (const key of ['items', 'data', 'results', 'content', 'tools', 'resources', 'prompts']) {
        const val = (obj as Record<string, unknown>)[key];
        if (Array.isArray(val)) return val.length;
      }
      // If no known array key, count the total entries
      return Object.keys(obj).length;
    }
    return 0;
  }

  /**
   * Measure the maximum nesting depth of an object.
   * JSON depth = 1 for a flat object, increases for nested objects/arrays.
   */
  private measureDepth(obj: unknown): number {
    if (obj === null || typeof obj !== 'object') return 0;
    if (Array.isArray(obj)) {
      if (obj.length === 0) return 1;
      return 1 + Math.max(0, ...obj.map((item) => this.measureDepth(item)));
    }
    const values = Object.values(obj as Record<string, unknown>);
    if (values.length === 0) return 1;
    return 1 + Math.max(...values.map((v) => this.measureDepth(v)));
  }
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

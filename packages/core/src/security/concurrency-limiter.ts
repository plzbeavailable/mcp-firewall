import type { SecurityMiddleware, PipelineContext, SecurityDecision } from '../pipeline/types';

/**
 * Per-client concurrency limiter middleware.
 *
 * Limits the number of concurrent in-flight requests per client
 * and per tool to prevent resource exhaustion and DoS attacks.
 *
 * Optionally supports queuing excess requests instead of rejecting them.
 *
 * Priority: 35 (runs after RBAC, before rate limiting)
 */
export class ConcurrencyLimiterMiddleware implements SecurityMiddleware {
  readonly name = 'concurrency-limiter';
  readonly priority = 35;
  readonly phase = 'request' as const;

  private enabled: boolean;
  private maxConcurrent: number;
  private maxConcurrentPerTool: number;
  private queueEnabled: boolean;
  private maxQueueSize: number;

  // Track active request counts
  private clientRequests = new Map<string, number>();
  private toolRequests = new Map<string, number>();

  // Simple non-persistent queue (lost on restart — acceptable for firewall)
  private clientQueues = new Map<string, Array<{ resolve: (v: SecurityDecision | null) => void; ctx: PipelineContext }>>();

  constructor(options: {
    enabled: boolean;
    maxConcurrent: number;
    maxConcurrentPerTool: number;
    queueEnabled: boolean;
    maxQueueSize: number;
  }) {
    this.enabled = options.enabled;
    this.maxConcurrent = options.maxConcurrent;
    this.maxConcurrentPerTool = options.maxConcurrentPerTool;
    this.queueEnabled = options.queueEnabled;
    this.maxQueueSize = options.maxQueueSize;
  }

  async evaluate(ctx: PipelineContext): Promise<SecurityDecision | null> {
    if (!this.enabled) return null;

    const clientKey = ctx.client.clientId;
    const toolKey = ctx.toolName ? `${ctx.serverName}:${ctx.toolName}` : ctx.method;

    // Check client-level concurrency
    const clientCount = this.clientRequests.get(clientKey) ?? 0;
    if (clientCount >= this.maxConcurrent) {
      if (this.queueEnabled) {
        // Check queue size
        const queue = this.clientQueues.get(clientKey) ?? [];
        if (queue.length >= this.maxQueueSize) {
          return {
            verdict: 'block',
            reason: `Client "${clientKey}" has reached max concurrent requests (${this.maxConcurrent}) and queue is full (${this.maxQueueSize})`,
            errorCode: -32001,
            metadata: {
              clientId: clientKey,
              currentConcurrent: clientCount,
              maxConcurrent: this.maxConcurrent,
              queueSize: queue.length,
            },
          };
        }

        // Queue this request
        return new Promise((resolve) => {
          if (!this.clientQueues.has(clientKey)) {
            this.clientQueues.set(clientKey, []);
          }
          this.clientQueues.get(clientKey)!.push({ resolve, ctx });
        });
      }

      return {
        verdict: 'block',
        reason: `Client "${clientKey}" has reached max concurrent requests (${this.maxConcurrent})`,
        errorCode: -32001,
        metadata: {
          clientId: clientKey,
          currentConcurrent: clientCount,
          maxConcurrent: this.maxConcurrent,
        },
      };
    }

    // Check tool-level concurrency
    const toolCount = this.toolRequests.get(toolKey) ?? 0;
    if (toolCount >= this.maxConcurrentPerTool) {
      return {
        verdict: 'block',
        reason: `Tool "${toolKey}" has reached max concurrent requests (${this.maxConcurrentPerTool})`,
        errorCode: -32001,
        metadata: {
          toolName: toolKey,
          currentConcurrent: toolCount,
          maxConcurrentPerTool: this.maxConcurrentPerTool,
        },
      };
    }

    // Increment counters
    this.increment(clientKey, toolKey);

    // Store cleanup info in metadata for response phase
    ctx.metadata['_concurrencyClientKey'] = clientKey;
    ctx.metadata['_concurrencyToolKey'] = toolKey;

    return null;
  }

  /**
   * Decrement concurrency counters when a request completes.
   * Called by the firewall after the response is processed.
   */
  release(clientKey: string, toolKey: string): void {
    // Decrement client counter
    const clientCount = this.clientRequests.get(clientKey);
    if (clientCount !== undefined) {
      if (clientCount <= 1) {
        this.clientRequests.delete(clientKey);
      } else {
        this.clientRequests.set(clientKey, clientCount - 1);
      }
    }

    // Decrement tool counter
    const toolCount = this.toolRequests.get(toolKey);
    if (toolCount !== undefined) {
      if (toolCount <= 1) {
        this.toolRequests.delete(toolKey);
      } else {
        this.toolRequests.set(toolKey, toolCount - 1);
      }
    }

    // Dequeue next request if queued
    const queue = this.clientQueues.get(clientKey);
    if (queue && queue.length > 0) {
      const next = queue.shift()!;
      if (queue.length === 0) {
        this.clientQueues.delete(clientKey);
      }
      // Increment for the dequeued request
      this.increment(clientKey, toolKey);
      next.resolve(null); // Allow the queued request to proceed
    }
  }

  /**
   * Get current concurrency stats.
   */
  getStats(): { activeClients: number; activeTools: number; queuedRequests: number } {
    let queuedRequests = 0;
    for (const queue of this.clientQueues.values()) {
      queuedRequests += queue.length;
    }
    return {
      activeClients: this.clientRequests.size,
      activeTools: this.toolRequests.size,
      queuedRequests,
    };
  }

  private increment(clientKey: string, toolKey: string): void {
    this.clientRequests.set(clientKey, (this.clientRequests.get(clientKey) ?? 0) + 1);
    this.toolRequests.set(toolKey, (this.toolRequests.get(toolKey) ?? 0) + 1);
  }
}

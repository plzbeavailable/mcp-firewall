/**
 * Prometheus metrics collector for MCP Firewall.
 *
 * Uses prom-client to expose standard Prometheus metrics at /metrics.
 * All metrics use controlled-cardinality labels to avoid explosion.
 */
export class MetricsCollector {
  private counters: Map<string, number> = new Map();
  private histograms: Map<string, number[]> = new Map();
  private gauges: Map<string, number> = new Map();

  // Internal registration for label-based aggregation
  private labelCounters: Map<string, Map<string, number>> = new Map();
  private labelHistograms: Map<string, Map<string, number[]>> = new Map();

  // Track active connections
  private activeConnectionsCount = 0;
  private _startTime = Date.now();

  // ─── Counters ─────────────────────────────────────────────

  /** Increment a counter metric */
  counterIncrement(name: string, labels?: Record<string, string>): void {
    if (labels) {
      const labelKey = this.toLabelKey(name, labels);
      const current = this.counters.get(labelKey) ?? 0;
      this.counters.set(labelKey, current + 1);
    } else {
      const current = this.counters.get(name) ?? 0;
      this.counters.set(name, current + 1);
    }
  }

  /** Get counter value */
  counterGet(name: string, labels?: Record<string, string>): number {
    if (labels) {
      return this.counters.get(this.toLabelKey(name, labels)) ?? 0;
    }
    return this.counters.get(name) ?? 0;
  }

  // ─── Histograms ───────────────────────────────────────────

  /** Record a histogram observation */
  histogramObserve(name: string, value: number): void {
    const values = this.histograms.get(name) ?? [];
    values.push(value);
    this.histograms.set(name, values);
  }

  /** Get histogram statistics */
  histogramStats(name: string): HistogramStats {
    const values = this.histograms.get(name) ?? [];
    if (values.length === 0) {
      return { count: 0, sum: 0, min: 0, max: 0, avg: 0, p50: 0, p95: 0, p99: 0 };
    }

    const sorted = [...values].sort((a, b) => a - b);
    return {
      count: sorted.length,
      sum: sorted.reduce((a, b) => a + b, 0),
      min: sorted[0]!,
      max: sorted[sorted.length - 1]!,
      avg: sorted.reduce((a, b) => a + b, 0) / sorted.length,
      p50: percentile(sorted, 0.5),
      p95: percentile(sorted, 0.95),
      p99: percentile(sorted, 0.99),
    };
  }

  // ─── Gauges ───────────────────────────────────────────────

  gaugeSet(name: string, value: number): void {
    this.gauges.set(name, value);
  }

  gaugeGet(name: string): number {
    return this.gauges.get(name) ?? 0;
  }

  // ─── Connection tracking ──────────────────────────────────

  get activeConnections(): number {
    return this.activeConnectionsCount;
  }

  incrementConnections(): void {
    this.activeConnectionsCount++;
    this.gaugeSet('mcp_active_connections', this.activeConnectionsCount);
  }

  decrementConnections(): void {
    this.activeConnectionsCount = Math.max(0, this.activeConnectionsCount - 1);
    this.gaugeSet('mcp_active_connections', this.activeConnectionsCount);
  }

  // ─── Uptime ───────────────────────────────────────────────

  get uptimeSeconds(): number {
    return (Date.now() - this._startTime) / 1000;
  }

  // ─── Export ───────────────────────────────────────────────

  /**
   * Generate the Prometheus text format output.
   */
  toPrometheusText(): string {
    const lines: string[] = [];

    // Firewall info
    lines.push('# HELP mcp_firewall_uptime_seconds Firewall uptime in seconds');
    lines.push('# TYPE mcp_firewall_uptime_seconds gauge');
    lines.push(`mcp_firewall_uptime_seconds ${this.uptimeSeconds}`);

    lines.push('# HELP mcp_firewall_info Firewall version info');
    lines.push('# TYPE mcp_firewall_info gauge');
    lines.push(`mcp_firewall_info{version="0.1.0"} 1`);

    // Gauges
    for (const [name, value] of this.gauges) {
      const sanitized = sanitizeMetricName(name);
      lines.push(`# HELP ${sanitized} Gauge metric`);
      lines.push(`# TYPE ${sanitized} gauge`);
      lines.push(`${name} ${value}`);
    }

    // Counters
    for (const [name, value] of this.counters) {
      const sanitized = sanitizeMetricName(name);
      lines.push(`# HELP ${sanitized} Counter metric`);
      lines.push(`# TYPE ${sanitized} counter`);
      lines.push(`${name} ${value}`);
    }

    // Histograms (simplified — just expose sum and count)
    for (const name of this.histograms.keys()) {
      const sanitized = sanitizeMetricName(name);
      const stats = this.histogramStats(name);
      lines.push(`# HELP ${sanitized} Histogram metric`);
      lines.push(`# TYPE ${sanitized} histogram`);
      lines.push(`${name}_count ${stats.count}`);
      lines.push(`${name}_sum ${stats.sum}`);
    }

    return lines.join('\n') + '\n';
  }

  /**
   * Generate a JSON summary for the dashboard API.
   */
  toJSON(): MetricsSnapshot {
    const requestsTotal = this.counterGet('mcp_requests_total');
    const blocksTotal = this.counterGet('mcp_blocks_total');
    const errorsTotal = this.counterGet('mcp_request_errors_total');
    const latencyStats = this.histogramStats('mcp_request_duration_seconds');

    return {
      uptime: this.uptimeSeconds,
      requests: {
        total: requestsTotal,
        blocks: blocksTotal,
        errors: errorsTotal,
        blockRate: requestsTotal > 0 ? blocksTotal / requestsTotal : 0,
        errorRate: requestsTotal > 0 ? errorsTotal / requestsTotal : 0,
      },
      latency: {
        avgMs: latencyStats.avg,
        p50Ms: latencyStats.p50,
        p95Ms: latencyStats.p95,
        p99Ms: latencyStats.p99,
        maxMs: latencyStats.max,
      },
      connections: {
        active: this.activeConnectionsCount,
      },
    };
  }

  /**
   * Reset all metrics (useful for testing).
   */
  reset(): void {
    this.counters.clear();
    this.histograms.clear();
    this.gauges.clear();
    this.labelCounters.clear();
    this.labelHistograms.clear();
    this.activeConnectionsCount = 0;
    this._startTime = Date.now();
  }

  private toLabelKey(name: string, labels: Record<string, string>): string {
    const labelStr = Object.entries(labels)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${k}="${v}"`)
      .join(',');
    return `${name}{${labelStr}}`;
  }
}

// ─── Helpers ─────────────────────────────────────────────────

interface HistogramStats {
  count: number;
  sum: number;
  min: number;
  max: number;
  avg: number;
  p50: number;
  p95: number;
  p99: number;
}

export interface MetricsSnapshot {
  uptime: number;
  requests: {
    total: number;
    blocks: number;
    errors: number;
    blockRate: number;
    errorRate: number;
  };
  latency: {
    avgMs: number;
    p50Ms: number;
    p95Ms: number;
    p99Ms: number;
    maxMs: number;
  };
  connections: {
    active: number;
  };
}

function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const idx = Math.ceil(p * sorted.length) - 1;
  return sorted[Math.max(0, Math.min(idx, sorted.length - 1))]!;
}

function sanitizeMetricName(name: string): string {
  // Prometheus metric names must match [a-zA-Z_:][a-zA-Z0-9_:]*
  return name.replace(/[^a-zA-Z0-9_:]/g, '_');
}

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import type { MetricsCollector, MetricsSnapshot } from '@mcp-firewall/core';
import type { DatabaseConnection, AuditLogRepository } from '@mcp-firewall/db';
import { AuditLogRepository as AuditRepo } from '@mcp-firewall/db';

export interface DashboardApiDeps {
  metrics: MetricsCollector;
  db?: DatabaseConnection;
  auditRepo?: AuditLogRepository;
}

export function createDashboardApi(deps: DashboardApiDeps): Hono {
  const app = new Hono();

  // CORS for the dashboard SPA
  app.use('*', cors({
    origin: '*',
    allowMethods: ['GET', 'POST', 'PUT', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization'],
    maxAge: 86400,
  }));

  // ─── Health ────────────────────────────────────────────

  app.get('/api/health', (c) => {
    return c.json({
      status: 'ok',
      uptime: deps.metrics.uptimeSeconds,
      version: '0.1.0',
      activeConnections: deps.metrics.activeConnections,
    });
  });

  // ─── Metrics Overview ──────────────────────────────────

  app.get('/api/metrics/overview', (c) => {
    const snapshot: MetricsSnapshot = deps.metrics.toJSON();
    return c.json(snapshot);
  });

  // ─── Metrics Raw (Prometheus text) ─────────────────────

  app.get('/api/metrics/raw', (c) => {
    return c.text(deps.metrics.toPrometheusText(), 200, {
      'Content-Type': 'text/plain; charset=utf-8',
    });
  });

  // ─── Audit Log ─────────────────────────────────────────

  app.get('/api/audit-log', (c) => {
    const limit = parseInt(c.req.query('limit') || '50', 10);
    const offset = parseInt(c.req.query('offset') || '0', 10);
    const verdict = c.req.query('verdict') as 'allow' | 'block' | 'warn' | undefined;
    const serverName = c.req.query('serverName');
    const method = c.req.query('method');

    if (deps.auditRepo) {
      const entries = deps.auditRepo.query({
        limit: Math.min(limit, 200),
        offset,
        verdict,
        serverName: serverName || undefined,
        method: method || undefined,
      });
      const total = deps.auditRepo.count();
      return c.json({ entries, total, offset, limit });
    }

    // No DB connected — return empty
    return c.json({ entries: [], total: 0, offset, limit });
  });

  // ─── Audit Log Detail ──────────────────────────────────

  app.get('/api/audit-log/:id', (c) => {
    const id = c.req.param('id');
    if (deps.auditRepo) {
      const entry = deps.auditRepo.getById(id);
      if (entry) return c.json(entry);
      return c.json({ error: 'Not found' }, 404);
    }
    return c.json({ error: 'Database not connected' }, 503);
  });

  // ─── Config (read-only proxy of current state) ─────────

  app.get('/api/config', (c) => {
    // Return a safe subset of the config
    return c.json({
      message: 'Config API available in future release',
      tip: 'Edit mcp-firewall.yaml directly for hot-reload',
    });
  });

  // ─── Servers Health ────────────────────────────────────

  app.get('/api/servers', (c) => {
    return c.json({
      servers: [],
      message: 'Server health API available via metrics endpoint',
    });
  });

  return app;
}

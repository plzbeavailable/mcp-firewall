import { sqliteTable, text, integer, real, index } from 'drizzle-orm/sqlite-core';

// ─── Audit Log ────────────────────────────────────────────────

export const auditLog = sqliteTable(
  'audit_log',
  {
    id: text('id').primaryKey(),
    timestamp: text('timestamp').notNull(),
    traceId: text('trace_id').notNull(),
    spanId: text('span_id').notNull(),
    clientId: text('client_id'),
    serverName: text('server_name').notNull(),
    method: text('method').notNull(),
    toolName: text('tool_name'),
    requestParams: text('request_params'), // JSON string
    responseData: text('response_data'), // JSON string
    verdict: text('verdict', { enum: ['allow', 'block', 'warn'] })
      .notNull()
      .default('allow'),
    blockReason: text('block_reason'),
    durationMs: real('duration_ms').notNull(),
    upstreamDurationMs: real('upstream_duration_ms'),
    tokenInput: integer('token_input'),
    tokenOutput: integer('token_output'),
    tokenModel: text('token_model'),
    securityEvents: text('security_events'), // JSON array
    createdAt: text('created_at').default("(datetime('now'))"),
  },
  (table) => ({
    idxTimestamp: index('idx_audit_log_timestamp').on(table.timestamp),
    idxServer: index('idx_audit_log_server').on(table.serverName),
    idxVerdict: index('idx_audit_log_verdict').on(table.verdict),
    idxClient: index('idx_audit_log_client').on(table.clientId),
    idxMethod: index('idx_audit_log_method').on(table.method),
  }),
);

// ─── Token Usage ──────────────────────────────────────────────

export const tokenUsage = sqliteTable(
  'token_usage',
  {
    id: text('id').primaryKey(),
    auditLogId: text('audit_log_id').references(() => auditLog.id),
    serverName: text('server_name').notNull(),
    model: text('model').notNull(),
    inputTokens: integer('input_tokens').default(0),
    outputTokens: integer('output_tokens').default(0),
    costEstimate: real('cost_estimate').default(0.0),
    timestamp: text('timestamp').notNull(),
  },
  (table) => ({
    idxServer: index('idx_token_usage_server').on(table.serverName),
    idxTimestamp: index('idx_token_usage_timestamp').on(table.timestamp),
  }),
);

// ─── Metrics Snapshots ────────────────────────────────────────

export const metricsSnapshots = sqliteTable(
  'metrics_snapshots',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    timestamp: text('timestamp').notNull(),
    metricName: text('metric_name').notNull(),
    labels: text('labels').notNull(), // JSON object
    value: real('value').notNull(),
  },
  (table) => ({
    idxQuery: index('idx_metrics_snapshot_query').on(
      table.timestamp,
      table.metricName,
    ),
  }),
);

// ─── Policy Changes ───────────────────────────────────────────

export const policyChanges = sqliteTable('policy_changes', {
  id: text('id').primaryKey(),
  policyName: text('policy_name').notNull(),
  changeType: text('change_type', {
    enum: ['create', 'update', 'delete'],
  }).notNull(),
  previousConfig: text('previous_config'), // JSON
  newConfig: text('new_config'), // JSON
  changedBy: text('changed_by'),
  changedAt: text('changed_at').default("(datetime('now'))"),
});

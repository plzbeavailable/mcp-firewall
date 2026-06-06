// @mcp-firewall/db — Database layer
// Drizzle ORM with SQLite (and future PostgreSQL) support

export { auditLog, tokenUsage, metricsSnapshots, policyChanges } from './schema';
export type { DatabaseConnection } from './connection';
export { getDatabase, getRawConnection, closeDatabase } from './connection';
export { AuditLogRepository, type AuditLogEntry } from './repositories/audit-log';

export const DB_VERSION = '0.1.0';

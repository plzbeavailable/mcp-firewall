import Database, { type Database as BetterSQLite3Db } from 'better-sqlite3';
import { drizzle, type BetterSQLite3Database } from 'drizzle-orm/better-sqlite3';
import { migrate } from 'drizzle-orm/better-sqlite3/migrator';
import * as schema from './schema';

export type DatabaseConnection = BetterSQLite3Database<typeof schema>;

let instance: DatabaseConnection | null = null;

/**
 * Get or create the SQLite database connection (singleton).
 */
export function getDatabase(dbPath: string): DatabaseConnection {
  if (instance) return instance;

  // Ensure directory exists
  const dir = dbPath.substring(0, dbPath.lastIndexOf('/'));
  if (dir) {
    const fs = require('node:fs');
    fs.mkdirSync(dir, { recursive: true });
  }

  const sqlite = new Database(dbPath);

  // Enable WAL mode for better concurrent read performance
  sqlite.pragma('journal_mode = WAL');
  sqlite.pragma('foreign_keys = ON');
  sqlite.pragma('busy_timeout = 5000');

  instance = drizzle(sqlite, { schema });
  return instance;
}

/**
 * Get the raw SQLite connection for low-level operations.
 */
export function getRawConnection(dbPath: string): BetterSQLite3Db {
  const sqlite = new Database(dbPath);
  sqlite.pragma('journal_mode = WAL');
  sqlite.pragma('foreign_keys = ON');
  return sqlite;
}

/**
 * Close the database connection.
 */
export function closeDatabase(): void {
  if (instance) {
    // Drizzle doesn't expose close directly — we need the underlying driver
    instance = null;
  }
}

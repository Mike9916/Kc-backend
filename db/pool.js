// backend/db/pool.js
const { Pool } = require('pg');
require('dotenv').config();

/**
 * Creates a single shared connection pool for the whole app.
 * - Uses DATABASE_URL from .env
 * - Respects PGSSLMODE (e.g., "require" on some cloud hosts)
 * - Safe defaults for small/medium Node APIs
 */

const useSSL =
  (process.env.PGSSLMODE && process.env.PGSSLMODE.toLowerCase() === 'require') ||
  (process.env.NODE_ENV === 'production' && !process.env.PGSSLMODE)
    ? { rejectUnauthorized: false }
    : false;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: useSSL,
  max: parseInt(process.env.PG_MAX || '10', 10),
  idleTimeoutMillis: parseInt(process.env.PG_IDLE_TIMEOUT_MS || '30000', 10),
  connectionTimeoutMillis: parseInt(process.env.PG_CONN_TIMEOUT_MS || '10000', 10),
});

// Optional: simple helper for one-off queries
const query = (text, params) => pool.query(text, params);

// Optional: basic startup check (call from server.js if you like)
async function assertDbConnection() {
  const { rows } = await pool.query('SELECT 1 AS ok');
  if (!rows?.[0]?.ok) throw new Error('DB connectivity check failed');
  return true;
}

// Graceful shutdown
process.on('SIGINT', async () => {
  try { await pool.end(); } catch (_) {}
  process.exit(0);
});

module.exports = { pool, query, assertDbConnection };
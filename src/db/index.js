// Uses Node's built-in SQLite module (node:sqlite) — available unflagged in
// Node 22.5+/24.x, so no native compilation (node-gyp/Visual Studio/Xcode)
// is required to install this project. If you're on an older Node version,
// upgrade to Node 20+ rather than reintroducing better-sqlite3.
import { DatabaseSync } from "node:sqlite";
import fs from "fs";
import path from "path";
import dotenv from "dotenv";
dotenv.config();

const dbPath = process.env.DATABASE_PATH || "./data/anshapi.db";
const dir = path.dirname(dbPath);
if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

const BACKUPS_DIR = path.join(dir, "backups");
if (!fs.existsSync(BACKUPS_DIR)) fs.mkdirSync(BACKUPS_DIR, { recursive: true });

// `let`, not `const` — restoreBackup() below closes and reopens this handle
// in place, and every read/write in this module resolves `raw` at call
// time (not at import time), so a reassignment here is picked up
// everywhere automatically without touching route code.
let raw = new DatabaseSync(dbPath);
initPragmas();

function initPragmas() {
  raw.exec("PRAGMA journal_mode = WAL");
  raw.exec("PRAGMA foreign_keys = ON");
  // Under bursty traffic (many proxied requests writing api_requests rows
  // concurrently), SQLite can return SQLITE_BUSY instead of just waiting
  // for the writer ahead of it. busy_timeout makes it wait (up to 8s)
  // instead of throwing, which is what lets a single admin write and a
  // flood of public proxy writes coexist without either side failing.
  raw.exec("PRAGMA busy_timeout = 8000");
  raw.exec("PRAGMA synchronous = NORMAL"); // safe with WAL, much faster than FULL
}

// node:sqlite throws on `undefined` bound parameters instead of treating
// them as NULL the way better-sqlite3 does — normalize so route code
// written against the better-sqlite3 convention keeps working unchanged.
function normalizeArgs(args) {
  return args.map((a) => {
    if (a === undefined) return null;
    if (a !== null && typeof a === "object" && !Array.isArray(a)) {
      const out = {};
      for (const [k, v] of Object.entries(a)) out[k] = v === undefined ? null : v;
      return out;
    }
    return a;
  });
}

// Thin compatibility layer so route files can keep using the
// better-sqlite3-style `db.prepare(sql).get/all/run(...)` API.
export const db = {
  exec: (sql) => raw.exec(sql),
  prepare: (sql) => {
    const stmt = raw.prepare(sql);
    return {
      get: (...args) => stmt.get(...normalizeArgs(args)),
      all: (...args) => stmt.all(...normalizeArgs(args)),
      run: (...rawArgs) => {
        const args = normalizeArgs(rawArgs);
        const res = stmt.run(...args);
        // Normalize BigInt lastInsertRowid to a regular number where safe.
        return {
          lastInsertRowid:
            typeof res.lastInsertRowid === "bigint" ? Number(res.lastInsertRowid) : res.lastInsertRowid,
          changes: typeof res.changes === "bigint" ? Number(res.changes) : res.changes,
        };
      },
    };
  },
};

// Replacement for better-sqlite3's db.transaction(fn) — call the returned
// function immediately: withTransaction(() => { ...writes...; return x; })
export function withTransaction(fn) {
  raw.exec("BEGIN");
  try {
    const result = fn();
    raw.exec("COMMIT");
    return result;
  } catch (e) {
    try {
      raw.exec("ROLLBACK");
    } catch {
      /* ignore rollback failure */
    }
    throw e;
  }
}

// ==================== BACKUP & RESTORE ====================
// SQLite's entire database is one file, so a "backup" is a consistent copy
// of it. We use `VACUUM INTO`, which writes a transactionally-consistent
// snapshot even while requests are being logged concurrently — a plain
// file copy can capture a half-written page if an automatic WAL
// checkpoint runs mid-copy.

// Only files we created ourselves are ever served, restored or pruned.
export const BACKUP_NAME_RE = /^anshapi-backup-[0-9A-Za-z._-]+\.db$/;

function backupTimestamp() {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

export function createBackup(suffix = "") {
  const filename = `anshapi-backup-${backupTimestamp()}${suffix ? `-${suffix}` : ""}.db`;
  const dest = path.join(BACKUPS_DIR, filename);
  try {
    raw.exec(`VACUUM INTO '${dest.replace(/'/g, "''")}'`);
  } catch {
    // Extremely old SQLite builds: fall back to checkpoint + copy.
    raw.exec("PRAGMA wal_checkpoint(FULL)");
    fs.copyFileSync(dbPath, dest);
  }
  const stat = fs.statSync(dest);
  return { filename, size_bytes: stat.size, created_at: new Date().toISOString() };
}

export function listBackups() {
  return fs
    .readdirSync(BACKUPS_DIR)
    .filter((f) => BACKUP_NAME_RE.test(f))
    .map((filename) => {
      const stat = fs.statSync(path.join(BACKUPS_DIR, filename));
      return { filename, size_bytes: stat.size, created_at: stat.mtime.toISOString() };
    })
    .sort((a, b) => (a.created_at < b.created_at ? 1 : -1));
}

// Keeps only the most recent `keep` backups, deleting older ones so the
// backups directory doesn't grow unbounded on a long-running server.
export function pruneBackups(keep = 30) {
  const all = listBackups();
  for (const b of all.slice(keep)) {
    try {
      fs.unlinkSync(path.join(BACKUPS_DIR, b.filename));
    } catch {
      /* best-effort */
    }
  }
}

/**
 * Resolves a backup filename from user input to an absolute path, or null.
 * Rejects anything that isn't exactly one of our own backup files: no path
 * separators, no "..", no other extensions — and re-checks the resolved
 * path really sits inside the backups directory.
 */
export function getBackupPath(filename) {
  if (typeof filename !== "string" || !BACKUP_NAME_RE.test(filename) || filename !== path.basename(filename)) {
    return null;
  }
  const full = path.resolve(BACKUPS_DIR, filename);
  if (path.dirname(full) !== path.resolve(BACKUPS_DIR)) return null;
  if (!fs.existsSync(full)) return null;
  return full;
}

// Opens a candidate backup read-only and checks it is an intact SQLite
// database that actually looks like an AnshAPI database.
function assertValidBackupFile(file) {
  let probe;
  try {
    probe = new DatabaseSync(file, { readOnly: true });
    const check = probe.prepare("PRAGMA quick_check").get();
    if (!check || check.quick_check !== "ok") throw new Error("integrity check failed");
    const tables = new Set(
      probe.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map((r) => r.name)
    );
    for (const t of ["users", "apis", "api_requests"]) {
      if (!tables.has(t)) throw new Error(`missing table "${t}"`);
    }
  } catch (e) {
    throw new Error(`This isn't a valid AnshAPI backup (${e.message})`);
  } finally {
    try {
      probe?.close();
    } catch {
      /* ignore */
    }
  }
}

// Restores the live database from a previously created backup file.
// Safe against WAL corruption because we close the live handle first,
// swap the file, drop any stale -wal/-shm siblings, then reopen — and
// re-run schema/migrations, because the backup may be older than the
// running code (e.g. taken before the request-log columns existed).
// A safety copy of the CURRENT database is taken first, so a mistaken
// restore can itself be undone.
export function restoreBackup(filename) {
  const src = getBackupPath(filename);
  if (!src) throw new Error("Backup file not found");
  assertValidBackupFile(src);

  const safety = createBackup("pre-restore");

  raw.exec("PRAGMA wal_checkpoint(FULL)");
  raw.close();
  try {
    fs.copyFileSync(src, dbPath);
    for (const ext of ["-wal", "-shm"]) {
      try {
        fs.unlinkSync(dbPath + ext);
      } catch {
        /* fine if they don't exist */
      }
    }
  } finally {
    raw = new DatabaseSync(dbPath);
    initPragmas();
  }
  ensureSchema();
  return { restored_from: path.basename(src), safety_backup: safety.filename };
}

// Accepts a raw SQLite file buffer (e.g. a backup the admin previously
// downloaded and is now uploading back), validates it before touching
// anything (rejects garbage/malicious uploads outright), saves it into the
// backups folder, and returns its filename so the caller can restore from
// it via restoreBackup().
const SQLITE_MAGIC = "SQLite format 3\u0000";
export function saveUploadedBackup(buffer) {
  if (!buffer || buffer.length < 16) {
    throw new Error("Uploaded file is empty or too small to be a valid backup");
  }
  const header = buffer.subarray(0, 16).toString("utf8");
  if (header !== SQLITE_MAGIC) {
    throw new Error("This doesn't look like a valid AnshAPI backup file (.db)");
  }
  const filename = `anshapi-backup-${backupTimestamp()}-uploaded.db`;
  const full = path.join(BACKUPS_DIR, filename);
  fs.writeFileSync(full, buffer);
  try {
    assertValidBackupFile(full);
  } catch (e) {
    fs.unlinkSync(full); // never keep a rejected upload around
    throw e;
  }
  return filename;
}

// ==================== SCHEMA ====================
// NOTE: Written in SQLite for zero-setup local/dev use. The schema below
// maps 1:1 onto PostgreSQL — swap the `db` driver for `pg` and this data
// model carries over unchanged.

const BASE_SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  name TEXT DEFAULT 'Admin',
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS apis (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  slug TEXT UNIQUE NOT NULL,
  description TEXT DEFAULT '',
  upstream_url TEXT NOT NULL,
  method TEXT NOT NULL DEFAULT 'GET',
  auth_type TEXT NOT NULL DEFAULT 'none', -- none | api_key | bearer | custom_header | custom_query
  auth_config TEXT DEFAULT '{}', -- JSON, encrypted secret fields inside
  response_type TEXT NOT NULL DEFAULT 'auto', -- json | text | binary | auto
  timeout_ms INTEGER DEFAULT 10000,
  retry_count INTEGER DEFAULT 0,
  retry_delay_ms INTEGER DEFAULT 500,
  cache_enabled INTEGER DEFAULT 0,
  cache_duration_ms INTEGER DEFAULT 0,
  response_wrapper_enabled INTEGER DEFAULT 1,
  transform_enabled INTEGER DEFAULT 0,
  transform_rules TEXT DEFAULT '[]',
  static_query_params TEXT DEFAULT '[]',
  status TEXT NOT NULL DEFAULT 'active', -- active | disabled
  created_by INTEGER REFERENCES users(id),
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_apis_slug ON apis(slug);

CREATE TABLE IF NOT EXISTS api_parameters (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  api_id INTEGER NOT NULL REFERENCES apis(id) ON DELETE CASCADE,
  public_name TEXT NOT NULL,
  upstream_name TEXT NOT NULL,
  location TEXT NOT NULL DEFAULT 'query', -- query | body | path
  required INTEGER DEFAULT 0,
  default_value TEXT DEFAULT NULL
);
CREATE INDEX IF NOT EXISTS idx_params_api ON api_parameters(api_id);

CREATE TABLE IF NOT EXISTS api_headers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  api_id INTEGER NOT NULL REFERENCES apis(id) ON DELETE CASCADE,
  header_name TEXT NOT NULL,
  header_value TEXT NOT NULL, -- encrypted if sensitive
  is_sensitive INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_headers_api ON api_headers(api_id);

CREATE TABLE IF NOT EXISTS api_limits (
  api_id INTEGER PRIMARY KEY REFERENCES apis(id) ON DELETE CASCADE,
  per_minute INTEGER DEFAULT 60,
  per_hour INTEGER DEFAULT 1000,
  per_day INTEGER DEFAULT 10000,
  max_concurrent INTEGER DEFAULT 5,
  max_response_size_bytes INTEGER DEFAULT 5242880,
  max_request_body_bytes INTEGER DEFAULT 1048576,
  ip_limit_per_minute INTEGER DEFAULT 30,
  global_limit_per_minute INTEGER DEFAULT 0 -- 0 = unlimited
);

CREATE TABLE IF NOT EXISTS api_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  key_prefix TEXT NOT NULL,
  key_hash TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active', -- active | revoked
  expires_at TEXT DEFAULT NULL,
  requests_per_day INTEGER DEFAULT 0,
  requests_per_month INTEGER DEFAULT 0,
  allowed_apis TEXT DEFAULT 'all', -- 'all' or JSON array of api ids
  ip_whitelist TEXT DEFAULT '[]',
  ip_blacklist TEXT DEFAULT '[]',
  created_at TEXT DEFAULT (datetime('now')),
  last_used_at TEXT DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS api_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  api_id INTEGER REFERENCES apis(id) ON DELETE SET NULL,
  api_key_id INTEGER REFERENCES api_keys(id) ON DELETE SET NULL,
  method TEXT,
  ip_address TEXT,
  user_agent TEXT,
  status_code INTEGER,
  response_time_ms INTEGER,
  response_size_bytes INTEGER,
  error_message TEXT DEFAULT NULL,
  success INTEGER DEFAULT 1,
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_requests_api ON api_requests(api_id);
CREATE INDEX IF NOT EXISTS idx_requests_key ON api_requests(api_key_id);
CREATE INDEX IF NOT EXISTS idx_requests_created ON api_requests(created_at);
CREATE INDEX IF NOT EXISTS idx_requests_ip ON api_requests(ip_address);
CREATE INDEX IF NOT EXISTS idx_requests_status ON api_requests(status_code);

CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER REFERENCES users(id),
  action TEXT NOT NULL,
  target TEXT,
  meta TEXT DEFAULT '{}',
  ip_address TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS schema_migrations (
  name TEXT PRIMARY KEY,
  applied_at TEXT DEFAULT (datetime('now'))
);
`;

function hasColumn(table, column) {
  return raw.prepare(`PRAGMA table_info(${table})`).all().some((c) => c.name === column);
}
function addColumnIfMissing(table, columnDef) {
  const name = columnDef.split(/\s+/)[0];
  if (!hasColumn(table, name)) raw.exec(`ALTER TABLE ${table} ADD COLUMN ${columnDef}`);
}

// Ordered, append-only list. Each migration runs exactly once per database
// (recorded in schema_migrations) inside a transaction, and only ever
// ADDS columns/indexes or rewrites derived data — existing rows are never
// deleted. ensureSchema() also re-runs after a backup restore, so an old
// backup is upgraded in place.
const MIGRATIONS = [
  {
    name: "001_legacy_api_columns",
    up() {
      addColumnIfMissing("apis", "transform_rules TEXT DEFAULT '[]'");
      addColumnIfMissing("apis", "static_query_params TEXT DEFAULT '[]'");
    },
  },
  {
    name: "002_request_log_v2",
    up() {
      // Full request context per log line. api_slug/api_name are snapshots,
      // so a log still says which API it belonged to after that API is
      // renamed or deleted (api_id becomes NULL on delete).
      addColumnIfMissing("api_requests", "request_id TEXT");
      addColumnIfMissing("api_requests", "api_slug TEXT");
      addColumnIfMissing("api_requests", "api_name TEXT");
      addColumnIfMissing("api_requests", "path TEXT");
      addColumnIfMissing("api_requests", "query_string TEXT"); // redacted JSON
      addColumnIfMissing("api_requests", "request_body TEXT"); // redacted, size-capped JSON
      addColumnIfMissing("api_requests", "request_headers TEXT"); // allow-listed, redacted JSON
      addColumnIfMissing("api_requests", "referrer TEXT");
      addColumnIfMissing("api_requests", "api_key_prefix TEXT");
      addColumnIfMissing("api_requests", "cache_hit INTEGER DEFAULT 0");

      raw.exec(`
        CREATE INDEX IF NOT EXISTS idx_requests_api_created ON api_requests(api_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_requests_ip_created ON api_requests(ip_address, created_at);
        CREATE INDEX IF NOT EXISTS idx_requests_success_created ON api_requests(success, created_at);
        CREATE INDEX IF NOT EXISTS idx_requests_method ON api_requests(method);
        CREATE INDEX IF NOT EXISTS idx_requests_request_id ON api_requests(request_id);
      `);

      // Backfill snapshots for historical rows whose API still exists.
      raw.exec(`
        UPDATE api_requests
           SET api_slug = (SELECT slug FROM apis WHERE apis.id = api_requests.api_id),
               api_name = (SELECT name FROM apis WHERE apis.id = api_requests.api_id)
         WHERE api_id IS NOT NULL AND api_slug IS NULL;
        UPDATE api_requests SET path = '/api/' || api_slug WHERE path IS NULL AND api_slug IS NOT NULL;
      `);
    },
  },
  {
    name: "003_api_key_prefix_hardening",
    up() {
      // Custom keys used to store their first 12 characters as the "prefix" —
      // for any custom key of 12 characters or fewer that was the ENTIRE
      // secret, shown in the key list. Shrink those prefixes. When the stored
      // prefix is shorter than 12 chars, it IS the whole key, so its length
      // tells us the key length; otherwise 4 chars is a safe hint.
      const rows = raw.prepare("SELECT id, key_prefix FROM api_keys WHERE key_prefix NOT LIKE 'sk_live_%'").all();
      const upd = raw.prepare("UPDATE api_keys SET key_prefix = ? WHERE id = ?");
      for (const r of rows) {
        const len = r.key_prefix.length;
        const keep = len < 12 ? Math.max(1, Math.floor(len / 3)) : 4;
        upd.run(r.key_prefix.slice(0, keep), r.id);
      }
    },
  },
];

function runMigrations() {
  const applied = new Set(raw.prepare("SELECT name FROM schema_migrations").all().map((r) => r.name));
  for (const m of MIGRATIONS) {
    if (applied.has(m.name)) continue;
    raw.exec("BEGIN");
    try {
      m.up();
      raw.prepare("INSERT INTO schema_migrations (name) VALUES (?)").run(m.name);
      raw.exec("COMMIT");
      console.log(`[db] applied migration ${m.name}`);
    } catch (e) {
      try {
        raw.exec("ROLLBACK");
      } catch {
        /* ignore */
      }
      throw new Error(`Migration ${m.name} failed: ${e.message}`);
    }
  }
}

function ensureSchema() {
  raw.exec(BASE_SCHEMA);
  runMigrations();
}

ensureSchema();

export default db;

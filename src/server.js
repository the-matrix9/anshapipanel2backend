import "dotenv/config";
import express from "express";
import helmet from "helmet";
import cors from "cors";
import cookieParser from "cookie-parser";
import rateLimit from "express-rate-limit";
import { db, createBackup, pruneBackups } from "./db/index.js"; // importing this creates/migrates the schema

import authRoutes from "./routes/auth.js";
import apiRoutes from "./routes/apis.js";
import apiKeyRoutes from "./routes/apiKeys.js";
import logRoutes from "./routes/logs.js";
import analyticsRoutes from "./routes/analytics.js";
import docsRoutes from "./routes/docs.js";
import proxyRoutes from "./routes/proxy.js";
import backupRoutes from "./routes/backups.js";
import systemRoutes from "./routes/system.js";
import { requireCsrfHeader } from "./middleware/auth.js";
import { apiRequestLogger, assignRequestId } from "./middleware/requestLogger.js";
import { errorHandler, notFoundHandler } from "./middleware/errors.js";
import { parseTrustProxy } from "./lib/clientIp.js";

// ---- Refuse to boot in production with default/placeholder secrets ----
// These two secrets protect every admin session (JWT_SECRET) and every
// encrypted header/auth-config/static-param value at rest
// (ENCRYPTION_KEY). Shipping with the example placeholders in production
// would mean anyone who's seen this codebase could forge sessions or
// decrypt secrets.
if (process.env.NODE_ENV === "production") {
  const insecureDefaults = {
    JWT_SECRET: "insecure_dev_secret_change_me",
    ENCRYPTION_KEY: "insecure_dev_key_change_me",
  };
  const problems = [];
  for (const [name, placeholder] of Object.entries(insecureDefaults)) {
    const value = process.env[name];
    if (!value || value === placeholder || value.includes("change_this")) {
      problems.push(name);
    }
  }
  if (problems.length) {
    console.error(
      `[fatal] Refusing to start in production with insecure/placeholder value(s) for: ${problems.join(
        ", "
      )}. Set strong random values for these in your environment (e.g. \`openssl rand -hex 32\`) before deploying.`
    );
    process.exit(1);
  }
}

const app = express();
app.disable("x-powered-by");

// ---- Client IP / reverse-proxy trust ----
// See lib/clientIp.js. Behind Railway alone: 1 (default). Vercel rewrite ->
// Railway, or Cloudflare -> host: 2. Never `true`.
let trust;
try {
  trust = parseTrustProxy(process.env.TRUST_PROXY ?? process.env.TRUST_PROXY_HOPS);
} catch (e) {
  console.error(`[fatal] ${e.message}`);
  process.exit(1);
}
if (trust.warning) console.warn(`[proxy] ${trust.warning}`);
app.set("trust proxy", trust.setting);
app.set("trust proxy config", trust.description);
console.log(`[proxy] client IP detection: ${trust.description}`);

// FRONTEND_ORIGIN can be a single URL or a comma-separated list — useful
// when the same backend serves a Vercel preview URL, a custom domain,
// and localhost during development all at once.
const allowedOrigins = (process.env.FRONTEND_ORIGIN || "http://localhost:5173")
  .split(",")
  .map((o) => o.trim())
  .filter(Boolean);

// Public-proxy logging goes FIRST so it observes every outcome, including
// requests rejected by CORS or the body parser further down the chain.
app.use("/api", apiRequestLogger);

app.use(helmet({ crossOriginResourcePolicy: { policy: "cross-origin" } }));
app.use(
  cors({
    origin(origin, callback) {
      // No Origin header (curl, server-to-server, same-origin) — allow.
      if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
      callback(new Error("Not allowed by CORS"));
    },
    credentials: true,
    exposedHeaders: ["X-Request-Id", "Content-Disposition"],
  })
);
app.use(cookieParser());
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true, limit: "2mb" }));

app.get("/health", (req, res) => {
  let dbOk = true;
  try {
    db.prepare("SELECT 1").get();
  } catch {
    dbOk = false;
  }
  res.status(dbOk ? 200 : 503).json({ status: dbOk, data: { uptime: process.uptime(), db: dbOk ? "ok" : "unavailable" } });
});

// ---- Admin API ----
app.use("/admin", assignRequestId);
// Admin responses are per-user and often sensitive — never let a browser or
// shared cache keep them.
app.use("/admin", (req, res, next) => {
  res.setHeader("Cache-Control", "no-store");
  next();
});

// Moderate, generous rate limit across the whole admin API — not meant to
// throttle normal dashboard usage, just to slow down credential-stuffing
// or scripted enumeration if a session is ever compromised.
app.use(
  "/admin",
  rateLimit({
    windowMs: 60_000,
    max: 600,
    standardHeaders: true,
    legacyHeaders: false,
    message: { status: false, error: "Too many requests, please slow down", code: "RATE_LIMITED" },
  })
);

// Brute-force protection on the admin login endpoint only. The PUBLIC
// proxy endpoints (/api/*) are deliberately NOT rate-limited here — each
// API's own admin-configured limits in routes/proxy.js are the single
// source of truth for how much traffic it accepts.
app.use(
  "/admin/auth/login",
  rateLimit({
    windowMs: 15 * 60_000,
    max: 20,
    standardHeaders: true,
    legacyHeaders: false,
    message: { status: false, error: "Too many login attempts, try again later", code: "RATE_LIMITED", credit: "@shreeapi" },
  })
);

app.use("/admin", requireCsrfHeader);
app.use("/admin/auth", authRoutes);
app.use("/admin/apis", apiRoutes);
app.use("/admin/api-keys", apiKeyRoutes);
app.use("/admin/logs", logRoutes);
app.use("/admin/analytics", analyticsRoutes);
app.use("/admin/docs", docsRoutes);
app.use("/admin/backups", backupRoutes);
app.use("/admin/system", systemRoutes);

// ---- Public proxy engine ----
app.use("/api", proxyRoutes);

app.use(notFoundHandler);
app.use(errorHandler);

const PORT = process.env.PORT || 4000;
const server = app.listen(PORT, () => {
  console.log(`AnshAPI backend running on port ${PORT}`);
});

// ---- Automated backups ----
// Every API config and every logged request lives in one SQLite file, so
// a full, restorable backup is just a scheduled snapshot of it.
const BACKUP_INTERVAL_MS = 6 * 60 * 60 * 1000; // every 6 hours
function runScheduledBackup() {
  try {
    const info = createBackup();
    pruneBackups(30); // keep the most recent 30 automatic+manual backups
    console.log(`[backup] created ${info.filename} (${(info.size_bytes / 1024).toFixed(1)} KB)`);
  } catch (e) {
    // A failed backup must never take the API down — log and keep serving.
    console.error("[backup] scheduled backup failed:", e.message);
  }
}
if (process.env.DISABLE_SCHEDULED_BACKUPS !== "true") {
  setTimeout(runScheduledBackup, 15_000).unref(); // first backup shortly after boot
  setInterval(runScheduledBackup, BACKUP_INTERVAL_MS).unref();
}

// ---- Optional log retention ----
// Off by default: request logs are never deleted unless you opt in with
// LOG_RETENTION_DAYS (e.g. 90).
const retentionDays = Number.parseInt(process.env.LOG_RETENTION_DAYS || "0", 10);
if (retentionDays > 0) {
  const prune = () => {
    try {
      const r = db
        .prepare("DELETE FROM api_requests WHERE created_at < datetime('now', ?)")
        .run(`-${retentionDays} days`);
      if (r.changes) console.log(`[retention] removed ${r.changes} request logs older than ${retentionDays} days`);
    } catch (e) {
      console.error("[retention] prune failed:", e.message);
    }
  };
  setTimeout(prune, 60_000).unref();
  setInterval(prune, 24 * 60 * 60 * 1000).unref();
}

// ---- Graceful shutdown (Railway/Docker send SIGTERM on deploy) ----
for (const sig of ["SIGTERM", "SIGINT"]) {
  process.on(sig, () => {
    console.log(`[shutdown] ${sig} received, closing server…`);
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 10_000).unref();
  });
}

// ---- Crash-proofing at scale ----
// A single unexpected error from one request must never crash the whole
// process and drop every other in-flight/future request. Every route
// already guards its own logic, but these are the last line of defense.
process.on("uncaughtException", (err) => {
  console.error("[fatal-guard] uncaughtException (server kept running):", err);
});
process.on("unhandledRejection", (reason) => {
  console.error("[fatal-guard] unhandledRejection (server kept running):", reason);
});

import { Router } from "express";
import express from "express";
import jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";
import {
  requireAuth,
  signDownloadTicket,
  verifyDownloadTicket,
  DOWNLOAD_TICKET_TTL_S,
} from "../middleware/auth.js";
import { HttpError, asyncHandler } from "../middleware/errors.js";
import { createBackup, listBackups, pruneBackups, getBackupPath, restoreBackup, saveUploadedBackup } from "../db/index.js";
import { db } from "../db/index.js";
import { getClientIp } from "../lib/clientIp.js";
import { clearCache } from "../lib/ttlCache.js";

const router = Router();

// Backups touch disk and can restore/replace the entire database — worth
// a tighter limit than ordinary admin reads, so a mistake (or a
// compromised session) can't be used to spam backups or hammer restores.
const backupActionLimiter = rateLimit({
  windowMs: 60 * 60_000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { status: false, error: "Too many backup operations — please wait a bit and try again", code: "RATE_LIMITED" },
});
const downloadLimiter = rateLimit({
  windowMs: 60 * 60_000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { status: false, error: "Too many backup downloads — please wait a bit and try again", code: "RATE_LIMITED" },
});

const audit = (req, userId, action, target) =>
  db
    .prepare("INSERT INTO audit_logs (user_id, action, target, ip_address) VALUES (?, ?, ?, ?)")
    .run(userId, action, target, getClientIp(req));

// ---------------------------------------------------------------------------
// DOWNLOAD
//
// Two ways to authenticate a download, both fully server-verified:
//
//  1. The admin session cookie (works whenever the browser sends it — e.g.
//     when you open the URL on the same domain the dashboard is served from).
//  2. A short-lived, single-use ?ticket= obtained from
//     POST /admin/backups/:filename/download-link over the dashboard's normal
//     authenticated request. This is what the dashboard uses: a plain
//     browser navigation to another domain (e.g. the Railway URL instead of
//     the Vercel one) does NOT carry the dashboard's cookie, which is exactly
//     why opening a backup URL directly used to answer "Not authenticated".
//
// With neither, the answer is 401 — the file is never served publicly.
// ---------------------------------------------------------------------------
function serveBackup(req, res, next) {
  const filename = req.params.filename;

  // Authenticate FIRST, look at the filesystem second — otherwise an
  // unauthenticated caller could tell existing backups from missing ones.
  const proceed = (userId) => {
    const full = getBackupPath(filename);
    if (!full) return next(new HttpError(404, "Backup not found", "NOT_FOUND"));
    return sendFile(req, res, userId, full, filename);
  };

  const ticket = typeof req.query.ticket === "string" ? req.query.ticket : null;
  if (ticket) {
    try {
      return proceed(verifyDownloadTicket(ticket, filename).sub);
    } catch (e) {
      const expired = e instanceof jwt.TokenExpiredError;
      return res.status(401).json({
        status: false,
        error: expired
          ? "This download link has expired — go back to Settings → Backups and click Download again"
          : "This download link is invalid or was already used — go back to Settings → Backups and click Download again",
        code: expired ? "TICKET_EXPIRED" : "TICKET_INVALID",
      });
    }
  }
  return requireAuth(req, res, () => proceed(req.user.sub));
}

function sendFile(req, res, userId, full, filename) {
  audit(req, userId, "download_backup", filename);
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.download(full, filename, (err) => {
    if (err && !res.headersSent) {
      res.status(500).json({ status: false, error: "Could not read the backup file", code: "READ_FAILED" });
    }
  });
}

// NOTE: registered BEFORE the router-wide auth guard below — these two are
// authenticated inside serveBackup (cookie OR ticket).
router.get("/:filename/download", downloadLimiter, serveBackup);
// Short alias: GET /admin/backups/<backup-file>
router.get("/:filename", downloadLimiter, serveBackup);

// ---- everything below requires a normal admin session ----------------------
router.use(requireAuth);

router.get("/", (req, res) => {
  res.json({ status: true, data: listBackups() });
});

router.post("/", backupActionLimiter, (req, res) => {
  const info = createBackup();
  pruneBackups(30);
  audit(req, req.user.sub, "manual_backup", info.filename);
  res.status(201).json({ status: true, data: info });
});

router.post("/:filename/download-link", downloadLimiter, (req, res) => {
  if (!getBackupPath(req.params.filename)) throw new HttpError(404, "Backup not found", "NOT_FOUND");
  const ticket = signDownloadTicket({ sub: req.user.sub, file: req.params.filename });
  res.setHeader("Cache-Control", "no-store");
  res.json({
    status: true,
    data: {
      // relative, so the dashboard resolves it against whichever backend base URL it talks to
      url: `/admin/backups/${encodeURIComponent(req.params.filename)}/download?ticket=${encodeURIComponent(ticket)}`,
      expires_in: DOWNLOAD_TICKET_TTL_S,
    },
  });
});

router.post("/:filename/restore", backupActionLimiter, (req, res) => {
  const result = restoreBackup(req.params.filename);
  clearCache();
  audit(req, req.user.sub, "restore_backup", req.params.filename);
  res.json({ status: true, data: { ...result, message: "Database restored successfully." } });
});

// Restore from a backup file the admin uploads from their own computer
// (e.g. one they previously downloaded) — saves it, validates it's a
// real, intact AnshAPI database, then restores immediately so every API,
// key, parameter mapping and limit comes back exactly as it was.
router.post(
  "/upload",
  backupActionLimiter,
  express.raw({ type: "*/*", limit: "50mb" }),
  asyncHandler(async (req, res) => {
    if (!Buffer.isBuffer(req.body) || req.body.length === 0) {
      throw new HttpError(400, "No file data received", "NO_FILE");
    }
    let savedFilename;
    try {
      savedFilename = saveUploadedBackup(req.body);
    } catch (e) {
      throw new HttpError(400, e.message, "INVALID_BACKUP");
    }
    let result;
    try {
      result = restoreBackup(savedFilename);
    } catch (e) {
      throw new HttpError(400, e.message, "INVALID_BACKUP");
    }
    clearCache();
    pruneBackups(30);
    audit(req, req.user.sub, "upload_restore_backup", savedFilename);
    res.json({
      status: true,
      data: { ...result, filename: savedFilename, message: "Backup uploaded and restored successfully." },
    });
  })
);

export default router;

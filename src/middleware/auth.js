import crypto from "crypto";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import { db } from "../db/index.js";
dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET || "insecure_dev_secret_change_me";
const ALGS = ["HS256"];

export function signToken(user) {
  return jwt.sign({ sub: user.id, email: user.email }, JWT_SECRET, { algorithm: "HS256", expiresIn: "12h" });
}

// Vercel (frontend) and Railway (backend) can be different domains, and a
// cross-site cookie is only accepted by browsers when it's SameSite=None AND
// Secure. Whenever COOKIE_SECURE=true (i.e. you're on HTTPS) we default to
// "none" so login persists across the two domains; local dev stays "lax".
// Override with COOKIE_SAMESITE=lax|strict|none — e.g. "lax" is the safer
// choice when the dashboard proxies /admin through its own domain (the
// Vercel rewrite setup), because then the cookie is first-party.
const isSecure = process.env.COOKIE_SECURE === "true";
const envSameSite = (process.env.COOKIE_SAMESITE || "").toLowerCase();
const sameSite = ["lax", "strict", "none"].includes(envSameSite) ? envSameSite : isSecure ? "none" : "lax";

export const cookieOptions = {
  httpOnly: true,
  secure: isSecure || sameSite === "none",
  sameSite,
  maxAge: 12 * 60 * 60 * 1000,
  path: "/",
};
export const clearCookieOptions = { ...cookieOptions, maxAge: undefined };

function unauthorized(res, error, code) {
  return res.status(401).json({ status: false, error, code });
}

export function requireAuth(req, res, next) {
  const token = req.cookies?.token;
  if (!token) return unauthorized(res, "Not authenticated — please sign in", "NOT_AUTHENTICATED");
  try {
    const payload = jwt.verify(token, JWT_SECRET, { algorithms: ALGS });
    // A valid signature isn't enough: the account must still exist (it may
    // have been removed, or the database restored from another backup).
    const exists = db.prepare("SELECT id FROM users WHERE id = ?").get(payload.sub);
    if (!exists) {
      res.clearCookie("token", clearCookieOptions);
      return unauthorized(res, "Your account no longer exists — please sign in again", "INVALID_SESSION");
    }
    req.user = payload;
    next();
  } catch (e) {
    res.clearCookie("token", clearCookieOptions);
    if (e?.name === "TokenExpiredError") {
      return unauthorized(res, "Your session has expired — please sign in again", "SESSION_EXPIRED");
    }
    return unauthorized(res, "Invalid session — please sign in again", "INVALID_SESSION");
  }
}

// ---- CSRF ------------------------------------------------------------------
// The auth cookie can be SameSite=None, so a hostile site could otherwise
// make a logged-in admin's browser fire state-changing requests. Browsers
// will not let another origin attach a custom header without a CORS
// preflight, which our CORS policy refuses for unknown origins — so
// requiring this header on every non-GET admin request closes that hole.
// The dashboard's axios client sends it automatically.
export function requireCsrfHeader(req, res, next) {
  if (req.method === "GET" || req.method === "HEAD" || req.method === "OPTIONS") return next();
  if (req.headers["x-requested-with"] === "XMLHttpRequest") return next();
  return res.status(403).json({
    status: false,
    error: "Missing X-Requested-With: XMLHttpRequest header (CSRF protection)",
    code: "CSRF_HEADER_REQUIRED",
  });
}

// ---- Backup download tickets ---------------------------------------------
// A browser download is a plain navigation, so it can't carry the
// dashboard's XHR credentials reliably (cookies are per-domain, and
// third-party cookies are blocked by many browsers). The dashboard first
// asks for a ticket over its normal authenticated XHR; the ticket is a
// signed, 60-second, single-use token bound to ONE backup file, so the
// resulting URL can be opened by a plain navigation — and is useless to
// anyone else a minute later.
const TICKET_TTL_S = 60;
const usedTickets = new Map(); // jti -> expiry (ms)

export function signDownloadTicket({ sub, file }) {
  return jwt.sign({ typ: "backup-dl", sub, file }, JWT_SECRET, {
    algorithm: "HS256",
    expiresIn: TICKET_TTL_S,
    jwtid: crypto.randomBytes(12).toString("hex"),
  });
}

export function verifyDownloadTicket(token, file) {
  const now = Date.now();
  for (const [jti, exp] of usedTickets) if (exp <= now) usedTickets.delete(jti);
  const p = jwt.verify(token, JWT_SECRET, { algorithms: ALGS });
  if (p.typ !== "backup-dl" || p.file !== file) throw new Error("ticket does not match this file");
  if (usedTickets.has(p.jti)) throw new Error("ticket already used");
  usedTickets.set(p.jti, now + TICKET_TTL_S * 1000);
  return p;
}

export const DOWNLOAD_TICKET_TTL_S = TICKET_TTL_S;

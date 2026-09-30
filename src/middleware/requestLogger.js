import crypto from "crypto";
import { db } from "../db/index.js";
import { getClientIp } from "../lib/clientIp.js";
import { pickSafeHeaders, redactString, toSafeJson } from "../lib/redact.js";
import { incrementAndCheck } from "../lib/rateLimiter.js";

// ---------------------------------------------------------------------------
// Central request logging for the public proxy (/api/*).
//
//   incoming request
//        -> assign request id, start the clock          (this middleware)
//        -> ...body parsing, CORS, the proxy handler...
//        -> response finishes / connection closes       (res 'finish'/'close')
//        -> status, latency, size, error are known
//        -> write ONE row to api_requests
//
// Because it hooks the response lifecycle rather than being called from
// inside handlers, EVERY outcome is captured — 2xx, upstream errors and
// timeouts, 4xx validation/auth/rate-limit rejections, disabled APIs,
// malformed JSON, CORS refusals, and clients that hang up early. Handlers
// only enrich the record via `req.apiLog` (api, apiKey, error, cacheHit).
//
// A failure to write the log is caught and reported to stderr; it can never
// alter or delay the response the caller already received.
// ---------------------------------------------------------------------------

const STATUS_TEXT = {
  400: "Bad request",
  401: "Unauthorized",
  403: "Forbidden",
  404: "Not found",
  405: "Method not allowed",
  413: "Payload too large",
  429: "Rate limit exceeded",
  499: "Client closed the connection before the response completed",
  500: "Internal server error",
  502: "Bad gateway",
  503: "Service unavailable",
};

function newRequestId() {
  return "req_" + crypto.randomBytes(9).toString("base64url");
}

/** "/api/num4" -> "num4"; anything that isn't exactly /api/<slug> -> null. */
function slugFromPath(pathname) {
  const parts = pathname.split("/").filter(Boolean);
  if (parts.length !== 2 || parts[0] !== "api") return null;
  try {
    return decodeURIComponent(parts[1]).slice(0, 100);
  } catch {
    return null;
  }
}

function flattenQueryForLog(query) {
  return query && typeof query === "object" && Object.keys(query).length ? query : null;
}

function writeLog(req, res, startNs, aborted) {
  const latencyMs = Math.max(0, Math.round(Number(process.hrtime.bigint() - startNs) / 1e6));
  const ctx = req.apiLog || {};
  const pathname = (req.originalUrl || req.url || "").split("?")[0].slice(0, 300);
  const slug = ctx.api?.slug || slugFromPath(pathname);

  // Resolve the API when the handler never got as far as loading it
  // (e.g. a JSON parse error rejected the request first).
  let api = ctx.api || null;
  if (!api && slug) {
    api = db.prepare("SELECT id, slug, name FROM apis WHERE slug = ?").get(slug) || null;
  }

  // Scanners hammering random /api/<garbage> URLs must not be able to
  // flood the log table: unknown slugs are logged, but capped.
  if (!api && !incrementAndCheck("log:unknown-api", 120, 60_000).allowed) return;

  const status = aborted ? 499 : res.statusCode;
  const success = status < 400;
  let error = ctx.error || null;
  if (!error && !success) error = STATUS_TEXT[status] || `HTTP ${status}`;
  if (!api && !error && slug) error = `API "${slug}" not found`;

  const contentType = String(req.headers["content-type"] || "");
  const hasBody = /json|urlencoded/i.test(contentType) && req.body && typeof req.body === "object";

  db.prepare(
    `INSERT INTO api_requests
       (request_id, api_id, api_slug, api_name, api_key_id, api_key_prefix, method, path, query_string,
        request_body, request_headers, referrer, ip_address, user_agent, status_code, response_time_ms,
        response_size_bytes, error_message, success, cache_hit)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
  ).run(
    req.requestId,
    api?.id ?? null,
    api?.slug ?? slug ?? null,
    api?.name ?? null,
    ctx.apiKey?.id ?? null,
    ctx.apiKey?.prefix ?? null,
    req.method,
    pathname,
    toSafeJson(flattenQueryForLog(req.query), 2000),
    hasBody ? toSafeJson(req.body, 4000) : null,
    toSafeJson(pickSafeHeaders(req.headers), 2000),
    req.headers.referer ? redactString(req.headers.referer, 500) : null,
    getClientIp(req),
    req.headers["user-agent"] ? String(req.headers["user-agent"]).slice(0, 400) : null,
    status,
    latencyMs,
    Number(res.getHeader("content-length")) || 0,
    error ? String(error).slice(0, 500) : null,
    success ? 1 : 0,
    ctx.cacheHit ? 1 : 0
  );
}

export function apiRequestLogger(req, res, next) {
  // CORS preflights aren't API calls.
  if (req.method === "OPTIONS") return next();

  const startNs = process.hrtime.bigint();
  req.requestId = newRequestId();
  req.apiLog = {};
  res.setHeader("X-Request-Id", req.requestId);

  let written = false;
  const finish = (aborted) => {
    if (written) return;
    written = true;
    try {
      writeLog(req, res, startNs, aborted);
    } catch (e) {
      console.error(`[request-log] write failed for ${req.requestId} (non-fatal):`, e.message);
    }
  };
  res.on("finish", () => finish(false));
  res.on("close", () => finish(!res.writableFinished));
  next();
}

/** Assigns a request id for /admin routes too, so errors there are traceable. */
export function assignRequestId(req, res, next) {
  if (!req.requestId) {
    req.requestId = newRequestId();
    res.setHeader("X-Request-Id", req.requestId);
  }
  next();
}

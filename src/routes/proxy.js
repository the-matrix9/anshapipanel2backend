import { Router } from "express";
import { upstreamClient } from "../lib/httpClient.js";
import { db } from "../db/index.js";
import { decrypt, hashApiKey } from "../lib/crypto.js";
import { assertSafeUpstreamUrl } from "../lib/ssrfGuard.js";
import { incrementAndCheck } from "../lib/rateLimiter.js";
import { applyAuth } from "./apis.js";
import { getClientIp, normalizeIpList } from "../lib/clientIp.js";

const router = Router();

// Simple in-memory response cache: cacheKey -> { expiresAt, payload }
const responseCache = new Map();

function creditWrap(status, payload, credit = "@shreeapi") {
  if (status) return { status: true, data: payload, credit };
  return { status: false, error: payload, credit };
}

// Applies admin-configured response transform rules to a successful
// upstream JSON response: "remove" drops a top-level field by name
// (matched by exact key), "add" injects a new top-level field with a
// given value (JSON-parsed when possible, so numbers/booleans/objects
// work — falls back to a plain string otherwise). Never touches
// non-object payloads (arrays, binary, plain text) or failed responses.
function applyResponseTransform(data, rules) {
  if (!rules || !rules.length) return data;
  if (data === null || typeof data !== "object" || Array.isArray(data)) return data;

  const out = { ...data };
  for (const rule of rules) {
    if (!rule?.field) continue;
    if (rule.action === "remove") {
      delete out[rule.field];
    } else if (rule.action === "add") {
      let value = rule.value;
      if (typeof value === "string") {
        try {
          value = JSON.parse(value);
        } catch {
          /* keep as plain string */
        }
      }
      out[rule.field] = value;
    }
  }
  return out;
}

function resolveApiKey(req) {
  const headerKey = req.headers["authorization"]?.replace(/^Bearer\s+/i, "");
  const queryKey = req.query.apikey || req.query.api_key || req.query.key;
  const rawKey = headerKey || queryKey;
  if (!rawKey) return { rawKey: null, record: null };
  const hash = hashApiKey(rawKey);
  const record = db.prepare("SELECT * FROM api_keys WHERE key_hash = ?").get(hash);
  return { rawKey, record };
}

router.all("/:slug", async (req, res) => {
  try {
    await handleProxyRequest(req, res);
  } catch (err) {
    // Absolute last line of defense: whatever went wrong, the caller
    // still gets a clean, credit-wrapped JSON response instead of a
    // hung connection or a crashed process.
    console.error("[proxy] unexpected error handling request:", err);
    if (!res.headersSent) {
      res.status(500).json(creditWrap(false, "Internal server error"));
    }
  }
});

// Request logging is done centrally by middleware/requestLogger.js, which
// records the final status, latency and size of EVERY response. Handlers
// only describe *why* something failed via `reject()` so the log line
// carries a specific error message rather than a bare status code.
function reject(req, res, status, logMessage, body) {
  if (req.apiLog) req.apiLog.error = logMessage;
  return res.status(status).json(body);
}

async function handleProxyRequest(req, res) {
  // Normalised, proxy-aware client IP (see lib/clientIp.js) — never a raw,
  // client-supplied X-Forwarded-For value.
  const ip = getClientIp(req);
  const method = req.method;

  const api = db.prepare("SELECT * FROM apis WHERE slug = ?").get(req.params.slug);
  if (!api) {
    return reject(req, res, 404, `API "${req.params.slug}" not found`, creditWrap(false, "API not found"));
  }
  req.apiLog.api = { id: api.id, slug: api.slug, name: api.name };
  if (api.status !== "active") {
    return reject(req, res, 503, "API disabled", creditWrap(false, "This API is currently disabled"));
  }
  if (api.method !== method) {
    return reject(req, res, 405, `Method ${method} not allowed (API expects ${api.method})`, creditWrap(false, `Method not allowed. Expected ${api.method}`));
  }

  // ---- API key resolution & validation ----
  let apiKeyRecord = null;
  if (api.auth_type !== "none" || req.query.apikey || req.query.api_key || req.query.key || req.headers.authorization) {
    const { rawKey, record } = resolveApiKey(req);
    if (api.auth_type === "api_key" && !rawKey) {
      // api_key here refers to upstream auth, handled separately below; public-facing
      // key requirement is independent and governed by whether keys exist at all.
    }
    apiKeyRecord = record || null;

    if (rawKey && !record) {
      return reject(req, res, 401, "Invalid API key", creditWrap(false, "Invalid API key"));
    }
    if (record) {
      req.apiLog.apiKey = { id: record.id, prefix: record.key_prefix };
      if (record.status !== "active") {
        return reject(req, res, 403, `API key "${record.name}" is revoked`, creditWrap(false, "API key is revoked"));
      }
      if (record.expires_at && new Date(record.expires_at.includes("T") ? record.expires_at : record.expires_at.replace(" ", "T") + "Z") < new Date()) {
        return reject(req, res, 403, `API key "${record.name}" has expired`, creditWrap(false, "API key has expired"));
      }
      if (record.allowed_apis !== "all") {
        const allowed = JSON.parse(record.allowed_apis);
        if (!allowed.includes(api.id)) {
          return reject(req, res, 403, `API key "${record.name}" is not permitted for this API`, creditWrap(false, "API key is not permitted for this API"));
        }
      }
      const whitelist = normalizeIpList(JSON.parse(record.ip_whitelist || "[]"));
      const blacklist = normalizeIpList(JSON.parse(record.ip_blacklist || "[]"));
      if (blacklist.includes(ip)) {
        return reject(req, res, 403, `IP ${ip} is blacklisted for key "${record.name}"`, creditWrap(false, "IP is blacklisted for this key"));
      }
      if (whitelist.length && !whitelist.includes(ip)) {
        return reject(req, res, 403, `IP ${ip} is not whitelisted for key "${record.name}"`, creditWrap(false, "IP is not whitelisted for this key"));
      }
      try {
        db.prepare("UPDATE api_keys SET last_used_at = datetime('now') WHERE id = ?").run(record.id);
      } catch (e) {
        console.error("[proxy] could not update key last_used_at (non-fatal):", e.message);
      }
    }
  }

  // ---- Rate limiting ----
  const limits = db.prepare("SELECT * FROM api_limits WHERE api_id = ?").get(api.id) || {};
  const checks = [
    [`api:${api.id}:min`, limits.per_minute, 60_000],
    [`api:${api.id}:hour`, limits.per_hour, 3_600_000],
    [`api:${api.id}:day`, limits.per_day, 86_400_000],
    [`api:${api.id}:ip:${ip}:min`, limits.ip_limit_per_minute, 60_000],
    [`global:min`, limits.global_limit_per_minute, 60_000],
  ];
  if (apiKeyRecord) {
    checks.push([`key:${apiKeyRecord.id}:day`, apiKeyRecord.requests_per_day, 86_400_000]);
    checks.push([`key:${apiKeyRecord.id}:month`, apiKeyRecord.requests_per_month, 2_592_000_000]);
  }
  for (const [key, limit, windowMs] of checks) {
    const result = incrementAndCheck(key, limit, windowMs);
    if (!result.allowed) {
      const which = key.startsWith("global") ? "global" : key.includes(":ip:") ? "per-IP" : key.startsWith("key:") ? "API key" : "API";
      return reject(req, res, 429, `Rate limit exceeded (${which} limit, retry in ${result.retryAfterSeconds}s)`, {
        status: false,
        error: "Rate limit exceeded",
        retry_after: result.retryAfterSeconds,
        credit: "@shreeapi",
      });
    }
  }

  // ---- Parameter mapping ----
  const paramDefs = db.prepare("SELECT * FROM api_parameters WHERE api_id = ?").all(api.id);
  const incomingQuery = { ...req.query };
  delete incomingQuery.apikey;
  delete incomingQuery.api_key;
  delete incomingQuery.key;
  const incomingBody = req.body || {};

  const upstreamQuery = {};
  const upstreamBody = {};
  const missingRequired = [];

  if (paramDefs.length) {
    for (const p of paramDefs) {
      const source = p.location === "body" ? incomingBody : incomingQuery;
      let value = source[p.public_name];
      if (value === undefined && p.default_value !== null) value = p.default_value;
      if (value === undefined && p.required) missingRequired.push(p.public_name);
      if (value !== undefined) {
        if (p.location === "body") upstreamBody[p.upstream_name] = value;
        else upstreamQuery[p.upstream_name] = value;
      }
    }
  } else {
    // No explicit mapping configured — pass through as-is
    Object.assign(upstreamQuery, incomingQuery);
    Object.assign(upstreamBody, incomingBody);
  }

  if (missingRequired.length) {
    const msg = `Missing required parameter(s): ${missingRequired.join(", ")}`;
    return reject(req, res, 400, msg, creditWrap(false, msg));
  }

  // ---- Cache lookup ----
  const cacheKey = api.cache_enabled
    ? `${api.id}:${JSON.stringify(upstreamQuery)}:${JSON.stringify(upstreamBody)}`
    : null;
  if (cacheKey && responseCache.has(cacheKey)) {
    const cached = responseCache.get(cacheKey);
    if (cached.expiresAt > Date.now()) {
      req.apiLog.cacheHit = true;
      return res.status(200).json(cached.payload);
    }
    responseCache.delete(cacheKey);
  }

  // ---- Build headers + auth ----
  const headerDefs = db.prepare("SELECT * FROM api_headers WHERE api_id = ?").all(api.id);
  const upstreamHeaders = {};
  for (const h of headerDefs) {
    upstreamHeaders[h.header_name] = h.is_sensitive ? decrypt(h.header_value) : h.header_value;
  }
  const authConfig = JSON.parse(api.auth_config || "{}");
  applyAuth(api.auth_type, authConfig, upstreamHeaders, upstreamQuery);

  // ---- Static query params (e.g. an upstream that requires its own
  // fixed `key=...` on every call) — always injected, never overridable
  // or visible to the public caller. Applied after the caller's own
  // mapped parameters so a fixed admin-configured value always wins if
  // there's a name collision.
  try {
    const staticParams = JSON.parse(api.static_query_params || "[]");
    for (const p of staticParams) {
      upstreamQuery[p.name] = decrypt(p.value) ?? p.value;
    }
  } catch {
    /* malformed static params — proceed without them rather than failing the request */
  }

  // ---- SSRF re-check at request time (defends DNS rebinding) ----
  try {
    await assertSafeUpstreamUrl(api.upstream_url);
  } catch (e) {
    return reject(req, res, 502, `Upstream blocked: ${e.message}`, creditWrap(false, "Upstream is currently unreachable"));
  }

  // ---- Send upstream request with retry ----
  const maxAttempts = 1 + (api.retry_count || 0);
  let lastError = null;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const response = await upstreamClient({
        method: api.method,
        url: api.upstream_url,
        params: upstreamQuery,
        data: Object.keys(upstreamBody).length ? upstreamBody : undefined,
        headers: upstreamHeaders,
        timeout: api.timeout_ms,
        maxContentLength: limits.max_response_size_bytes || 5_242_880,
        maxBodyLength: limits.max_request_body_bytes || 1_048_576,
        validateStatus: () => true,
        responseType: api.response_type === "binary" ? "arraybuffer" : "json",
      });

      let upstreamData = response.data;
      if (
        api.transform_enabled &&
        response.status >= 200 &&
        response.status < 300 &&
        api.response_type !== "binary"
      ) {
        try {
          const rules = JSON.parse(api.transform_rules || "[]");
          upstreamData = applyResponseTransform(upstreamData, rules);
        } catch {
          /* malformed rules — fall through with the untransformed response
             rather than failing the request */
        }
      }
      const bodyForClient =
        api.response_wrapper_enabled && response.status >= 200 && response.status < 300
          ? creditWrap(true, upstreamData)
          : response.status >= 200 && response.status < 300
          ? upstreamData
          : creditWrap(false, typeof response.data === "object" ? JSON.stringify(response.data) : String(response.data));

      const sizeBytes = Buffer.byteLength(JSON.stringify(bodyForClient));
      if (response.status >= 400) req.apiLog.error = `Upstream returned ${response.status}`;

      if (cacheKey && api.cache_duration_ms > 0 && response.status < 400) {
        responseCache.set(cacheKey, { expiresAt: Date.now() + api.cache_duration_ms, payload: bodyForClient, size: sizeBytes });
      }

      return res.status(response.status).json(bodyForClient);
    } catch (err) {
      lastError = err;
      if (attempt < maxAttempts) {
        await new Promise((r) => setTimeout(r, api.retry_delay_ms || 500));
        continue;
      }
    }
  }

  const timedOut = lastError?.code === "ECONNABORTED" || lastError?.code === "ETIMEDOUT";
  const why = timedOut ? `Upstream timed out after ${api.timeout_ms}ms` : lastError?.message || "Upstream request failed";
  return reject(
    req,
    res,
    502,
    `${why}${maxAttempts > 1 ? ` (after ${maxAttempts} attempts)` : ""}`,
    creditWrap(false, "Upstream request failed after retries")
  );
}

export default router;

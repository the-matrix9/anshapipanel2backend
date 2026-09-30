import { Router } from "express";
import { z } from "zod";
import { upstreamClient } from "../lib/httpClient.js";
import { db, withTransaction } from "../db/index.js";
import { requireAuth } from "../middleware/auth.js";
import { encrypt, decrypt } from "../lib/crypto.js";
import { getClientIp } from "../lib/clientIp.js";
import { assertSafeUpstreamUrl } from "../lib/ssrfGuard.js";
import { asyncHandler, intParam } from "../middleware/errors.js";
import { clearCache } from "../lib/ttlCache.js";
import { normalizeTz, startOfLocalDay, toIso, toSqlite } from "../lib/tz.js";

// Turns the first Zod issue into a message that names the exact field —
// "parameters.0.upstream_name: String must contain at least 1
// character(s)" instead of a bare, unlocatable "String must contain at
// least 1 character(s)".
function formatZodError(error) {
  const issue = error.issues[0];
  if (!issue) return "Invalid input";
  const path = issue.path.join(".");
  return path ? `${path}: ${issue.message}` : issue.message;
}

const router = Router();
router.use(requireAuth);
router.param("id", intParam("API id"));

// RFC 7230 "token" — anything else in a header name is a header-injection risk.
const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;

const paramSchema = z.object({
  public_name: z.string().min(1),
  upstream_name: z.string().min(1),
  location: z.enum(["query", "body", "path"]).default("query"),
  required: z.boolean().default(false),
  default_value: z.string().nullable().optional(),
});

const headerSchema = z.object({
  header_name: z.string().min(1).max(100).regex(HEADER_NAME, "Header names may only contain letters, digits and - _ . ~ ! # $ % & ' * + ^ ` |"),
  header_value: z.string().max(4000),
  is_sensitive: z.boolean().default(false),
});

const limitsSchema = z.object({
  per_minute: z.number().int().min(0).default(60),
  per_hour: z.number().int().min(0).default(1000),
  per_day: z.number().int().min(0).default(10000),
  max_concurrent: z.number().int().min(0).default(5),
  max_response_size_bytes: z.number().int().min(0).default(5242880),
  max_request_body_bytes: z.number().int().min(0).default(1048576),
  ip_limit_per_minute: z.number().int().min(0).default(30),
  global_limit_per_minute: z.number().int().min(0).default(0),
});

const apiSchema = z.object({
  name: z.string().trim().min(1, "Name is required").max(100, "Name must be 100 characters or fewer"),
  slug: z
    .string()
    .min(1, "Slug is required")
    .max(60, "Slug must be 60 characters or fewer")
    .regex(/^[a-z0-9-_]+$/, "Slug can only contain lowercase letters, numbers, - and _"),
  description: z.string().max(1000, "Description must be 1000 characters or fewer").optional().default(""),
  upstream_url: z.string().url("Upstream URL must be a valid http(s) URL").max(2000),
  method: z.enum(["GET", "POST", "PUT", "DELETE"]).default("GET"),
  auth_type: z.enum(["none", "api_key", "bearer", "custom_header", "custom_query"]).default("none"),
  auth_config: z.record(z.any()).optional().default({}),
  response_type: z.enum(["json", "text", "binary", "auto"]).default("auto"),
  timeout_ms: z.number().int().min(100).max(120000).default(10000),
  retry_count: z.number().int().min(0).max(5).default(2),
  retry_delay_ms: z.number().int().min(0).max(30000).default(300),
  cache_enabled: z.boolean().default(false),
  cache_duration_ms: z.number().int().min(0).default(0),
  response_wrapper_enabled: z.boolean().default(true),
  transform_enabled: z.boolean().default(false),
  transform_rules: z
    .array(
      z.object({
        action: z.enum(["add", "remove"]),
        field: z.string().min(1),
        value: z.string().optional(), // only used for action "add"
      })
    )
    .default([]),
  static_query_params: z
    .array(
      z.object({
        name: z.string().min(1),
        value: z.string().min(1),
      })
    )
    .default([]),
  parameters: z.array(paramSchema).max(50).default([]),
  headers: z.array(headerSchema).max(50).default([]),
  status: z.enum(["active", "disabled"]).optional(),
  limits: limitsSchema.default({}),
});

// `pre` optionally supplies already-fetched parameters/headers/limits (keyed
// by api id) so the list endpoint does 3 queries in total rather than 3 per API.
function serializeApi(api, pre) {
  const parameters = (
    pre?.parameters.get(api.id) ??
    db
      .prepare("SELECT id, public_name, upstream_name, location, required, default_value FROM api_parameters WHERE api_id = ?")
      .all(api.id)
  ).map((p) => ({ ...p, required: !!p.required }));
  const headers = (
    pre?.headers.get(api.id) ?? db.prepare("SELECT id, header_name, header_value, is_sensitive FROM api_headers WHERE api_id = ?").all(api.id)
  ).map((h) => ({
    ...h,
    is_sensitive: !!h.is_sensitive,
    // Secret values (stored encrypted) never leave the server. Non-secret ones are returned so
    // the edit form can show them — previously they were dropped, and saving an edit wiped them.
    header_value: h.is_sensitive ? "••••••••" : h.header_value,
  }));
  const limits = pre ? pre.limits.get(api.id) : db.prepare("SELECT * FROM api_limits WHERE api_id = ?").get(api.id);
  const authConfig = JSON.parse(api.auth_config || "{}");
  // Never expose secret auth values back to the client
  const safeAuthConfig = { ...authConfig };
  for (const k of ["key", "token", "value", "secret"]) {
    if (safeAuthConfig[k]) safeAuthConfig[k] = "••••••••";
  }
  return {
    ...api,
    // SQLite has no native boolean type — these come back as 0/1 integers,
    // but the form (and its Zod validation on save) expects real
    // true/false. Without this coercion, loading an API into the edit
    // form and saving it straight back fails with "Expected boolean,
    // received number".
    cache_enabled: !!api.cache_enabled,
    response_wrapper_enabled: !!api.response_wrapper_enabled,
    transform_enabled: !!api.transform_enabled,
    auth_config: safeAuthConfig,
    parameters,
    headers,
    limits,
    transform_rules: JSON.parse(api.transform_rules || "[]"),
    static_query_params: JSON.parse(api.static_query_params || "[]").map((p) => ({ name: p.name, value: "••••••••" })),
    public_url: `/api/${api.slug}`,
    created_at: toIso(api.created_at) ?? api.created_at,
    updated_at: toIso(api.updated_at) ?? api.updated_at,
  };
}

function groupBy(rows, key) {
  const m = new Map();
  for (const r of rows) {
    if (!m.has(r[key])) m.set(r[key], []);
    m.get(r[key]).push(r);
  }
  return m;
}

router.get("/", (req, res) => {
  const tz = normalizeTz(req.query.tz);
  const apis = db.prepare("SELECT * FROM apis ORDER BY created_at DESC, id DESC").all();

  // Request stats for ALL apis in one grouped pass (covering index
  // idx_requests_api_created) instead of three correlated subqueries per API.
  const stats = new Map(
    db
      .prepare(
        `SELECT api_id, COUNT(*) AS total, COALESCE(SUM(created_at >= @today), 0) AS today, MAX(created_at) AS last_request
           FROM api_requests WHERE api_id IS NOT NULL GROUP BY api_id`
      )
      .all({ today: toSqlite(startOfLocalDay(tz, 0)) })
      .map((r) => [r.api_id, r])
  );
  // Health over the last hour, also grouped.
  const hour = new Map(
    db
      .prepare(
        `SELECT api_id, COUNT(*) AS total, COALESCE(SUM(success = 0), 0) AS failed, AVG(response_time_ms) AS avg_latency
           FROM api_requests WHERE api_id IS NOT NULL AND created_at >= ? GROUP BY api_id`
      )
      .all(toSqlite(Date.now() - 3_600_000))
      .map((r) => [r.api_id, r])
  );

  const pre = {
    parameters: groupBy(
      db.prepare("SELECT id, api_id, public_name, upstream_name, location, required, default_value FROM api_parameters").all(),
      "api_id"
    ),
    headers: groupBy(db.prepare("SELECT id, api_id, header_name, header_value, is_sensitive FROM api_headers").all(), "api_id"),
    limits: new Map(db.prepare("SELECT * FROM api_limits").all().map((l) => [l.api_id, l])),
  };

  res.json({
    status: true,
    data: apis.map((a) => {
      const st = stats.get(a.id);
      const h = hour.get(a.id);
      // "error" = the API is enabled but most of its recent traffic is failing.
      let health_state = a.status !== "active" ? "disabled" : "ok";
      if (a.status === "active" && h && h.total >= 3 && h.failed / h.total >= 0.5) health_state = "error";
      return {
        ...serializeApi(a, pre),
        requests_today: st?.today || 0,
        total_requests: st?.total || 0,
        last_request: toIso(st?.last_request),
        recent_requests_1h: h?.total || 0,
        recent_failures_1h: h?.failed || 0,
        avg_latency_1h_ms: h?.avg_latency ? Math.round(h.avg_latency) : null,
        health_state,
      };
    }),
  });
});

router.get("/:id", (req, res) => {
  const api = db.prepare("SELECT * FROM apis WHERE id = ?").get(req.params.id);
  if (!api) return res.status(404).json({ status: false, error: "API not found" });
  res.json({ status: true, data: serializeApi(api) });
});

router.post("/", asyncHandler(async (req, res) => {
  const parsed = apiSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ status: false, error: formatZodError(parsed.error) });
  }
  const d = parsed.data;

  const existing = db.prepare("SELECT id FROM apis WHERE slug = ?").get(d.slug);
  if (existing) return res.status(409).json({ status: false, error: "Slug already in use" });

  try {
    await assertSafeUpstreamUrl(d.upstream_url);
  } catch (e) {
    return res.status(400).json({ status: false, error: e.message });
  }

  // Encrypt sensitive auth_config fields before storing
  const authConfig = { ...d.auth_config };
  for (const k of ["key", "token", "value", "secret"]) {
    if (authConfig[k]) authConfig[k] = encrypt(authConfig[k]);
  }

  const insertApi = db.prepare(`
    INSERT INTO apis (name, slug, description, upstream_url, method, auth_type, auth_config,
      response_type, timeout_ms, retry_count, retry_delay_ms, cache_enabled, cache_duration_ms,
      response_wrapper_enabled, transform_enabled, transform_rules, static_query_params, created_by)
    VALUES (@name, @slug, @description, @upstream_url, @method, @auth_type, @auth_config,
      @response_type, @timeout_ms, @retry_count, @retry_delay_ms, @cache_enabled, @cache_duration_ms,
      @response_wrapper_enabled, @transform_enabled, @transform_rules, @static_query_params, @created_by)
  `);

  const encryptedStaticParams = (d.static_query_params || []).map((p) => ({ name: p.name, value: encrypt(p.value) }));

  const apiId = withTransaction(() => {
    const info = insertApi.run({
      name: d.name,
      slug: d.slug,
      description: d.description,
      upstream_url: d.upstream_url,
      method: d.method,
      auth_type: d.auth_type,
      auth_config: JSON.stringify(authConfig),
      response_type: d.response_type,
      timeout_ms: d.timeout_ms,
      retry_count: d.retry_count,
      retry_delay_ms: d.retry_delay_ms,
      cache_enabled: d.cache_enabled ? 1 : 0,
      cache_duration_ms: d.cache_duration_ms,
      response_wrapper_enabled: d.response_wrapper_enabled ? 1 : 0,
      transform_enabled: d.transform_enabled ? 1 : 0,
      transform_rules: JSON.stringify(d.transform_rules || []),
      static_query_params: JSON.stringify(encryptedStaticParams),
      created_by: req.user.sub,
    });
    const apiId = info.lastInsertRowid;

    const insertParam = db.prepare(
      "INSERT INTO api_parameters (api_id, public_name, upstream_name, location, required, default_value) VALUES (?,?,?,?,?,?)"
    );
    for (const p of d.parameters) {
      insertParam.run(apiId, p.public_name, p.upstream_name, p.location, p.required ? 1 : 0, p.default_value ?? null);
    }

    const insertHeader = db.prepare(
      "INSERT INTO api_headers (api_id, header_name, header_value, is_sensitive) VALUES (?,?,?,?)"
    );
    for (const h of d.headers) {
      const val = h.is_sensitive ? encrypt(h.header_value) : h.header_value;
      insertHeader.run(apiId, h.header_name, val, h.is_sensitive ? 1 : 0);
    }

    const l = d.limits;
    db.prepare(
      `INSERT INTO api_limits (api_id, per_minute, per_hour, per_day, max_concurrent, max_response_size_bytes, max_request_body_bytes, ip_limit_per_minute, global_limit_per_minute)
       VALUES (?,?,?,?,?,?,?,?,?)`
    ).run(
      apiId,
      l.per_minute,
      l.per_hour,
      l.per_day,
      l.max_concurrent,
      l.max_response_size_bytes,
      l.max_request_body_bytes,
      l.ip_limit_per_minute,
      l.global_limit_per_minute
    );

    db.prepare("INSERT INTO audit_logs (user_id, action, target, ip_address) VALUES (?, 'create_api', ?, ?)").run(
      req.user.sub,
      d.slug,
      getClientIp(req)
    );

    return apiId;
  });

  clearCache();
  const api = db.prepare("SELECT * FROM apis WHERE id = ?").get(apiId);
  res.status(201).json({ status: true, data: serializeApi(api) });
}));

router.put("/:id", asyncHandler(async (req, res) => {
  const api = db.prepare("SELECT * FROM apis WHERE id = ?").get(req.params.id);
  if (!api) return res.status(404).json({ status: false, error: "API not found" });

  const parsed = apiSchema.partial().safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ status: false, error: formatZodError(parsed.error) });
  }
  const d = parsed.data;

  if (d.upstream_url) {
    try {
      await assertSafeUpstreamUrl(d.upstream_url);
    } catch (e) {
      return res.status(400).json({ status: false, error: e.message });
    }
  }

  if (d.slug && d.slug !== api.slug) {
    const clash = db.prepare("SELECT id FROM apis WHERE slug = ? AND id != ?").get(d.slug, api.id);
    if (clash) return res.status(409).json({ status: false, error: "Slug already in use" });
  }

  const authConfig = d.auth_config ? { ...d.auth_config } : JSON.parse(api.auth_config || "{}");
  if (d.auth_config) {
    for (const k of ["key", "token", "value", "secret"]) {
      if (authConfig[k] && authConfig[k] !== "••••••••") authConfig[k] = encrypt(authConfig[k]);
      else if (authConfig[k] === "••••••••") delete authConfig[k]; // keep existing, don't overwrite with mask
    }
  }

  withTransaction(() => {
    db.prepare(
      `UPDATE apis SET name=?, slug=?, description=?, upstream_url=?, method=?, auth_type=?, auth_config=?,
        response_type=?, timeout_ms=?, retry_count=?, retry_delay_ms=?, cache_enabled=?, cache_duration_ms=?,
        response_wrapper_enabled=?, transform_enabled=?, transform_rules=?, static_query_params=?, status=?, updated_at=datetime('now') WHERE id=?`
    ).run(
      d.name ?? api.name,
      d.slug ?? api.slug,
      d.description ?? api.description,
      d.upstream_url ?? api.upstream_url,
      d.method ?? api.method,
      d.auth_type ?? api.auth_type,
      JSON.stringify({ ...JSON.parse(api.auth_config || "{}"), ...authConfig }),
      d.response_type ?? api.response_type,
      d.timeout_ms ?? api.timeout_ms,
      d.retry_count ?? api.retry_count,
      d.retry_delay_ms ?? api.retry_delay_ms,
      d.cache_enabled !== undefined ? (d.cache_enabled ? 1 : 0) : api.cache_enabled,
      d.cache_duration_ms ?? api.cache_duration_ms,
      d.response_wrapper_enabled !== undefined ? (d.response_wrapper_enabled ? 1 : 0) : api.response_wrapper_enabled,
      d.transform_enabled !== undefined ? (d.transform_enabled ? 1 : 0) : api.transform_enabled,
      d.transform_rules !== undefined ? JSON.stringify(d.transform_rules) : api.transform_rules,
      d.static_query_params !== undefined
        ? JSON.stringify(
            d.static_query_params.map((p) => {
              // If the value is still the masked placeholder, the admin
              // didn't touch this param — keep its existing encrypted
              // value instead of literally encrypting the dots.
              if (p.value === "••••••••") {
                const old = JSON.parse(api.static_query_params || "[]").find((op) => op.name === p.name);
                if (old) return old;
              }
              return { name: p.name, value: encrypt(p.value) };
            })
          )
        : api.static_query_params,
      d.status ?? api.status,
      api.id
    );

    if (d.parameters) {
      db.prepare("DELETE FROM api_parameters WHERE api_id = ?").run(api.id);
      const insertParam = db.prepare(
        "INSERT INTO api_parameters (api_id, public_name, upstream_name, location, required, default_value) VALUES (?,?,?,?,?,?)"
      );
      for (const p of d.parameters) {
        insertParam.run(api.id, p.public_name, p.upstream_name, p.location, p.required ? 1 : 0, p.default_value ?? null);
      }
    }

    if (d.headers) {
      // Secret header values are never sent to the browser, so an edit form
      // can only submit them blank (or masked). A sensitive header with a
      // blank/masked value means "unchanged" — carry its stored encrypted
      // value over instead of wiping it (or encrypting the placeholder).
      const previous = new Map(
        db.prepare("SELECT header_name, header_value FROM api_headers WHERE api_id = ? AND is_sensitive = 1").all(api.id).map((h) => [h.header_name.toLowerCase(), h.header_value])
      );
      db.prepare("DELETE FROM api_headers WHERE api_id = ?").run(api.id);
      const insertHeader = db.prepare(
        "INSERT INTO api_headers (api_id, header_name, header_value, is_sensitive) VALUES (?,?,?,?)"
      );
      for (const h of d.headers) {
        let val;
        if (h.is_sensitive && (!h.header_value || h.header_value === "••••••••")) {
          val = previous.get(h.header_name.toLowerCase());
          if (val === undefined) continue; // nothing stored to keep, and no new value given
        } else {
          val = h.is_sensitive ? encrypt(h.header_value) : h.header_value;
        }
        insertHeader.run(api.id, h.header_name, val, h.is_sensitive ? 1 : 0);
      }
    }

    if (d.limits) {
      const l = d.limits;
      db.prepare(
        `INSERT INTO api_limits (api_id, per_minute, per_hour, per_day, max_concurrent, max_response_size_bytes, max_request_body_bytes, ip_limit_per_minute, global_limit_per_minute)
         VALUES (?,?,?,?,?,?,?,?,?)
         ON CONFLICT(api_id) DO UPDATE SET per_minute=excluded.per_minute, per_hour=excluded.per_hour, per_day=excluded.per_day,
           max_concurrent=excluded.max_concurrent, max_response_size_bytes=excluded.max_response_size_bytes,
           max_request_body_bytes=excluded.max_request_body_bytes, ip_limit_per_minute=excluded.ip_limit_per_minute,
           global_limit_per_minute=excluded.global_limit_per_minute`
      ).run(
        api.id,
        l.per_minute,
        l.per_hour,
        l.per_day,
        l.max_concurrent,
        l.max_response_size_bytes,
        l.max_request_body_bytes,
        l.ip_limit_per_minute,
        l.global_limit_per_minute
      );
    }

    db.prepare("INSERT INTO audit_logs (user_id, action, target, ip_address) VALUES (?, 'update_api', ?, ?)").run(
      req.user.sub,
      api.slug,
      getClientIp(req)
    );
  });

  clearCache();
  const updated = db.prepare("SELECT * FROM apis WHERE id = ?").get(api.id);
  res.json({ status: true, data: serializeApi(updated) });
}));

router.post("/:id/toggle", (req, res) => {
  const api = db.prepare("SELECT * FROM apis WHERE id = ?").get(req.params.id);
  if (!api) return res.status(404).json({ status: false, error: "API not found" });
  const next = api.status === "active" ? "disabled" : "active";
  db.prepare("UPDATE apis SET status = ?, updated_at = datetime('now') WHERE id = ?").run(next, api.id);
  db.prepare("INSERT INTO audit_logs (user_id, action, target, ip_address) VALUES (?, ?, ?, ?)").run(
    req.user.sub,
    next === "active" ? "enable_api" : "disable_api",
    api.slug,
    getClientIp(req)
  );
  clearCache();
  res.json({ status: true, data: { status: next } });
});

router.delete("/:id", (req, res) => {
  const api = db.prepare("SELECT * FROM apis WHERE id = ?").get(req.params.id);
  if (!api) return res.status(404).json({ status: false, error: "API not found" });
  db.prepare("DELETE FROM apis WHERE id = ?").run(api.id); // cascades via FK
  db.prepare("INSERT INTO audit_logs (user_id, action, target, ip_address) VALUES (?, 'delete_api', ?, ?)").run(
    req.user.sub,
    api.slug,
    getClientIp(req)
  );
  clearCache();
  res.json({ status: true, data: { message: "API deleted" } });
});

// Built-in API tester — proxies a one-off test request through the same
// safety checks as the live proxy, without touching rate limits/logs.
router.post("/:id/test", asyncHandler(async (req, res) => {
  const api = db.prepare("SELECT * FROM apis WHERE id = ?").get(req.params.id);
  if (!api) return res.status(404).json({ status: false, error: "API not found" });

  const headers = db.prepare("SELECT * FROM api_headers WHERE api_id = ?").all(api.id);
  const finalHeaders = {};
  for (const h of headers) {
    finalHeaders[h.header_name] = h.is_sensitive ? decrypt(h.header_value) : h.header_value;
  }

  const authConfig = JSON.parse(api.auth_config || "{}");
  const testQuery = { ...(req.body.query || {}) };
  applyAuth(api.auth_type, authConfig, finalHeaders, testQuery);
  try {
    const staticParams = JSON.parse(api.static_query_params || "[]");
    for (const p of staticParams) {
      testQuery[p.name] = decrypt(p.value) ?? p.value;
    }
  } catch {
    /* ignore malformed static params in the tester */
  }

  try {
    await assertSafeUpstreamUrl(api.upstream_url);
    const start = Date.now();
    const response = await upstreamClient({
      method: api.method,
      url: api.upstream_url,
      headers: finalHeaders,
      params: testQuery,
      data: req.body.body || undefined,
      timeout: api.timeout_ms,
      validateStatus: () => true,
      maxContentLength: 10 * 1024 * 1024,
    });
    const time = Date.now() - start;
    res.json({
      status: true,
      data: {
        status_code: response.status,
        response_time_ms: time,
        response_headers: response.headers,
        response_body: response.data,
        final_upstream_url: api.upstream_url,
      },
    });
  } catch (e) {
    // A failed test is a gateway problem, not a successful call — say so.
    res.status(502).json({ status: false, error: `Test request failed: ${e.message}` });
  }
}));

export function applyAuth(authType, authConfig, headers, queryParams) {
  const get = (k) => (authConfig[k] ? decrypt(authConfig[k]) || authConfig[k] : undefined);
  if (authType === "api_key") {
    const headerName = authConfig.header_name || "x-api-key";
    headers[headerName] = get("key");
  } else if (authType === "bearer") {
    headers["Authorization"] = `Bearer ${get("token")}`;
  } else if (authType === "custom_header") {
    headers[authConfig.header_name] = get("value");
  } else if (authType === "custom_query") {
    queryParams[authConfig.param_name] = get("value");
  }
}

export default router;

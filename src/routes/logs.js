import { Router } from "express";
import { db } from "../db/index.js";
import { requireAuth } from "../middleware/auth.js";
import { HttpError, asyncHandler } from "../middleware/errors.js";
import { normalizeIp, isNonPublicIp } from "../lib/clientIp.js";
import { safeParse } from "../lib/redact.js";
import { fromSqlite, normalizeTz, toIso, toSqlite, zonedMidnight } from "../lib/tz.js";

const router = Router();
router.use(requireAuth);

const METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]);

// Sort keys are whitelisted — never interpolate user input into SQL.
const SORTS = {
  time: "r.created_at",
  latency: "r.response_time_ms",
  status: "r.status_code",
  api: "r.api_name",
  method: "r.method",
  ip: "r.ip_address",
};

const likeEscape = (s) => s.replace(/[\\%_]/g, (c) => `\\${c}`);

function intOr(v, fallback, min, max) {
  const n = Number.parseInt(v, 10);
  if (Number.isNaN(n)) return fallback;
  return Math.min(max, Math.max(min, n));
}

function parseTime(value, field) {
  if (!value) return null;
  const ms = fromSqlite(String(value));
  if (Number.isNaN(ms)) throw new HttpError(400, `"${field}" must be an ISO-8601 date-time`, "INVALID_FILTER");
  return ms;
}

// Builds the WHERE clause once and reuses it for the rows query and the
// statistics query, so the numbers above the list always describe exactly
// the rows in it.
function buildWhere(q) {
  const where = [];
  const params = {};

  if (q.api_id) {
    if (!/^\d+$/.test(String(q.api_id))) throw new HttpError(400, "api_id must be a number", "INVALID_FILTER");
    where.push("r.api_id = @api_id");
    params.api_id = Number(q.api_id);
  }
  if (q.api_key_id) {
    if (!/^\d+$/.test(String(q.api_key_id))) throw new HttpError(400, "api_key_id must be a number", "INVALID_FILTER");
    where.push("r.api_key_id = @api_key_id");
    params.api_key_id = Number(q.api_key_id);
  }

  const status = String(q.status || "").toLowerCase();
  if (status === "success") where.push("r.success = 1");
  else if (status === "failed") where.push("r.success = 0");
  else if (/^[1-5]xx$/.test(status)) {
    where.push("r.status_code >= @sc_lo AND r.status_code < @sc_hi");
    params.sc_lo = Number(status[0]) * 100;
    params.sc_hi = params.sc_lo + 100;
  } else if (/^\d{3}$/.test(status)) {
    where.push("r.status_code = @sc");
    params.sc = Number(status);
  } else if (status) {
    throw new HttpError(400, `Unknown status filter "${q.status}"`, "INVALID_FILTER");
  }

  if (q.method) {
    const m = String(q.method).toUpperCase();
    if (!METHODS.has(m)) throw new HttpError(400, `Unknown method "${q.method}"`, "INVALID_FILTER");
    where.push("r.method = @method");
    params.method = m;
  }

  if (q.ip) {
    const raw = String(q.ip).trim().slice(0, 64);
    const exact = normalizeIp(raw);
    if (exact) {
      where.push("r.ip_address = @ip");
      params.ip = exact;
    } else {
      // partial IP ("123.123.", "2001:db8") — substring match
      where.push("r.ip_address LIKE @ip_like ESCAPE '\\'");
      params.ip_like = `%${likeEscape(raw)}%`;
    }
  }

  // Time window. `from`/`to` are absolute instants (ISO). The legacy `date`
  // parameter ("YYYY-MM-DD") is interpreted as a full day in the caller's tz.
  let from = parseTime(q.from, "from");
  let to = parseTime(q.to, "to");
  if (q.date && !from && !to) {
    const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(q.date));
    if (!m) throw new HttpError(400, `"date" must be YYYY-MM-DD`, "INVALID_FILTER");
    const tz = normalizeTz(q.tz);
    from = zonedMidnight(+m[1], +m[2], +m[3], tz);
    const next = new Date(Date.UTC(+m[1], +m[2] - 1, +m[3] + 1));
    to = zonedMidnight(next.getUTCFullYear(), next.getUTCMonth() + 1, next.getUTCDate(), tz);
  }
  if (from !== null) {
    where.push("r.created_at >= @from");
    params.from = toSqlite(from);
  }
  if (to !== null) {
    where.push("r.created_at < @to");
    params.to = toSqlite(to);
  }

  if (q.q) {
    const term = String(q.q).trim().slice(0, 100);
    if (term) {
      params.q = `%${likeEscape(term)}%`;
      where.push(
        `(r.api_name LIKE @q ESCAPE '\\' OR r.api_slug LIKE @q ESCAPE '\\' OR r.path LIKE @q ESCAPE '\\'
          OR r.ip_address LIKE @q ESCAPE '\\' OR r.query_string LIKE @q ESCAPE '\\'
          OR r.error_message LIKE @q ESCAPE '\\' OR r.request_id LIKE @q ESCAPE '\\'
          OR r.user_agent LIKE @q ESCAPE '\\')`
      );
    }
  }

  return { whereSql: where.length ? `WHERE ${where.join(" AND ")}` : "", params };
}

// "/api/num4" + {"num":"9876543210"}  ->  "/api/num4?num=9876543210"
function buildRequestUrl(path, queryJson) {
  const q = safeParse(queryJson);
  if (!q || typeof q !== "object") return path || null;
  const usp = new URLSearchParams();
  for (const [k, v] of Object.entries(q)) {
    if (Array.isArray(v)) v.forEach((x) => usp.append(k, typeof x === "object" ? JSON.stringify(x) : String(x)));
    else usp.append(k, typeof v === "object" && v !== null ? JSON.stringify(v) : String(v ?? ""));
  }
  const s = usp.toString();
  return s ? `${path}?${s}` : path || null;
}

function shapeRow(r, detail = false) {
  const query = safeParse(r.query_string);
  const out = {
    id: r.id,
    request_id: r.request_id,
    api_id: r.api_id,
    api_slug: r.api_slug || r.live_slug || null,
    api_name: r.api_name || r.live_name || null,
    method: r.method,
    path: r.path || (r.api_slug || r.live_slug ? `/api/${r.api_slug || r.live_slug}` : null),
    query,
    request_url: buildRequestUrl(r.path || (r.api_slug || r.live_slug ? `/api/${r.api_slug || r.live_slug}` : ""), r.query_string),
    ip_address: r.ip_address,
    client_ip: r.ip_address,
    status_code: r.status_code,
    success: !!r.success,
    response_time_ms: r.response_time_ms,
    response_size_bytes: r.response_size_bytes,
    error_message: r.error_message,
    user_agent: r.user_agent,
    referrer: r.referrer,
    api_key_id: r.api_key_id,
    key_name: r.key_name || null,
    api_key_prefix: r.api_key_prefix || null,
    cache_hit: !!r.cache_hit,
    created_at: toIso(r.created_at),
  };
  if (detail) {
    out.request_body = safeParse(r.request_body);
    out.request_headers = safeParse(r.request_headers);
  }
  return out;
}

const ROW_COLUMNS = `r.id, r.request_id, r.api_id, r.api_slug, r.api_name, r.method, r.path, r.query_string,
  r.ip_address, r.status_code, r.success, r.response_time_ms, r.response_size_bytes, r.error_message,
  r.user_agent, r.referrer, r.api_key_id, r.api_key_prefix, r.cache_hit, r.created_at,
  a.slug AS live_slug, a.name AS live_name, k.name AS key_name`;
const ROW_JOINS = `FROM api_requests r LEFT JOIN apis a ON a.id = r.api_id LEFT JOIN api_keys k ON k.id = r.api_key_id`;

router.get(
  "/",
  asyncHandler(async (req, res) => {
    const page = intOr(req.query.page, 1, 1, 100000);
    const limit = intOr(req.query.limit, 25, 1, 100);
    const { whereSql, params } = buildWhere(req.query);

    const sortCol = SORTS[String(req.query.sort || "time")] || SORTS.time;
    const dir = String(req.query.dir || "desc").toLowerCase() === "asc" ? "ASC" : "DESC";
    // r.id as a tiebreaker keeps pagination stable when many rows share a value.
    const orderSql = `ORDER BY ${sortCol} ${dir}, r.id ${dir}`;

    // One aggregate pass over the filtered set gives the total and the stats.
    const agg = db
      .prepare(
        `SELECT COUNT(*) AS total,
                COALESCE(SUM(r.success = 1), 0) AS success,
                COALESCE(SUM(r.success = 0), 0) AS failed,
                AVG(r.response_time_ms) AS avg_latency
           FROM api_requests r ${whereSql}`
      )
      .get(params);

    const rows = db
      .prepare(`SELECT ${ROW_COLUMNS} ${ROW_JOINS} ${whereSql} ${orderSql} LIMIT @limit OFFSET @offset`)
      .all({ ...params, limit, offset: (page - 1) * limit });

    res.json({
      status: true,
      data: {
        rows: rows.map((r) => shapeRow(r)),
        total: agg.total,
        page,
        limit,
        pages: Math.max(1, Math.ceil(agg.total / limit)),
        summary: {
          total: agg.total,
          success: agg.success,
          failed: agg.failed,
          success_rate: agg.total ? +((agg.success / agg.total) * 100).toFixed(1) : null,
          avg_latency_ms: agg.avg_latency === null ? null : Math.round(agg.avg_latency),
        },
      },
    });
  })
);

// Sanity check for IP detection: if the most recent requests all carry
// private/proxy addresses, or all come from one address, the proxy
// configuration (TRUST_PROXY) probably doesn't match the deployment.
router.get("/ip-health", (req, res) => {
  const recent = db.prepare("SELECT ip_address FROM api_requests ORDER BY id DESC LIMIT 50").all();
  const ips = recent.map((r) => r.ip_address).filter(Boolean);
  const distinct = new Set(ips).size;
  const nonPublic = ips.filter((ip) => isNonPublicIp(ip)).length;
  let warning = null;
  if (ips.length >= 5 && nonPublic / ips.length >= 0.8) {
    warning = "private_addresses";
  } else if (ips.length >= 20 && distinct === 1) {
    warning = "single_address";
  }
  res.json({ status: true, data: { sample: ips.length, distinct_ips: distinct, non_public: nonPublic, warning } });
});

router.get("/:id", (req, res) => {
  const id = String(req.params.id);
  const byRequestId = id.startsWith("req_");
  if (!byRequestId && !/^\d{1,12}$/.test(id)) throw new HttpError(400, "Invalid log id", "INVALID_ID");
  const row = db
    .prepare(`SELECT ${ROW_COLUMNS}, r.request_body, r.request_headers ${ROW_JOINS} WHERE ${byRequestId ? "r.request_id" : "r.id"} = ?`)
    .get(byRequestId ? id : Number(id));
  if (!row) throw new HttpError(404, "Log entry not found", "NOT_FOUND");
  res.json({ status: true, data: shapeRow(row, true) });
});

export default router;

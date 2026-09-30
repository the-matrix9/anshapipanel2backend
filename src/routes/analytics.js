import { Router } from "express";
import { db } from "../db/index.js";
import { requireAuth } from "../middleware/auth.js";
import { HttpError, intParam } from "../middleware/errors.js";
import { cached } from "../lib/ttlCache.js";
import {
  fromSqlite,
  lastNDayKeys,
  localDayKey,
  localHourKey,
  localParts,
  normalizeTz,
  startOfLocalDay,
  toIso,
  toSqlite,
} from "../lib/tz.js";

const router = Router();
router.use(requireAuth);
router.param("id", intParam("API id"));

const CACHE_MS = 5_000; // aggregate reads: at most one recompute per 5s per tz/range

const rate = (ok, total) => (total ? +((ok / total) * 100).toFixed(1) : null);
const round = (n) => (n === null || n === undefined ? null : Math.round(n));

// ---- time series ----------------------------------------------------------
// Rows are grouped in SQL by UTC 15-minute slot, then folded into the
// caller's LOCAL days/hours here. 15 minutes is the finest granularity of
// any real-world UTC offset (India is +5:30, Nepal +5:45), so a slot never
// straddles a local hour or midnight and the buckets are exact — including
// across daylight-saving changes.
function slotSeries(sinceMs, tz, granularity, apiId = null) {
  const rows = db
    .prepare(
      `SELECT strftime('%Y-%m-%d %H:', created_at) || printf('%02d', (CAST(strftime('%M', created_at) AS INTEGER) / 15) * 15) AS slot,
              COUNT(*) AS total,
              COALESCE(SUM(success = 1), 0) AS ok,
              COALESCE(SUM(success = 0), 0) AS failed,
              COALESCE(SUM(response_time_ms), 0) AS lat_sum,
              COUNT(response_time_ms) AS lat_n
         FROM api_requests
        WHERE created_at >= @since ${apiId ? "AND api_id = @api_id" : ""}
        GROUP BY slot`
    )
    .all({ since: toSqlite(sinceMs), ...(apiId ? { api_id: apiId } : {}) });

  const keyOf = granularity === "day" ? localDayKey : localHourKey;
  const buckets = new Map();
  for (const r of rows) {
    const ms = Date.parse(`${r.slot.replace(" ", "T")}:00Z`);
    const key = keyOf(ms, tz);
    const b = buckets.get(key) || { total: 0, ok: 0, failed: 0, lat_sum: 0, lat_n: 0 };
    b.total += r.total;
    b.ok += r.ok;
    b.failed += r.failed;
    b.lat_sum += r.lat_sum;
    b.lat_n += r.lat_n;
    buckets.set(key, b);
  }
  return buckets;
}

function bucketToPoint(key, b) {
  return {
    count: b?.total || 0,
    success: b?.ok || 0,
    failed: b?.failed || 0,
    avg_latency_ms: b && b.lat_n ? Math.round(b.lat_sum / b.lat_n) : null,
    ...(key.length > 10 ? { hour: key } : { day: key }),
  };
}

function dailySeries(tz, days, apiId = null) {
  const keys = lastNDayKeys(tz, days);
  const buckets = slotSeries(startOfLocalDay(tz, days - 1), tz, "day", apiId);
  return keys.map((k) => bucketToPoint(k, buckets.get(k)));
}

function hourlySeries(tz, hours = 24) {
  const nowMs = Date.now();
  const p = localParts(nowMs, tz);
  const keys = [];
  // Walk back hour by hour from the current one; derive each key from the instant itself.
  const start = nowMs - (p.mi * 60 + p.s) * 1000 - (nowMs % 1000);
  for (let i = hours - 1; i >= 0; i--) {
    const k = localHourKey(start - i * 3_600_000, tz);
    if (!keys.includes(k)) keys.push(k);
  }
  const buckets = slotSeries(start - (hours - 1) * 3_600_000, tz, "hour");
  return keys.map((k) => bucketToPoint(k, buckets.get(k)));
}

const shapeRecent = (r) => ({
  id: r.id,
  request_id: r.request_id,
  method: r.method,
  status_code: r.status_code,
  success: !!r.success,
  response_time_ms: r.response_time_ms,
  ip_address: r.ip_address,
  path: r.path,
  error_message: r.error_message,
  created_at: toIso(r.created_at),
  api_name: r.api_name || r.live_name || null,
  api_slug: r.api_slug || r.live_slug || null,
});
const RECENT_SQL = `SELECT r.id, r.request_id, r.method, r.status_code, r.success, r.response_time_ms, r.ip_address,
                           r.path, r.error_message, r.created_at, r.api_name, r.api_slug, a.name AS live_name, a.slug AS live_slug
                      FROM api_requests r LEFT JOIN apis a ON a.id = r.api_id`;

// ---------------------------------------------------------------------------
router.get("/dashboard", (req, res) => {
  const tz = normalizeTz(req.query.tz);
  const data = cached(`dash:${tz}`, CACHE_MS, () => {
    const apis = db
      .prepare("SELECT COUNT(*) AS total, COALESCE(SUM(status = 'active'), 0) AS active FROM apis")
      .get();

    // One pass over the log table for all-time figures.
    const all = db
      .prepare(
        `SELECT COUNT(*) AS total,
                COALESCE(SUM(success = 0), 0) AS failed,
                COALESCE(SUM(status_code = 429), 0) AS rate_limited
           FROM api_requests`
      )
      .get();

    const todayStart = toSqlite(startOfLocalDay(tz, 0));
    const today = db
      .prepare(
        `SELECT COUNT(*) AS total, COALESCE(SUM(success = 0), 0) AS failed, AVG(response_time_ms) AS avg_latency
           FROM api_requests WHERE created_at >= ?`
      )
      .get(todayStart);

    const last24 = db
      .prepare("SELECT COUNT(*) AS total, AVG(response_time_ms) AS avg_latency FROM api_requests WHERE created_at >= ?")
      .get(toSqlite(Date.now() - 86_400_000));

    const recent = db.prepare(`${RECENT_SQL} ORDER BY r.id DESC LIMIT 10`).all();

    // Health: one grouped query for the last hour, joined in JS.
    const lastHour = new Map(
      db
        .prepare(
          `SELECT api_id, COUNT(*) AS total, SUM(success = 0) AS failed, AVG(response_time_ms) AS avg_latency
             FROM api_requests WHERE created_at >= ? AND api_id IS NOT NULL GROUP BY api_id`
        )
        .all(toSqlite(Date.now() - 3_600_000))
        .map((r) => [r.api_id, r])
    );
    const health = db
      .prepare("SELECT id, name, slug, status FROM apis ORDER BY name COLLATE NOCASE")
      .all()
      .map((a) => {
        const h = lastHour.get(a.id);
        return {
          ...a,
          avg_response_time: h ? h.avg_latency : null,
          recent_requests: h?.total || 0,
          recent_failures: h?.failed || 0,
        };
      });

    return {
      total_apis: apis.total,
      active_apis: apis.active,
      disabled_apis: apis.total - apis.active,
      total_requests: all.total,
      requests_today: today.total,
      failed_requests: all.failed,
      failed_today: today.failed,
      rate_limit_violations: all.rate_limited,
      success_rate: rate(all.total - all.failed, all.total),
      success_rate_today: rate(today.total - today.failed, today.total),
      avg_latency_ms: round(last24.avg_latency),
      avg_latency_today_ms: round(today.avg_latency),
      requests_last_24h: last24.total,
      usage_days: 14,
      usage_by_day: dailySeries(tz, 14),
      recent_requests: recent.map(shapeRecent),
      health,
      timezone: tz,
      generated_at: new Date().toISOString(),
    };
  });
  res.json({ status: true, data });
});

// ---------------------------------------------------------------------------
const RANGES = { "24h": { hours: 24 }, "7d": { days: 7 }, "30d": { days: 30 } };

router.get("/", (req, res) => {
  const tz = normalizeTz(req.query.tz);
  const rangeKey = String(req.query.range || "7d");
  const range = RANGES[rangeKey];
  if (!range) throw new HttpError(400, `range must be one of ${Object.keys(RANGES).join(", ")}`, "INVALID_FILTER");

  const data = cached(`an:${tz}:${rangeKey}`, CACHE_MS, () => {
    const sinceMs = range.hours ? Date.now() - range.hours * 3_600_000 : startOfLocalDay(tz, range.days - 1);
    const since = toSqlite(sinceMs);

    const s = db
      .prepare(
        `SELECT COUNT(*) AS total,
                COALESCE(SUM(success = 1), 0) AS ok,
                COALESCE(SUM(success = 0), 0) AS failed,
                COALESCE(SUM(status_code = 429), 0) AS rate_limited,
                AVG(response_time_ms) AS avg_latency,
                COUNT(DISTINCT ip_address) AS unique_ips
           FROM api_requests WHERE created_at >= ?`
      )
      .get(since);

    const topApis = db
      .prepare(
        `SELECT r.api_id, COALESCE(r.api_name, a.name, r.api_slug, 'Unknown API') AS name,
                COALESCE(r.api_slug, a.slug) AS slug,
                COUNT(*) AS count, SUM(r.success = 0) AS failed, AVG(r.response_time_ms) AS avg_latency
           FROM api_requests r LEFT JOIN apis a ON a.id = r.api_id
          WHERE r.created_at >= ?
          GROUP BY r.api_id, COALESCE(r.api_slug, a.slug)
          ORDER BY count DESC LIMIT 10`
      )
      .all(since)
      .map((r) => ({ ...r, avg_latency_ms: round(r.avg_latency), avg_latency: undefined }));

    const errorsByStatus = db
      .prepare(
        `SELECT status_code, COUNT(*) AS count FROM api_requests
          WHERE success = 0 AND created_at >= ? GROUP BY status_code ORDER BY count DESC LIMIT 10`
      )
      .all(since);
    const errorMessages = db
      .prepare(
        `SELECT error_message AS message, COUNT(*) AS count FROM api_requests
          WHERE success = 0 AND error_message IS NOT NULL AND created_at >= ?
          GROUP BY error_message ORDER BY count DESC LIMIT 8`
      )
      .all(since);

    const methods = db
      .prepare("SELECT method, COUNT(*) AS count FROM api_requests WHERE created_at >= ? GROUP BY method ORDER BY count DESC")
      .all(since);

    const topIps = db
      .prepare(
        `SELECT ip_address, COUNT(*) AS count, SUM(success = 0) AS failed FROM api_requests
          WHERE created_at >= ? AND ip_address IS NOT NULL GROUP BY ip_address ORDER BY count DESC LIMIT 10`
      )
      .all(since);

    const topKeys = db
      .prepare(
        `SELECT k.id, k.name, k.key_prefix, COUNT(*) AS count FROM api_requests r JOIN api_keys k ON k.id = r.api_key_id
          WHERE r.created_at >= ? GROUP BY k.id ORDER BY count DESC LIMIT 10`
      )
      .all(since);

    return {
      range: rangeKey,
      granularity: range.hours ? "hour" : "day",
      since: new Date(sinceMs).toISOString(),
      timezone: tz,
      summary: {
        total: s.total,
        success: s.ok,
        failed: s.failed,
        rate_limited: s.rate_limited,
        success_rate: rate(s.ok, s.total),
        avg_latency_ms: round(s.avg_latency),
        unique_ips: s.unique_ips,
      },
      timeseries: range.hours ? hourlySeries(tz, range.hours) : dailySeries(tz, range.days),
      top_apis: topApis,
      error_distribution: { by_status: errorsByStatus, by_message: errorMessages },
      methods,
      top_ips: topIps,
      top_keys: topKeys,
      generated_at: new Date().toISOString(),
    };
  });
  res.json({ status: true, data });
});

// ---------------------------------------------------------------------------
router.get("/apis/:id", (req, res) => {
  const id = Number(req.params.id);
  const tz = normalizeTz(req.query.tz);
  if (!db.prepare("SELECT id FROM apis WHERE id = ?").get(id)) throw new HttpError(404, "API not found", "NOT_FOUND");

  const data = cached(`api:${id}:${tz}`, CACHE_MS, () => {
    const now = Date.now();
    const s = db
      .prepare(
        `SELECT COUNT(*) AS total,
                COALESCE(SUM(success = 1), 0) AS ok,
                COALESCE(SUM(success = 0), 0) AS failed,
                COALESCE(SUM(status_code = 429), 0) AS rate_limited,
                COALESCE(SUM(created_at >= @today), 0) AS today,
                COALESCE(SUM(created_at >= @week), 0) AS week,
                COALESCE(SUM(created_at >= @month), 0) AS month,
                AVG(response_time_ms) AS avg_latency,
                MAX(created_at) AS last_request
           FROM api_requests WHERE api_id = @id`
      )
      .get({
        id,
        today: toSqlite(startOfLocalDay(tz, 0)),
        week: toSqlite(now - 7 * 86_400_000),
        month: toSqlite(now - 30 * 86_400_000),
      });

    const topIps = db
      .prepare(
        `SELECT ip_address, COUNT(*) AS count FROM api_requests WHERE api_id = ? AND ip_address IS NOT NULL
          GROUP BY ip_address ORDER BY count DESC LIMIT 5`
      )
      .all(id);
    const recent = db.prepare(`${RECENT_SQL} WHERE r.api_id = ? ORDER BY r.id DESC LIMIT 10`).all(id);
    const recentErrors = db.prepare(`${RECENT_SQL} WHERE r.api_id = ? AND r.success = 0 ORDER BY r.id DESC LIMIT 10`).all(id);

    return {
      requests_today: s.today,
      requests_week: s.week,
      requests_month: s.month,
      total_requests: s.total,
      successful: s.ok,
      failed: s.failed,
      rate_limit_violations: s.rate_limited,
      avg_response_time: s.avg_latency || 0,
      success_rate: rate(s.ok, s.total),
      error_rate: s.total ? +((s.failed / s.total) * 100).toFixed(2) : 0,
      last_request: toIso(s.last_request),
      top_ips: topIps,
      usage_by_day: dailySeries(tz, 14, id),
      recent_requests: recent.map(shapeRecent),
      recent_errors: recentErrors.map(shapeRecent),
      timezone: tz,
    };
  });
  res.json({ status: true, data });
});

export default router;

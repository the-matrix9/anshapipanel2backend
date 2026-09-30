import { Router } from "express";
import { z } from "zod";
import { db } from "../db/index.js";
import { requireAuth } from "../middleware/auth.js";
import { HttpError, intParam } from "../middleware/errors.js";
import { generateApiKey, hashApiKey } from "../lib/crypto.js";
import { getClientIp, normalizeIp } from "../lib/clientIp.js";
import { fromSqlite, normalizeTz, startOfLocalDay, toIso, toSqlite } from "../lib/tz.js";

function formatZodError(error) {
  const issue = error.issues[0];
  if (!issue) return "Invalid input";
  const path = issue.path.join(".");
  return path ? `${path}: ${issue.message}` : issue.message;
}

const router = Router();
router.use(requireAuth);
router.param("id", intParam("key id"));

const ipList = z
  .array(z.string().max(64))
  .max(200)
  .default([])
  .transform((list, ctx) =>
    list.map((raw, i) => {
      const n = normalizeIp(raw);
      if (!n) ctx.addIssue({ code: "custom", message: `"${raw}" is not a valid IP address`, path: [i] });
      return n || raw;
    })
  );

const keySchema = z.object({
  name: z.string().trim().min(1, "Name is required").max(100),
  custom_key: z
    .string()
    .min(3, "Custom key must be at least 3 characters")
    .max(256)
    .regex(/^\S+$/, "Spaces aren't allowed — any other character is fine")
    .optional(),
  expires_at: z
    .string()
    .nullable()
    .optional()
    .refine((v) => !v || !Number.isNaN(fromSqlite(v)), "expires_at must be a valid date"),
  requests_per_day: z.number().int().min(0).default(0),
  requests_per_month: z.number().int().min(0).default(0),
  allowed_apis: z.union([z.literal("all"), z.array(z.number())]).default("all"),
  ip_whitelist: ipList,
  ip_blacklist: ipList,
});

const audit = (req, action, target) =>
  db
    .prepare("INSERT INTO audit_logs (user_id, action, target, ip_address) VALUES (?, ?, ?, ?)")
    .run(req.user.sub, action, target, getClientIp(req));

function serializeKey(r, usage) {
  const expiresMs = r.expires_at ? fromSqlite(r.expires_at) : null;
  const expired = expiresMs !== null && !Number.isNaN(expiresMs) && expiresMs < Date.now();
  const u = usage?.get(r.id);
  return {
    id: r.id,
    name: r.name,
    key_prefix: r.key_prefix,
    // The secret itself is never stored (only its hash) and never returned
    // after creation. This is all a client can ever see of it.
    key_display: `${r.key_prefix}${"•".repeat(16)}`,
    status: r.status,
    is_expired: expired,
    effective_status: r.status !== "active" ? r.status : expired ? "expired" : "active",
    expires_at: toIso(r.expires_at),
    requests_per_day: r.requests_per_day,
    requests_per_month: r.requests_per_month,
    allowed_apis: r.allowed_apis === "all" ? "all" : JSON.parse(r.allowed_apis),
    ip_whitelist: JSON.parse(r.ip_whitelist || "[]"),
    ip_blacklist: JSON.parse(r.ip_blacklist || "[]"),
    created_at: toIso(r.created_at),
    last_used_at: toIso(r.last_used_at),
    total_requests: u?.total || 0,
    requests_today: u?.today || 0,
  };
}

router.get("/", (req, res) => {
  const tz = normalizeTz(req.query.tz);
  const rows = db
    .prepare(
      `SELECT id, name, key_prefix, status, expires_at, requests_per_day, requests_per_month, allowed_apis,
              ip_whitelist, ip_blacklist, created_at, last_used_at
         FROM api_keys ORDER BY created_at DESC, id DESC`
    )
    .all();
  const usage = new Map(
    db
      .prepare(
        `SELECT api_key_id, COUNT(*) AS total, COALESCE(SUM(created_at >= @today), 0) AS today
           FROM api_requests WHERE api_key_id IS NOT NULL GROUP BY api_key_id`
      )
      .all({ today: toSqlite(startOfLocalDay(tz, 0)) })
      .map((u) => [u.api_key_id, u])
  );
  res.json({ status: true, data: rows.map((r) => serializeKey(r, usage)) });
});

router.post("/", (req, res) => {
  const parsed = keySchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ status: false, error: formatZodError(parsed.error) });
  const d = parsed.data;

  let key, prefix;
  if (d.custom_key) {
    key = d.custom_key;
    // Only a small hint of a custom key is kept: never more than a third of it,
    // so even a short custom key can't be read back out of the key list.
    prefix = key.slice(0, Math.max(1, Math.min(6, Math.floor(key.length / 3))));
    const clash = db.prepare("SELECT id FROM api_keys WHERE key_hash = ?").get(hashApiKey(key));
    if (clash) return res.status(409).json({ status: false, error: "This custom key is already in use" });
  } else {
    ({ key, prefix } = generateApiKey());
  }
  const hash = hashApiKey(key);

  const info = db
    .prepare(
      `INSERT INTO api_keys (name, key_prefix, key_hash, expires_at, requests_per_day, requests_per_month, allowed_apis, ip_whitelist, ip_blacklist)
       VALUES (?,?,?,?,?,?,?,?,?)`
    )
    .run(
      d.name,
      prefix,
      hash,
      d.expires_at ? new Date(fromSqlite(d.expires_at)).toISOString() : null,
      d.requests_per_day,
      d.requests_per_month,
      d.allowed_apis === "all" ? "all" : JSON.stringify(d.allowed_apis),
      JSON.stringify(d.ip_whitelist),
      JSON.stringify(d.ip_blacklist)
    );

  audit(req, "create_api_key", d.name);

  // The full key is shown exactly once, in this response.
  res.setHeader("Cache-Control", "no-store");
  res.status(201).json({ status: true, data: { id: info.lastInsertRowid, key, key_prefix: prefix, name: d.name } });
});

router.post("/:id/rotate", (req, res) => {
  const existing = db.prepare("SELECT * FROM api_keys WHERE id = ?").get(req.params.id);
  if (!existing) throw new HttpError(404, "Key not found", "NOT_FOUND");
  const { key, prefix } = generateApiKey();
  db.prepare("UPDATE api_keys SET key_prefix = ?, key_hash = ? WHERE id = ?").run(prefix, hashApiKey(key), existing.id);
  audit(req, "rotate_api_key", existing.name);
  res.setHeader("Cache-Control", "no-store");
  res.json({ status: true, data: { key, key_prefix: prefix } });
});

router.post("/:id/revoke", (req, res) => {
  const existing = db.prepare("SELECT name FROM api_keys WHERE id = ?").get(req.params.id);
  if (!existing) throw new HttpError(404, "Key not found", "NOT_FOUND");
  db.prepare("UPDATE api_keys SET status = 'revoked' WHERE id = ?").run(req.params.id);
  audit(req, "revoke_api_key", existing.name);
  res.json({ status: true, data: { message: "Key revoked" } });
});

router.delete("/:id", (req, res) => {
  const existing = db.prepare("SELECT name FROM api_keys WHERE id = ?").get(req.params.id);
  if (!existing) throw new HttpError(404, "Key not found", "NOT_FOUND");
  db.prepare("DELETE FROM api_keys WHERE id = ?").run(req.params.id);
  audit(req, "delete_api_key", existing.name);
  res.json({ status: true, data: { message: "Key deleted" } });
});

export default router;

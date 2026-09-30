import test from "node:test";
import assert from "node:assert/strict";
import { redactValue, redactString, toSafeJson, pickSafeHeaders } from "../src/lib/redact.js";
import { startOfLocalDay, lastNDayKeys, localDayKey, toSqlite, fromSqlite, toIso, zonedMidnight } from "../src/lib/tz.js";
import { isPrivateOrReservedIp } from "../src/lib/ssrfGuard.js";

test("redacts sensitive keys, not innocent ones", () => {
  const out = redactValue({ num: "9876", key: "abc", api_key: "x", Authorization: "Bearer zzz", password: "p", author: "bob", nested: { token: "t", city: "Delhi" } });
  assert.equal(out.num, "9876"); assert.equal(out.author, "bob"); assert.equal(out.nested.city, "Delhi");
  for (const v of [out.key, out.api_key, out.Authorization, out.password, out.nested.token]) assert.equal(v, "[REDACTED]");
});
test("redacts secret-shaped values under innocent keys", () => {
  assert.ok(!redactString("x sk_live_abcdefghijk y").includes("abcdefghijk"));
  assert.ok(!redactString("Bearer abcdefghij123").includes("abcdefghij123"));
  assert.ok(!redactString("https://a.b/c?token=SECRET&x=1").includes("SECRET"));
  assert.ok(redactString("https://a.b/c?token=SECRET&x=1").includes("x=1"));
});
test("caps size and depth", () => {
  assert.ok(redactString("a".repeat(5000)).length < 600);
  assert.ok(toSafeJson({ big: "a".repeat(20000), more: "b".repeat(20000) }, 500).length <= 520);
  assert.equal(toSafeJson({}), null);
});
test("headers: allow-list only, credentials withheld", () => {
  const h = pickSafeHeaders({ host: "h", authorization: "Bearer s", cookie: "a=b", "x-api-key": "k", "x-custom": "nope", "user-agent": "ua" });
  assert.equal(h.authorization, "[REDACTED]"); assert.equal(h.cookie, "[REDACTED]"); assert.equal(h["x-api-key"], "[REDACTED]");
  assert.equal(h["x-custom"], undefined); assert.equal(h["user-agent"], "ua");
});
test("timezones: India local midnight is 18:30Z the previous day", () => {
  const now = Date.parse("2026-09-29T09:15:22Z"); // 14:45 in Kolkata
  assert.equal(new Date(startOfLocalDay("Asia/Kolkata", 0, now)).toISOString(), "2026-09-28T18:30:00.000Z");
  const late = Date.parse("2026-09-29T19:00:00Z"); // already 30 Sep 00:30 in Kolkata
  assert.equal(localDayKey(late, "Asia/Kolkata"), "2026-09-30");
  assert.equal(localDayKey(late, "UTC"), "2026-09-29");
  const keys = lastNDayKeys("Asia/Kolkata", 14, late);
  assert.equal(keys.length, 14); assert.equal(keys.at(-1), "2026-09-30"); assert.equal(keys[0], "2026-09-17");
});
test("timezones: DST day is 23h, midnight still correct", () => {
  const a = zonedMidnight(2026, 3, 8, "America/New_York"), b = zonedMidnight(2026, 3, 9, "America/New_York");
  assert.equal((b - a) / 3_600_000, 23);
});
test("sqlite timestamp conversion is UTC-explicit", () => {
  assert.equal(toIso("2026-09-29 09:15:22"), "2026-09-29T09:15:22.000Z");
  assert.equal(toSqlite(fromSqlite("2026-09-29T09:15:22Z")), "2026-09-29 09:15:22");
});
test("SSRF guard blocks v4-mapped and internal ranges", () => {
  for (const ip of ["127.0.0.1", "::ffff:127.0.0.1", "10.1.2.3", "169.254.169.254", "::1", "fd00::1", "100.64.0.1", "::ffff:169.254.169.254"]) assert.equal(isPrivateOrReservedIp(ip), true, ip);
  for (const ip of ["8.8.8.8", "2606:4700:4700::1111"]) assert.equal(isPrivateOrReservedIp(ip), false, ip);
});

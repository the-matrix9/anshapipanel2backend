// Timezone helpers. SQLite stores created_at as UTC ("YYYY-MM-DD HH:MM:SS"),
// so "today" / "last 14 days" must be computed against the *viewer's* local
// midnight, not UTC midnight — otherwise a user in India sees requests
// from 5:30 AM tomorrow counted as "today".

const fmtCache = new Map();

export function normalizeTz(tz) {
  if (!tz || typeof tz !== "string" || tz.length > 64) return "UTC";
  try {
    new Intl.DateTimeFormat("en-US", { timeZone: tz });
    return tz;
  } catch {
    return "UTC";
  }
}

function formatter(tz) {
  let f = fmtCache.get(tz);
  if (!f) {
    f = new Intl.DateTimeFormat("en-CA", {
      timeZone: tz,
      hourCycle: "h23",
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
    fmtCache.set(tz, f);
  }
  return f;
}

/** Local wall-clock parts of an instant (ms) in a timezone. */
export function localParts(ms, tz) {
  const o = {};
  for (const p of formatter(tz).formatToParts(new Date(ms))) o[p.type] = p.value;
  return { y: +o.year, m: +o.month, d: +o.day, h: +o.hour, mi: +o.minute, s: +o.second };
}

function offsetMs(ms, tz) {
  const p = localParts(ms, tz);
  return Date.UTC(p.y, p.m - 1, p.d, p.h, p.mi, p.s) - Math.floor(ms / 1000) * 1000;
}

/** UTC instant (ms) of local midnight for a given local calendar date. */
export function zonedMidnight(y, m, d, tz) {
  const guess = Date.UTC(y, m - 1, d);
  const off = offsetMs(guess, tz);
  let t = guess - off;
  const off2 = offsetMs(t, tz);
  if (off2 !== off) t = guess - off2;
  return t;
}

const pad = (n) => String(n).padStart(2, "0");
export const dayKey = (y, m, d) => `${y}-${pad(m)}-${pad(d)}`;

/** Start (UTC ms) of the local day `daysAgo` days before today. */
export function startOfLocalDay(tz, daysAgo = 0, nowMs = Date.now()) {
  const p = localParts(nowMs, tz);
  const base = new Date(Date.UTC(p.y, p.m - 1, p.d - daysAgo));
  return zonedMidnight(base.getUTCFullYear(), base.getUTCMonth() + 1, base.getUTCDate(), tz);
}

/** Ordered list of the last `n` local day keys ("YYYY-MM-DD"), oldest first. */
export function lastNDayKeys(tz, n, nowMs = Date.now()) {
  const p = localParts(nowMs, tz);
  const keys = [];
  for (let i = n - 1; i >= 0; i--) {
    const dt = new Date(Date.UTC(p.y, p.m - 1, p.d - i));
    keys.push(dayKey(dt.getUTCFullYear(), dt.getUTCMonth() + 1, dt.getUTCDate()));
  }
  return keys;
}

/** Local day key ("YYYY-MM-DD") of an instant. */
export function localDayKey(ms, tz) {
  const p = localParts(ms, tz);
  return dayKey(p.y, p.m, p.d);
}

/** Local hour key ("YYYY-MM-DD HH") of an instant. */
export function localHourKey(ms, tz) {
  const p = localParts(ms, tz);
  return `${dayKey(p.y, p.m, p.d)} ${pad(p.h)}`;
}

// ---- SQLite <-> JS timestamp conversion --------------------------------

/** JS ms -> SQLite "YYYY-MM-DD HH:MM:SS" (UTC). */
export function toSqlite(ms) {
  return new Date(ms).toISOString().slice(0, 19).replace("T", " ");
}

/** SQLite "YYYY-MM-DD HH:MM:SS" (UTC) or ISO -> ms. NaN when unparseable. */
export function fromSqlite(s) {
  if (!s) return NaN;
  if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(s)) return Date.parse(s.replace(" ", "T") + "Z");
  return Date.parse(s);
}

/** SQLite timestamp -> ISO-8601 with an explicit Z so browsers parse it as UTC. */
export function toIso(s) {
  if (!s) return null;
  const ms = fromSqlite(s);
  return Number.isNaN(ms) ? null : new Date(ms).toISOString();
}

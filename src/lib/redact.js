// ---------------------------------------------------------------------------
// Log redaction. Everything that goes into api_requests (query strings,
// bodies, headers, referrers) passes through here first, so secrets never
// reach the database, the admin API, or the dashboard.
// ---------------------------------------------------------------------------

export const REDACTED = "[REDACTED]";

// Key names whose values are always masked, whatever they contain.
const SENSITIVE_KEY =
  /(pass(word|wd|code)?|secret|token|authori[sz]ation|^auth$|auth[-_]?(key|token|code)|api[-_]?key|apikey|access[-_]?key|private|credential|cookie|session|signature|^sig$|jwt|bearer|otp|[-_]key$|^key$|csrf|xsrf)/i;

// Value shapes that are secrets even under an innocent key name.
const VALUE_PATTERNS = [
  [/\bBearer\s+[A-Za-z0-9._~+/=-]{6,}/gi, "Bearer " + REDACTED],
  [/\bsk_live_[A-Za-z0-9_-]{6,}/g, "sk_live_" + REDACTED],
  [/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/g, REDACTED],
  [/([?&](?:key|apikey|api_key|access_token|token|password|passwd|secret|auth|sig|signature)=)[^&\s"']+/gi, "$1" + REDACTED],
];

const MAX_STRING = 500;
const MAX_KEYS = 40;
const MAX_ARRAY = 20;
const MAX_DEPTH = 4;

export function isSensitiveKey(name) {
  return SENSITIVE_KEY.test(String(name));
}

export function redactString(value, max = MAX_STRING) {
  let s = String(value);
  for (const [re, rep] of VALUE_PATTERNS) s = s.replace(re, rep);
  return s.length > max ? `${s.slice(0, max)}… (+${s.length - max} chars)` : s;
}

export function redactValue(value, depth = 0) {
  if (value === null || value === undefined) return null;
  if (typeof value === "string") return redactString(value);
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (depth >= MAX_DEPTH) return "[nested data omitted]";
  if (Array.isArray(value)) {
    const out = value.slice(0, MAX_ARRAY).map((v) => redactValue(v, depth + 1));
    if (value.length > MAX_ARRAY) out.push(`… (+${value.length - MAX_ARRAY} more)`);
    return out;
  }
  if (typeof value === "object") {
    const out = {};
    let n = 0;
    for (const [k, v] of Object.entries(value)) {
      if (n++ >= MAX_KEYS) {
        out["…"] = `(+${Object.keys(value).length - MAX_KEYS} more keys)`;
        break;
      }
      out[k] = isSensitiveKey(k) ? REDACTED : redactValue(v, depth + 1);
    }
    return out;
  }
  return String(value);
}

/** Redacts, serialises and size-caps a value. Returns null for empty input. */
export function toSafeJson(value, maxLen = 4000) {
  if (value === null || value === undefined) return null;
  if (typeof value === "object" && !Array.isArray(value) && Object.keys(value).length === 0) return null;
  if (Array.isArray(value) && value.length === 0) return null;
  const json = JSON.stringify(redactValue(value));
  if (json.length <= maxLen) return json;
  return JSON.stringify({ _truncated: true, preview: json.slice(0, maxLen - 60) });
}

// Only these request headers are ever stored. Cookie, Authorization,
// X-API-Key and anything else not listed is dropped entirely.
const SAFE_HEADERS = [
  "host",
  "user-agent",
  "accept",
  "accept-language",
  "accept-encoding",
  "content-type",
  "content-length",
  "origin",
  "referer",
  "x-requested-with",
  "x-forwarded-for",
  "x-forwarded-proto",
  "x-forwarded-host",
  "x-real-ip",
];

export function pickSafeHeaders(headers = {}) {
  const out = {};
  for (const name of SAFE_HEADERS) {
    const v = headers[name];
    if (v !== undefined) out[name] = redactString(Array.isArray(v) ? v.join(", ") : v, 300);
  }
  // Tell the reader that credentials were deliberately withheld.
  if (headers.authorization) out.authorization = REDACTED;
  if (headers.cookie) out.cookie = REDACTED;
  if (headers["x-api-key"]) out["x-api-key"] = REDACTED;
  return Object.keys(out).length ? out : null;
}

export function safeParse(json) {
  if (!json) return null;
  try {
    return JSON.parse(json);
  } catch {
    return null;
  }
}

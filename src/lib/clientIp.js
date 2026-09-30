import ipaddr from "ipaddr.js";

// ---------------------------------------------------------------------------
// Client IP detection
//
// We deliberately do NOT read X-Forwarded-For / X-Real-IP ourselves. Anyone
// can send those headers, so trusting them blindly lets a caller pretend to
// be any IP (bypassing per-IP rate limits, IP blacklists, and poisoning the
// logs). Instead we configure Express's "trust proxy" setting, which only
// honours X-Forwarded-For entries added by proxies WE trust, counting from
// the right-hand (closest) end of the chain. `req.ip` is then the first
// address that is NOT one of our trusted proxies.
//
// Configure with TRUST_PROXY (alias TRUST_PROXY_HOPS):
//   1              one reverse proxy in front (Railway, Render, Fly, nginx,
//                  Caddy...)  <- default
//   2              two proxies in front (e.g. Vercel rewrite -> Railway,
//                  Cloudflare -> Railway/nginx)
//   0 | false      no proxy: use the raw socket address only
//   10.0.0.0/8,loopback   trust only proxies whose IP is in this list
//                  (comma-separated CIDRs / IPs / loopback,linklocal,uniquelocal)
// `true` is refused: it trusts every hop and makes the header spoofable.
// ---------------------------------------------------------------------------

const KEYWORDS = new Set(["loopback", "linklocal", "uniquelocal"]);

export function parseTrustProxy(value) {
  const raw = (value ?? "").toString().trim().toLowerCase();
  if (raw === "") return { setting: 1, description: "1 proxy hop (default)", warning: null };
  if (raw === "false" || raw === "0" || raw === "off" || raw === "none") {
    return { setting: false, description: "no proxy trusted (socket address only)", warning: null };
  }
  if (raw === "true") {
    return {
      setting: 1,
      description: "1 proxy hop",
      warning: 'TRUST_PROXY=true would trust every hop and make client IPs spoofable — using 1 hop instead. Set a number (e.g. 2) or a CIDR list.',
    };
  }
  if (/^\d+$/.test(raw)) {
    const n = Number(raw);
    return { setting: n, description: `${n} proxy hop${n === 1 ? "" : "s"}`, warning: null };
  }
  const tokens = raw.split(",").map((t) => t.trim()).filter(Boolean);
  for (const t of tokens) {
    if (KEYWORDS.has(t)) continue;
    const ok = t.includes("/") ? safe(() => ipaddr.parseCIDR(t)) : ipaddr.isValid(t);
    if (!ok) throw new Error(`Invalid TRUST_PROXY entry "${t}". Use a number, or a comma-separated list of CIDRs/IPs/loopback/linklocal/uniquelocal.`);
  }
  return { setting: tokens, description: `trusted proxies: ${tokens.join(", ")}`, warning: null };
}

function safe(fn) {
  try {
    fn();
    return true;
  } catch {
    return false;
  }
}

/** Normalises any textual IP (v4, v6, v4-mapped v6, with port/brackets/zone) to a canonical form. */
export function normalizeIp(input) {
  if (input === undefined || input === null) return null;
  let s = String(input).trim();
  if (!s) return null;
  if (s.startsWith("[")) {
    const end = s.indexOf("]");
    if (end > 0) s = s.slice(1, end);
  } else if (/^\d{1,3}(\.\d{1,3}){3}:\d+$/.test(s)) {
    s = s.split(":")[0];
  }
  s = s.replace(/%.+$/, ""); // IPv6 zone id
  // Strict forms only. ipaddr.js also accepts legacy shorthand such as
  // "203.0.113" or "0x7f.1", which would let odd spellings of an address
  // compare unequal to (or masquerade as) the canonical one.
  const isV4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(s) && ipaddr.IPv4.isValidFourPartDecimal(s);
  const isV6 = s.includes(":") && ipaddr.IPv6.isValid(s);
  if (!isV4 && !isV6) return null;
  try {
    let addr = ipaddr.parse(s);
    if (addr.kind() === "ipv6" && addr.isIPv4MappedAddress()) addr = addr.toIPv4Address();
    return addr.kind() === "ipv6" ? addr.toRFC5952String() : addr.toString();
  } catch {
    return null;
  }
}

/** The client IP as resolved by Express's trusted-proxy logic, normalised. */
export function getClientIp(req) {
  return normalizeIp(req.ip) || normalizeIp(req.socket?.remoteAddress) || "unknown";
}

/** true when the address is private / loopback / CGNAT / link-local — i.e. not a real internet client. */
export function isNonPublicIp(ip) {
  const n = normalizeIp(ip);
  if (!n) return false;
  try {
    const range = ipaddr.parse(n).range();
    return ["private", "loopback", "linkLocal", "uniqueLocal", "carrierGradeNat", "unspecified", "reserved"].includes(range);
  } catch {
    return false;
  }
}

/** Normalises a stored list of IPs (whitelist/blacklist) so "::ffff:1.2.3.4" and "1.2.3.4" compare equal. */
export function normalizeIpList(list) {
  return (Array.isArray(list) ? list : []).map((x) => normalizeIp(x) || String(x).trim()).filter(Boolean);
}

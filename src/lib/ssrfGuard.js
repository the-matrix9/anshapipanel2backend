import dns from "dns/promises";
import net from "net";
import ipaddr from "ipaddr.js";

const BLOCKED_HOSTNAMES = new Set(["localhost", "0.0.0.0", "metadata.google.internal"]);
const BLOCKED_SUFFIXES = [".localhost", ".local", ".internal", ".localdomain"];
const METADATA_IPS = new Set(["169.254.169.254"]); // cloud metadata endpoints

const BLOCKED_RANGES = new Set([
  "private",
  "loopback",
  "linkLocal",
  "uniqueLocal",
  "carrierGradeNat",
  "reserved",
  "unspecified",
  "broadcast",
  "multicast",
  // IPv6 transition mechanisms that can smuggle an internal IPv4 address
  "6to4",
  "teredo",
  "rfc6052",
  "rfc6145",
  "discard",
]);

export function isPrivateOrReservedIp(ip) {
  try {
    let addr = ipaddr.parse(ip);
    // "::ffff:127.0.0.1" reports range "ipv4Mapped", which would slip past a
    // range check — unwrap it and judge the embedded IPv4 address instead.
    if (addr.kind() === "ipv6" && addr.isIPv4MappedAddress()) addr = addr.toIPv4Address();
    return BLOCKED_RANGES.has(addr.range()) || METADATA_IPS.has(addr.toString());
  } catch {
    return true; // fail closed
  }
}

function assertHostnameAllowed(hostname) {
  const h = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (BLOCKED_HOSTNAMES.has(h) || BLOCKED_SUFFIXES.some((s) => h.endsWith(s))) {
    throw new Error("Upstream host is blocked (localhost/internal)");
  }
  if (net.isIP(h) && isPrivateOrReservedIp(h)) {
    throw new Error("Upstream resolves to a private/reserved IP range and is blocked");
  }
}

/**
 * Validates an upstream URL at *configuration time* and again at
 * *request time* before any proxied request is sent. Throws with a
 * descriptive message if unsafe. (The connect-time guard in
 * httpClient.js closes the remaining DNS-rebinding window.)
 */
export async function assertSafeUpstreamUrl(rawUrl) {
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new Error("Invalid upstream URL");
  }

  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error("Only http/https upstream URLs are allowed");
  }
  if (url.username || url.password) {
    throw new Error("Credentials embedded in the upstream URL are not allowed — use the Authentication section instead");
  }

  const hostname = url.hostname.toLowerCase();
  assertHostnameAllowed(hostname);
  if (net.isIP(hostname.replace(/^\[|\]$/g, ""))) return url;

  let records;
  try {
    records = await dns.lookup(hostname, { all: true });
  } catch {
    throw new Error("Upstream hostname could not be resolved");
  }
  if (!records.length) throw new Error("Upstream hostname did not resolve");
  for (const rec of records) {
    if (isPrivateOrReservedIp(rec.address)) {
      throw new Error("Upstream resolves to a private/reserved IP range and is blocked");
    }
  }
  return url;
}

/**
 * Connect-time DNS lookup for the shared HTTP agents. The address that is
 * actually connected to is the one validated here, so an attacker can't
 * pass the pre-flight check and then flip their DNS record to 127.0.0.1
 * (DNS rebinding / TOCTOU).
 */
export function guardedLookup(hostname, options, callback) {
  const cb = typeof options === "function" ? options : callback;
  const opts = typeof options === "function" ? {} : options || {};
  dns
    .lookup(hostname, { ...opts, all: true })
    .then((records) => {
      for (const r of records) {
        if (isPrivateOrReservedIp(r.address)) {
          return cb(new Error("Upstream resolves to a private/reserved IP range and is blocked"));
        }
      }
      if (opts.all) return cb(null, records);
      cb(null, records[0].address, records[0].family);
    })
    .catch((e) => cb(e));
}

/** axios `beforeRedirect` hook — a redirect must not lead to an internal literal IP/host. */
export function guardRedirect(options) {
  assertHostnameAllowed(options.hostname || options.host || "");
}

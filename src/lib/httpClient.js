import axios from "axios";
import http from "http";
import https from "https";
import { guardedLookup, guardRedirect } from "./ssrfGuard.js";

// A shared, connection-pooled HTTP client for all upstream proxy calls.
//
// keepAlive + a generous maxSockets lets concurrent requests to the same
// upstream host reuse a small pool of already-established connections
// instead of each paying full connection setup cost — the single biggest
// lever for surviving high-concurrency bursts without failures.
//
// `lookup: guardedLookup` validates the IP address at the moment of
// connecting (SSRF / DNS-rebinding protection), and `beforeRedirect`
// re-checks every redirect hop.
const agentOpts = { keepAlive: true, maxSockets: 256, maxFreeSockets: 64, lookup: guardedLookup };
const httpAgent = new http.Agent(agentOpts);
const httpsAgent = new https.Agent(agentOpts);

export const upstreamClient = axios.create({
  httpAgent,
  httpsAgent,
  maxRedirects: 3,
  beforeRedirect: guardRedirect,
  // Individual requests still set their own per-API `timeout`; this is
  // just the shared transport underneath every one of them.
});

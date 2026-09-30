import express from "express";
import http from "http";
import { parseTrustProxy, getClientIp } from "../src/lib/clientIp.js";
const ask = (port, xff) => new Promise((res) => http.get({ port, path: "/", headers: xff ? { "x-forwarded-for": xff } : {} }, (r) => { let b=""; r.on("data",d=>b+=d); r.on("end",()=>res(b)); }));
const cases = [
  ["TRUST_PROXY=1 (Railway)", "1", [["6.6.6.6, 1.2.3.4", "1.2.3.4"], ["6.6.6.6", "6.6.6.6*"], [null, "127.0.0.1"]]],
  ["TRUST_PROXY=0 (no proxy)", "0", [["6.6.6.6, 1.2.3.4", "127.0.0.1"], ["9.9.9.9", "127.0.0.1"]]],
  ["TRUST_PROXY=2 (Vercel->Railway)", "2", [["1.2.3.4, 76.76.21.9", "1.2.3.4"], ["6.6.6.6, 1.2.3.4, 76.76.21.9", "1.2.3.4"], ["2001:DB8::5, 10.0.0.1", "2001:db8::5"]]],
  ["TRUST_PROXY=loopback (CIDR)", "loopback", [["6.6.6.6, 1.2.3.4", "1.2.3.4"]]],
];
let port = 5300, fail = 0;
for (const [label, val, tests] of cases) {
  const app = express(); app.set("trust proxy", parseTrustProxy(val).setting);
  app.get("/", (req, res) => res.send(getClientIp(req)));
  const srv = app.listen(++port); 
  for (const [xff, expect] of tests) {
    const got = await ask(port, xff);
    const ok = got === expect.replace("*", "");
    if (!ok) fail++;
    console.log(ok ? "PASS" : "FAIL", label.padEnd(34), `XFF=${xff}`.padEnd(46), "->", got, expect.endsWith("*") ? "(single-entry XFF: that entry IS the proxy-observed client; expected)" : "");
  }
  srv.close();
}
process.exit(fail ? 1 : 0);

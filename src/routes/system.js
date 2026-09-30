import { Router } from "express";
import { requireAuth } from "../middleware/auth.js";
import { getClientIp, isNonPublicIp, normalizeIp } from "../lib/clientIp.js";

const router = Router();
router.use(requireAuth);

// Shows exactly what the server sees for THIS request, so an admin can verify
// TRUST_PROXY: open the dashboard, look at "Your IP as detected". If it isn't
// your real public IP, the proxy-hop count is wrong for this deployment.
// Only the caller's own request is reflected back — nothing about anyone else.
router.get("/network", (req, res) => {
  const xff = req.headers["x-forwarded-for"];
  res.json({
    status: true,
    data: {
      detected_ip: getClientIp(req),
      detected_ip_is_public: !isNonPublicIp(getClientIp(req)),
      socket_ip: normalizeIp(req.socket?.remoteAddress),
      forwarded_for_chain: xff ? String(xff).split(",").map((s) => s.trim()).filter(Boolean) : [],
      x_real_ip: req.headers["x-real-ip"] || null,
      trust_proxy: req.app.get("trust proxy config") || String(req.app.get("trust proxy")),
      protocol: req.protocol,
    },
  });
});

export default router;

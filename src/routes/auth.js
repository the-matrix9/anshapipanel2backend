import { Router } from "express";
import bcrypt from "bcryptjs";
import { z } from "zod";
import { db } from "../db/index.js";
import { signToken, cookieOptions, clearCookieOptions, requireAuth } from "../middleware/auth.js";
import { getClientIp } from "../lib/clientIp.js";

const router = Router();

const loginSchema = z.object({
  email: z.string().email().max(254),
  password: z.string().min(1).max(200),
});

// Compared against when the email doesn't exist, so response time doesn't
// reveal which emails are valid accounts.
const DUMMY_HASH = bcrypt.hashSync("not-a-real-password", 12);

router.post("/login", (req, res) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ status: false, error: "Invalid email or password format", code: "INVALID_INPUT" });
  }
  const { email, password } = parsed.data;
  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
  const ok = bcrypt.compareSync(password, user ? user.password_hash : DUMMY_HASH);
  if (!user || !ok) {
    return res.status(401).json({ status: false, error: "Invalid credentials", code: "INVALID_CREDENTIALS" });
  }

  res.cookie("token", signToken(user), cookieOptions);
  db.prepare("INSERT INTO audit_logs (user_id, action, target, ip_address) VALUES (?, 'login', ?, ?)").run(
    user.id,
    user.email,
    getClientIp(req)
  );

  res.json({ status: true, data: { email: user.email, name: user.name } });
});

// Logging out must always succeed — even with an expired/invalid session,
// where requireAuth would otherwise refuse and leave the cookie in place.
router.post("/logout", (req, res) => {
  res.clearCookie("token", clearCookieOptions);
  res.json({ status: true, data: { message: "Logged out" } });
});

router.get("/me", requireAuth, (req, res) => {
  const user = db.prepare("SELECT email, name, created_at FROM users WHERE id = ?").get(req.user.sub);
  res.json({ status: true, data: user });
});

export default router;

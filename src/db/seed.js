import bcrypt from "bcryptjs";
import crypto from "crypto";
import dotenv from "dotenv";
import { db } from "./index.js";
dotenv.config();

// The credentials that used to ship in .env.example / the README. If a
// deployment still uses them, say so loudly — they are public knowledge.
const KNOWN_DEFAULT_PASSWORD = "@Ansh1437";

const email = process.env.ADMIN_EMAIL || "anshapi@gmail.com";
const password = process.env.ADMIN_PASSWORD;

const existing = db.prepare("SELECT id FROM users WHERE email = ?").get(email);

if (password) {
  const hash = bcrypt.hashSync(password, 12);
  if (existing) {
    db.prepare("UPDATE users SET password_hash = ? WHERE email = ?").run(hash, email);
    console.log(`Admin account already existed — password synced from ADMIN_PASSWORD for ${email}`);
  } else {
    db.prepare("INSERT INTO users (email, password_hash, name) VALUES (?, ?, ?)").run(email, hash, "Ansh");
    console.log(`Admin account created: ${email}`);
  }
  if (password === KNOWN_DEFAULT_PASSWORD || /change_this/i.test(password)) {
    console.warn(
      "[security] ADMIN_PASSWORD is a publicly known/placeholder value. Set a strong unique password in your environment and redeploy."
    );
  }
} else if (existing) {
  // No ADMIN_PASSWORD configured: leave the existing password untouched
  // rather than silently resetting it to a hard-coded default.
  console.log(`Admin account ${email} exists — ADMIN_PASSWORD not set, password left unchanged.`);
} else {
  // Fresh database and no password configured: generate one instead of
  // creating an account with a guessable default.
  const generated = crypto.randomBytes(12).toString("base64url");
  db.prepare("INSERT INTO users (email, password_hash, name) VALUES (?, ?, ?)").run(
    email,
    bcrypt.hashSync(generated, 12),
    "Ansh"
  );
  console.log("=".repeat(60));
  console.log(`Admin account created: ${email}`);
  console.log(`Generated password (shown once, set ADMIN_PASSWORD to change it): ${generated}`);
  console.log("=".repeat(60));
}

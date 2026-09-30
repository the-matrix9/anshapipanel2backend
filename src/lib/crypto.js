import crypto from "crypto";
import dotenv from "dotenv";
dotenv.config();

// Derive a 32-byte key from ENCRYPTION_KEY (any length string) via SHA-256.
const rawKey = process.env.ENCRYPTION_KEY || "insecure_dev_key_change_me";
const KEY = crypto.createHash("sha256").update(rawKey).digest();
const ALGO = "aes-256-gcm";

export function encrypt(plainText) {
  if (plainText === null || plainText === undefined) return null;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGO, KEY, iv);
  const enc = Buffer.concat([cipher.update(String(plainText), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]).toString("base64");
}

export function decrypt(payload) {
  if (!payload) return null;
  try {
    const buf = Buffer.from(payload, "base64");
    const iv = buf.subarray(0, 12);
    const tag = buf.subarray(12, 28);
    const enc = buf.subarray(28);
    const decipher = crypto.createDecipheriv(ALGO, KEY, iv);
    decipher.setAuthTag(tag);
    const dec = Buffer.concat([decipher.update(enc), decipher.final()]);
    return dec.toString("utf8");
  } catch {
    return null;
  }
}

export function hashApiKey(key) {
  return crypto.createHash("sha256").update(key).digest("hex");
}

export function generateApiKey() {
  const raw = crypto.randomBytes(24).toString("base64url");
  const key = `sk_live_${raw}`;
  return { key, prefix: key.slice(0, 12) };
}

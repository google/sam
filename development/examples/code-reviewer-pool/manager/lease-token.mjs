import { createHmac, timingSafeEqual } from "node:crypto";

// Signed bearer lease token: `${peerId}.${exp}.${sig}`, sig = HMAC-SHA256(secret, `${peerId}.${exp}`).
// exp is epoch-ms; the token is valid while now < exp. Shared verbatim by manager and reviewer.

export function mintToken(secret, peerId, exp) {
  const payload = `${peerId}.${exp}`;
  const sig = createHmac("sha256", secret).update(payload).digest("hex");
  return `${payload}.${sig}`;
}

export function verifyToken(secret, token, now) {
  if (typeof token !== "string") return { valid: false };
  const parts = token.split("."); // peer ids are base58 (no dots), sig is hex → exactly 3 parts
  if (parts.length !== 3) return { valid: false };
  const [peerId, expStr, sig] = parts;
  const expected = createHmac("sha256", secret).update(`${peerId}.${expStr}`).digest("hex");
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !timingSafeEqual(a, b)) return { valid: false };
  const exp = Number(expStr);
  if (!Number.isFinite(exp) || now >= exp) return { valid: false };
  return { valid: true, peerId, exp };
}

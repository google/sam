import { test } from "node:test";
import assert from "node:assert/strict";
import { mintToken, verifyToken } from "./lease-token.mjs";

const SECRET = "test-secret";
const PEER = "12D3KooWabc";

test("mint then verify round-trips before expiry", () => {
  const token = mintToken(SECRET, PEER, 10_000);
  const r = verifyToken(SECRET, token, 5_000);
  assert.equal(r.valid, true);
  assert.equal(r.peerId, PEER);
  assert.equal(r.exp, 10_000);
});

test("rejects a tampered signature", () => {
  const token = mintToken(SECRET, PEER, 10_000);
  const bad = token.slice(0, -1) + (token.endsWith("a") ? "b" : "a");
  assert.equal(verifyToken(SECRET, bad, 5_000).valid, false);
});

test("rejects the wrong secret", () => {
  const token = mintToken(SECRET, PEER, 10_000);
  assert.equal(verifyToken("other-secret", token, 5_000).valid, false);
});

test("rejects an expired token", () => {
  const token = mintToken(SECRET, PEER, 10_000);
  assert.equal(verifyToken(SECRET, token, 10_000).valid, false);
});

test("rejects malformed or missing tokens", () => {
  assert.equal(verifyToken(SECRET, "garbage", 5_000).valid, false);
  assert.equal(verifyToken(SECRET, undefined, 5_000).valid, false);
});

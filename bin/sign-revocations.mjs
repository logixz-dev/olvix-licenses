#!/usr/bin/env node
// sign-revocations.mjs — produce the signed Olvix license revocation list.
//
// Reads `revoked-hashes.txt` (one SHA-256 hex per line; `#` comments and
// blank lines ignored), signs an EdDSA JWS with the license PRIVATE key,
// and writes `revocations.jwt` at the repo root. Zero npm dependencies —
// node:crypto only, so it runs with bare `node` or `bun`.
//
// The api (olvix-api/src/license/revocation.ts) fetches that file, verifies
// it against the SAME Ed25519 public key it uses for license tokens
// (olvix-api/src/license/public-key.ts), checks the `kind` claim, and
// downgrades any token whose hash is listed. Integrity comes from this
// signature — never from who serves the file — so the host only needs to
// be available (GitHub Pages).
//
// Usage:
//   node bin/sign-revocations.mjs --key /secure/license-private.pem
//   OLVIX_LICENSE_PRIVATE_KEY=/secure/license-private.pem node bin/sign-revocations.mjs
//
// The private key is the license signing key from the one-time keypair
// bootstrap (olvix-ops license-tokens runbook). NEVER commit it; pass it
// by path from your offline custody at sign time.

import { createPrivateKey, sign } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

const b64url = (buf) => Buffer.from(buf).toString("base64url");
const die = (msg) => {
  console.error(`error: ${msg}`);
  process.exit(1);
};

// ── resolve the private key path ─────────────────────────────────────
const args = process.argv.slice(2);
let keyPath = process.env.OLVIX_LICENSE_PRIVATE_KEY ?? "";
for (let i = 0; i < args.length; i++) {
  if (args[i] === "--key") keyPath = args[++i] ?? "";
}
if (!keyPath) {
  die("provide the license private key via --key <path> or OLVIX_LICENSE_PRIVATE_KEY");
}

// ── read + validate the hash list ────────────────────────────────────
const HASH_RE = /^[a-f0-9]{64}$/;
const hashesPath = new URL("../revoked-hashes.txt", import.meta.url);
const raw = readFileSync(hashesPath, "utf8");
const hashes = raw
  .split("\n")
  .map((line) => line.replace(/#.*$/, "").trim().toLowerCase())
  .filter((line) => line.length > 0);

const bad = hashes.filter((h) => !HASH_RE.test(h));
if (bad.length > 0) {
  die(`not valid SHA-256 hex (64 lowercase hex chars):\n  ${bad.join("\n  ")}`);
}
const unique = [...new Set(hashes)];

// ── load the key + assert it's Ed25519 ───────────────────────────────
let key;
try {
  key = createPrivateKey(readFileSync(keyPath, "utf8"));
} catch (err) {
  die(`could not read private key at ${keyPath}: ${err.message}`);
}
if (key.asymmetricKeyType !== "ed25519") {
  die(`key is ${key.asymmetricKeyType}, expected ed25519`);
}

// ── build + sign the compact JWS ──────────────────────────────────────
const header = b64url(JSON.stringify({ alg: "EdDSA", typ: "JWT" }));
const payload = b64url(
  JSON.stringify({
    kind: "olvix-revocations",
    revokedTokenHashes: unique,
    iat: Math.floor(Date.now() / 1000),
  }),
);
const signingInput = `${header}.${payload}`;
// Ed25519 in node:crypto: algorithm arg MUST be null.
const signature = b64url(sign(null, Buffer.from(signingInput), key));
const jwt = `${signingInput}.${signature}`;

writeFileSync(new URL("../revocations.jwt", import.meta.url), `${jwt}\n`);
console.log(`wrote revocations.jwt — ${unique.length} revoked hash(es)`);

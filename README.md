# olvix-licenses

Public host for the **signed Olvix enterprise-license revocation list**,
served via GitHub Pages at:

```
https://logixz-dev.github.io/olvix-licenses/revocations.jwt
```

This repo is intentionally **public** — the published list is a signed
document meant to be world-readable. The license **private key never
lives here**; it stays in Industrious Hive's offline custody and is
passed to the signing script by path at sign time.

## How it works

`revocations.jwt` is an Ed25519-signed JWT:

```json
{ "kind": "olvix-revocations", "revokedTokenHashes": ["<sha256-hex>", …], "iat": 1700000000 }
```

A self-hosted Olvix install (olvix-api) fetches it **only when it has an
enterprise license token**, verifies the signature against the same
Ed25519 public key it uses for license tokens
(`olvix-api/src/license/public-key.ts`), checks the `kind` claim, and
downgrades any token whose SHA-256 hash is on the list to community
defaults.

Design guarantees:

- **Fail-open.** Unreachable host, bad signature, wrong `kind`, or
  malformed payload → "nothing revoked", logged once. A problem here can
  never take a customer install down.
- **No phone-home for community.** Community (token-less) installs never
  construct the checker, so they never fetch this file.
- **Hash-based.** Every already-issued token is revocable without
  re-issuance; verbatim tokens never appear in this repo.
- **Host-agnostic integrity.** GitHub Pages only provides availability;
  trust is in the signature, so the host is swappable with one URL change.

## Revoking a token

Prerequisite: the license keypair must be bootstrapped (see the olvix-ops
`docs/operations/runbooks/license-tokens.md` one-time bootstrap) and you
have the private key in offline custody.

```bash
# 1. hash the token (the verbatim OLVIX_LICENSE_TOKEN string)
printf '%s' '<the token>' | shasum -a 256 | awk '{print $1}'

# 2. append the hash to revoked-hashes.txt, with a # note (customer, date)

# 3. sign (private key by path — never committed)
node bin/sign-revocations.mjs --key /secure/license-private.pem

# 4. publish
git commit -am "revoke <customerId> — <reason>" && git push
```

GitHub Pages redeploys on push. Propagation is bounded by the CDN cache
plus the api's 24h client cache; restart a customer's api to force
immediate pickup during an incident.

## Bootstrapping the empty list

At keypair bootstrap, sign once with an empty `revoked-hashes.txt` and
push so `/revocations.jwt` resolves cleanly (200 with an empty
`revokedTokenHashes`). Until then the path 404s and installs fail open —
safe, just noisier in logs.

## Verifying locally

```bash
# extract + check the payload of the current signed list
curl -s https://logixz-dev.github.io/olvix-licenses/revocations.jwt \
  | cut -d. -f2 | base64 -d 2>/dev/null | jq .
```

(Signature verification happens in the api against the license public
key; the command above just inspects the claims.)

## Custom domain (later)

To move to `license.industrioushive.com`: add a `CNAME` file with that
host, point a DNS CNAME at `logixz-dev.github.io`, and update
`OLVIX_LICENSE_REVOCATION_URL` in the olvix-ops env catalog. No customer
migration is needed while there are no enterprise installs configured
with the old URL.

# Changelog

## [Unreleased]

### Security & governance
- **Optional SecSSO admin login (OIDC).** The admin console and `/admin/api/*` accept a
  SecSSO bearer JWT or a browser session (Authorization Code + PKCE, httpOnly cookie) in
  addition to the static `SECCERT_ADMIN_TOKEN`, which remains valid as a break-glass
  credential. A login must carry the `SECCERT_ADMIN_GROUP` group (default
  `seccert-admins`) to administer SecCert. Off by default (no `SECCERT_OIDC_*` set); see
  `src/seccert/auth.py`.
- **Attributed, hash-chained audit ledger.** Every audit row now records a `principal`
  (`acme:<account id>` for ACME actions; the SecSSO `sub` or `token-admin` for admin
  actions) and is SHA-256 hash-chained to its predecessor. `GET /admin/api/audit/verify`
  walks the chain and reports whether it's intact. Existing databases upgrade in place via
  an `ALTER TABLE` migration; pre-migration rows are "grandfathered" (excluded from the
  chain, not reported as tampered).
- **One-shot compliance evidence bundle.** `GET /admin/api/evidence` returns sanitized
  config, audit-chain verification, recent audit events, and a live NIST SP 800-171
  control self-assessment — never CA keys, the CA passphrase, or the admin token.
- **Control mapping added to `docs/security.md`** — SC/AU/IA/CM control table with
  file:function pointers and evidence commands (mapping, not a certification claim).

## [1.0.0] — SecCert

First public release — a mini ACME (RFC 8555) certificate authority for closed networks.

### PKI & issuance
- **Two-tier PKI** — self-signed Root signs an Intermediate; only the Intermediate signs
  leaves. ECDSA P-384 by default (`ecdsa-p256` / `ecdsa-p384` / `rsa-3072` / `rsa-4096`).
- **Full RFC 8555 flow** — directory, nonce, account, order, authorization, HTTP-01
  challenge, finalize, certificate download, revoke. JWS with ES256/RS256, RFC 7638
  account thumbprints, replay-nonce on every ACME response.
- **CRL** and native-TLS self-issued serving certificates.
- Short-lived leaves (default 90 days) so mis-issuance is self-healing.

### Admin & operations
- Token-gated admin API + a dependency-free console; the trust anchor and `/health` stay
  open so hosts can bootstrap trust without credentials.
- SQLite state plus an append-only issuance/revocation audit ledger.
- Dockerfile (non-root) and a `docker-compose.yml` demo running a real `certbot` client
  against SecCert over HTTP-01.
- Sphinx documentation; JWS/CA unit tests plus a full in-process ACME end-to-end test.

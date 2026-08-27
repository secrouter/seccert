# Security posture

SecCert is a certificate authority — its private keys are the crown jewels. The design keeps
the attack surface small and the sensitive material contained.

## Key handling

- The **Root** and **Intermediate** keys are generated in-process on first boot and written
  to `/var/lib/seccert/ca/` with `0600` permissions in a `0700` directory.
- Only the **Intermediate** signs at request time. The Root signs exactly once — the
  Intermediate — and is otherwise untouched; keep the data volume access-controlled and
  consider air-gapping backups of the Root key.
- Set `SECCERT_CA_PASSPHRASE` to encrypt both keys at rest (PKCS#8, best-available cipher).
- Default CA key type is ECDSA **P-384**; leaves inherit the client's CSR key.

## Issuance discipline

- Leaves are short-lived (default 90 days) so mis-issuance is self-healing.
- The CSR presented at finalize must request **exactly** the order's validated identifiers;
  any mismatch is rejected (`badCSR`).
- Every issuance and revocation is written to an append-only, **hash-chained** audit ledger
  (viewable in the console, via `GET /admin/api/audit`, and verified via
  `GET /admin/api/audit/verify` — see AU-3.3.8 below).

## Network

- HTTP-01 validation is a single outbound fetch from SecCert to the requesting host inside
  the boundary. No inbound path from the public internet is required or used.
- The admin API is gated by a bearer token (`SECCERT_ADMIN_TOKEN`) by default, or by SecSSO
  admin login when `SECCERT_OIDC_*` is configured (see IA-3.5.1/3.5.2 below); the trust-anchor
  and `/health` endpoints are intentionally open so hosts can bootstrap trust.

## Audit ledger: hash chain and attribution

- Every audit row records a **principal**: an ACME account acting on its own resources is
  `acme:<account id>` (a machine identity — SecCert never learns who operates that key); an
  admin action is the SecSSO `sub` when OIDC admin auth is active, else the literal
  `token-admin` (the shared bearer token has no per-operator identity to attribute to).
- Rows are **hash-chained** (AU-3.3.8): each row's `hash` is SHA-256 over
  `prev_hash, ts, event, principal, detail` (canonically joined), where `prev_hash` is the
  previous row's `hash`, or the literal `GENESIS` for the very first chained row. Mutating or
  deleting a row breaks the chain from that point forward — `GET /admin/api/audit/verify`
  walks the chain and reports `{ok, checked, startedAtId, brokenAtId?}`.
- **Grandfathering.** The `principal`/`prev_hash`/`hash` columns were added by an in-place
  `ALTER TABLE` migration (`Store._migrate_audit_columns`); pre-migration rows have none of
  them (`NULL`) and are never treated as chain violations — verification simply starts at the
  first row that *has* a hash (`startedAtId`). A brand-new deployment has no pre-migration rows,
  so its chain starts at row 1 with `prev_hash = GENESIS`.
- Detail fields remain metadata only (identifiers, serials, reasons, hashes) — never
  certificate private keys, the CA passphrase, or the admin token.

## Optional SecSSO admin login

- By default the admin API and console accept only the static `SECCERT_ADMIN_TOKEN` bearer
  token, exactly as before this feature existed.
- Setting `SECCERT_OIDC_ISSUER` (+ client id/secret, `SECCERT_PUBLIC_URL`,
  `SECCERT_SESSION_SECRET`) turns on SecSSO admin login, mirroring SecLLM's `auth.py`: a
  bearer JWT (CLI/script) or a browser session cookie minted via Authorization Code + PKCE,
  either verified against SecSSO's JWKS. A login is accepted as admin only if it carries the
  `SECCERT_ADMIN_GROUP` group (default `seccert-admins`).
- The static token remains valid as a **break-glass** credential even with SSO configured —
  turning on SSO never locks out an operator who still has the token.
- `GET /health` and `GET /admin/api/evidence`'s `controls` report which identity mode is
  currently in effect.

## Control mapping (not certification)

SecCert is designed to slot into a CMMC / NIST SP 800-171 enclave. It is a building block —
these are mappings and evidence pointers, **not** a certification claim. IDs are bare
NIST SP 800-171 R2 control identifiers (Family column below); prose/code comments cite them as
`FAMILY-ID`, e.g. `AU-3.3.8`.

| Family | ID | Requirement | Implementation (file:function) | Evidence command |
|---|---|---|---|---|
| SC | 3.13.8 | Encrypt CUI in transit | Issues the certs that enable TLS everywhere in-boundary | `curl https://<host>/health` |
| SC | 3.13.11 | Cryptographic protection | ECDSA P-384 CA by default; leaves inherit the client's CSR key | `GET /admin/api/ca` |
| SC | 3.13.10 | Protect cryptographic keys | CA keys at `0600` in a `0700`-mode `ca_dir`; optional `SECCERT_CA_PASSPHRASE` encrypts them at rest | `config.py` (`Config.ensure_dirs`), `ca.py` | `stat -f%Lp <data_dir>/ca` (expect `700`); `GET /admin/api/evidence` → `controls["SC-3.13.10 (cryptographic key protection)"]` |
| SC | 3.13.1 / 3.13.6 | Boundary protection | Runs offline; no egress to public CAs; HTTP-01 validation stays in-enclave | `acme/router.py` (`challenge`), `validation.py` | inspect egress rules of the deployment |
| AU | 3.3.1 / 3.3.2 | Create & trace audit records | Every ACME/admin event is appended with an attributed `principal` | `store.py` (`Store.audit`), `acme/router.py`, `admin/api.py` (`admin_revoke`) | `GET /admin/api/audit` |
| AU | 3.3.8 | Protect audit information | SHA-256 hash chain over the audit ledger; tamper detected by chain walk | `store.py` (`Store._chain_hash`, `Store.verify_audit_chain`) | `GET /admin/api/audit/verify` |
| IA | 3.5.1 / 3.5.2 | Identify & authenticate (admin plane) | Static bearer token by default; optional SecSSO OIDC (bearer + BFF session) with admin-group gate, static token remains break-glass | `auth.py`, `admin/api.py` (`require_admin`) | `GET /health` → `auth`; `GET /auth/status` |
| IA | 3.5.2 | Identify & authenticate (devices) | Machine/service identity via short-lived leaf certificates | `acme/router.py` (`finalize`) | `GET /admin/api/certificates` |
| CM | 3.4.6 | Least functionality | Single-purpose service; one open trust-anchor endpoint; docs/OpenAPI disabled; admin gated | `app.py` (`create_app`), `admin/api.py` | `GET /docs` → 404 |

## Shared Responsibility

SecCert issues and tracks certificates. The operator owns: protecting and backing up the
data volume, distributing and rotating the Root, terminating TLS with a FIPS-validated module
where required, running an accurate time source (validity windows depend on it), restricting
network reachability to the ACME and admin ports, running/configuring the SecSSO IdP when OIDC
admin login is used (issuer, admin-group membership, MFA at the IdP), and long-term/legal-hold
archival of audit records beyond what the local ledger retains.

# Reference

## Configuration (environment)

| Variable | Default | Meaning |
|---|---|---|
| `SECCERT_EXTERNAL_URL` | `http://localhost:<port>` | Base URL clients use; every ACME URL is built from it |
| `SECCERT_DATA_DIR` | `./data` | CA keys + SQLite state (mount a volume) |
| `SECCERT_HOST` | `0.0.0.0` | Bind address |
| `SECCERT_PORT` | `14000` | Bind port |
| `SECCERT_ORG` | `SecCert` | Organization name in CA subjects |
| `SECCERT_ROOT_CN` | `SecCert Root CA` | Root common name |
| `SECCERT_INTERMEDIATE_CN` | `SecCert Intermediate CA` | Intermediate common name |
| `SECCERT_CA_KEY_TYPE` | `ecdsa-p384` | `ecdsa-p256` \| `ecdsa-p384` \| `rsa-3072` \| `rsa-4096` |
| `SECCERT_ROOT_DAYS` | `7300` | Root validity (days) |
| `SECCERT_INTERMEDIATE_DAYS` | `1825` | Intermediate validity (days) |
| `SECCERT_LEAF_DAYS` | `90` | Issued-cert lifetime (days) |
| `SECCERT_HTTP01_PORT` | `80` | Port SecCert fetches for HTTP-01 validation |
| `SECCERT_HTTP01_TIMEOUT` | `5` | Validation fetch timeout (seconds) |
| `SECCERT_TLS_MODE` | `none` | `none` (HTTP, behind a proxy) or `native` (SecCert terminates TLS) |
| `SECCERT_TLS_CERT` / `SECCERT_TLS_KEY` | — | Serving cert/key for `native` mode (else self-issued) |
| `SECCERT_CA_PASSPHRASE` | — | Encrypt CA private keys at rest |
| `SECCERT_ADMIN_TOKEN` | auto | Bearer token for the admin console/API (auto-generated + logged if unset); remains valid as a break-glass credential even when SecSSO is configured |
| `SECCERT_REQUIRE_EAB` | `false` | Require External Account Binding on new accounts |
| `SECCERT_TOS` | — | Terms-of-service URL advertised in the directory meta |

### Optional SecSSO admin login (OIDC)

Unset by default — the admin plane then accepts only `SECCERT_ADMIN_TOKEN`, exactly as
above. Setting these turns on SecSSO login for `/admin` and the `/admin/api/*` endpoints
(the token remains valid too, as break-glass); see {doc}`security` for the full model.

| Variable | Default | Meaning |
|---|---|---|
| `SECCERT_OIDC_ISSUER` | — | SecSSO issuer URL. Setting this + `SECCERT_OIDC_AUDIENCE` enables bearer-JWT admin auth |
| `SECCERT_OIDC_CLIENT_ID` | — | OIDC client id (required for browser login) |
| `SECCERT_OIDC_CLIENT_SECRET` | — | OIDC confidential-client secret (required for browser login) |
| `SECCERT_OIDC_AUDIENCE` | `SECCERT_OIDC_CLIENT_ID` | Expected token audience |
| `SECCERT_PUBLIC_URL` | — | This service's externally-reachable URL, used to build the `/auth/callback` redirect URI (required for browser login) |
| `SECCERT_SESSION_SECRET` | — | HS256 signing secret for the session/flow cookies (required for browser login) |
| `SECCERT_SESSION_TTL` | `43200` | Browser session lifetime, seconds (12h) |
| `SECCERT_ADMIN_GROUP` | `seccert-admins` | Group a login must carry to administer SecCert; blank = any authenticated user |
| `SECCERT_OIDC_JWKS_URL` | discovered | Override JWKS endpoint (skips `/.well-known/openid-configuration` discovery) |
| `SECCERT_OIDC_AUTHORIZE_URL` | discovered | Override authorization endpoint |
| `SECCERT_OIDC_TOKEN_URL` | discovered | Override token endpoint |

## ACME endpoints (RFC 8555)

| Endpoint | Method | Purpose |
|---|---|---|
| `/acme/directory` | GET | Entry point; lists the URLs below |
| `/acme/new-nonce` | HEAD/GET | Fresh anti-replay nonce |
| `/acme/new-account` | POST | Register / look up an account (JWS `jwk`) |
| `/acme/new-order` | POST | Request a certificate for DNS identifiers |
| `/acme/authz/{id}` | POST | Authorization + its challenges |
| `/acme/challenge/{id}` | POST | Signal ready → SecCert validates (HTTP-01) |
| `/acme/order/{id}/finalize` | POST | Submit CSR → issue |
| `/acme/order/{id}` | POST | Poll order status |
| `/acme/certificate/{id}` | POST | Download the chain (leaf + intermediate) |
| `/acme/revoke-cert` | POST | Revoke (account key or certificate key) |

## Public + admin endpoints

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /` | open | Redirect to the console |
| `GET /admin` | open | Admin console (token entered client-side, or SecSSO session) |
| `GET /health` | open | Liveness + CA subjects & SHA-256 fingerprints + admin-plane auth posture |
| `GET /ca.crt` · `/roots` | open | Root trust anchor (PEM) |
| `GET /intermediate.crt` | open | Intermediate (PEM) |
| `GET /crl` | open | Certificate revocation list (DER) |
| `GET /admin/api/ca` | admin | CA details |
| `GET /admin/api/certificates` | admin | List issued/revoked certs |
| `POST /admin/api/certificates/{serial}/revoke` | admin | Revoke a certificate |
| `GET /admin/api/audit` | admin | Issuance/revocation audit ledger (most recent 200 events) |
| `GET /admin/api/audit/verify` | admin | Walk the audit hash chain; `{ok, checked, startedAtId, brokenAtId?}` — see {doc}`security` |
| `GET /admin/api/evidence` | admin | One-shot CMMC/NIST SP 800-171 evidence bundle: sanitized config, chain verification, recent audit events, control self-assessment |

Admin calls send `Authorization: Bearer <SECCERT_ADMIN_TOKEN>` (default), or a SecSSO
bearer JWT / browser session when `SECCERT_OIDC_*` is configured — see the SecSSO admin
login table above and {doc}`security`.

## Auth endpoints (`/auth/*`, SecSSO only)

Present only in the sense that they respond even when SSO is unconfigured (with a
`sso_not_configured` error where relevant); they only *do* anything once
`SECCERT_OIDC_*` is set.

| Endpoint | Purpose |
|---|---|
| `GET /auth/status` | Whether SSO/bearer is enabled, and — if a session cookie is present — who's signed in and whether they're an admin |
| `GET /auth/login` | Start the Authorization Code + PKCE flow; redirects to the SecSSO issuer |
| `GET /auth/callback` | OIDC redirect target; exchanges the code, mints the session cookie |
| `POST /auth/logout` | Clear the session cookie |

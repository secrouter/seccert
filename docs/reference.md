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
| `SECCERT_ADMIN_TOKEN` | auto | Bearer token for the admin console/API (auto-generated + logged if unset) |
| `SECCERT_REQUIRE_EAB` | `false` | Require External Account Binding on new accounts |
| `SECCERT_TOS` | — | Terms-of-service URL advertised in the directory meta |

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
| `GET /admin` | open | Admin console (token entered client-side) |
| `GET /health` | open | Liveness + CA subjects & SHA-256 fingerprints |
| `GET /ca.crt` · `/roots` | open | Root trust anchor (PEM) |
| `GET /intermediate.crt` | open | Intermediate (PEM) |
| `GET /crl` | open | Certificate revocation list (DER) |
| `GET /admin/api/ca` | admin | CA details |
| `GET /admin/api/certificates` | admin | List issued/revoked certs |
| `POST /admin/api/certificates/{serial}/revoke` | admin | Revoke a certificate |
| `GET /admin/api/audit` | admin | Issuance/revocation audit ledger |

Admin calls send `Authorization: Bearer <SECCERT_ADMIN_TOKEN>`.

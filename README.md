# SecCert — a mini ACME CA for closed networks

**Automatic TLS certificates inside an air-gapped enclave — no path to the public internet.**
SecCert is a self-hosted [ACME](https://datatracker.ietf.org/doc/html/rfc8555) (RFC 8555)
certificate authority: point any standard ACME client (certbot, acme.sh, Caddy, Traefik,
lego, `step`) at it and your internal services get short-lived, auto-renewing certs from a
CA **you** run and trust. Think "a tiny Let's Encrypt for your `.mil`/`.internal` network."

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![ACME](https://img.shields.io/badge/ACME-RFC%208555-444)](https://datatracker.ietf.org/doc/html/rfc8555)

Part of the **SecRouter** family — pairs naturally with SecRouter's TLS front end and any
service that needs certs without reaching out to a public CA.

---

## Why

Closed / regulated networks (CMMC enclaves, GovCloud, lab and OT segments) can't reach
Let's Encrypt, yet still want the operational win of ACME: **no manual CSRs, no long-lived
certs, no expiry pages.** SecCert gives you the ACME workflow with a trust anchor that never
leaves your boundary.

- **Standards-based** — real RFC 8555. Existing ACME clients work unmodified.
- **Two-tier PKI** — a self-signed **Root** signs an **Intermediate**; only the Intermediate
  signs leaves. Publish the Root once as your enclave trust anchor.
- **Offline** — everything (key generation, issuance, validation) happens in-network. No
  telemetry, no external calls.
- **Small & auditable** — Python + FastAPI + `cryptography`, one container, SQLite state,
  an issuance audit ledger.

## Quickstart (Docker)

```bash
docker run -d --name seccert \
  -p 14000:14000 \
  -v seccert-data:/var/lib/seccert \
  -e SECCERT_EXTERNAL_URL=http://ca.internal.example:14000 \
  ghcr.io/secrouter/seccert:latest
```

On first boot SecCert generates the Root + Intermediate into the data volume and prints the
admin token. Grab the trust anchor and hand it to your hosts:

```bash
curl -o seccert-root.pem http://ca.internal.example:14000/ca.crt
```

Then point a client at the ACME directory:

```bash
# certbot (standalone http-01)
certbot certonly --standalone \
  --server http://ca.internal.example:14000/acme/directory \
  -d app.internal.example --agree-tos -m ops@internal.example

# acme.sh
acme.sh --issue --standalone \
  --server http://ca.internal.example:14000/acme/directory \
  -d app.internal.example
```

Or from source with [`uv`](https://docs.astral.sh/uv/):

```bash
uv run seccert           # serves on 0.0.0.0:14000
```

## Distributing the trust anchor

Clients validate SecCert-issued certs by trusting the **Root** (never the Intermediate — the
served chain already includes it). Distribute `GET /ca.crt` to your fleet:

- **Linux:** drop it in `/usr/local/share/ca-certificates/` → `update-ca-certificates`
- **RHEL:** `/etc/pki/ca-trust/source/anchors/` → `update-ca-trust`
- **Browsers / Java / Windows:** import into the respective trust store

`GET /roots` returns the same anchor as a PEM bundle for automation.

## ACME endpoints

| Endpoint | Purpose |
|---|---|
| `GET /acme/directory` | ACME directory (entry point for clients) |
| `HEAD/GET /acme/new-nonce` | Fresh anti-replay nonce |
| `POST /acme/new-account` | Register/look up an account (JWS, `jwk`) |
| `POST /acme/new-order` | Request a cert for one or more DNS identifiers |
| `POST /acme/authz/{id}` | Authorization + its challenges |
| `POST /acme/challenge/{id}` | Signal a challenge is ready → SecCert validates (HTTP-01) |
| `POST /acme/order/{id}/finalize` | Submit the CSR → SecCert issues |
| `POST /acme/certificate/{id}` | Download the issued chain (leaf + intermediate) |
| `POST /acme/revoke-cert` | Revoke a certificate |

## Admin console & API

`GET /admin` — a dependency-free console (SecRouter field-console theme): list & inspect
issued certificates, revoke, download the Root, and see CA info. Admin calls use a bearer
token (`SECCERT_ADMIN_TOKEN`; auto-generated and logged on first boot if unset).

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /ca.crt` · `/roots` | open | Root trust anchor (PEM) |
| `GET /health` | open | Liveness + CA fingerprint |
| `GET /admin/api/certificates` | admin | List issued/revoked certs |
| `POST /admin/api/certificates/{serial}/revoke` | admin | Revoke a cert |
| `GET /crl` | open | Certificate revocation list (DER) |

## Configuration (environment)

| Variable | Default | Meaning |
|---|---|---|
| `SECCERT_EXTERNAL_URL` | `http://localhost:<port>` | Base URL clients use; every ACME URL is built from it |
| `SECCERT_DATA_DIR` | `./data` | CA keys + SQLite state (mount a volume) |
| `SECCERT_HOST` / `SECCERT_PORT` | `0.0.0.0` / `14000` | Bind address |
| `SECCERT_CA_KEY_TYPE` | `ecdsa-p384` | Root/Intermediate key: `ecdsa-p256\|ecdsa-p384\|rsa-3072\|rsa-4096` |
| `SECCERT_LEAF_DAYS` | `90` | Issued-cert lifetime |
| `SECCERT_ROOT_DAYS` / `SECCERT_INTERMEDIATE_DAYS` | `7300` / `1825` | CA validity |
| `SECCERT_HTTP01_PORT` | `80` | Port SecCert fetches for HTTP-01 validation |
| `SECCERT_CA_PASSPHRASE` | — | Encrypt CA private keys at rest |
| `SECCERT_TLS_MODE` | `none` | `none` (HTTP, behind a proxy) or `native` (SecCert terminates TLS) |
| `SECCERT_ADMIN_TOKEN` | auto | Bearer token for the admin console/API |
| `SECCERT_REQUIRE_EAB` | `false` | Require External Account Binding on new accounts |

## Security posture

- CA private keys are generated in-container and stored owner-only in the data volume;
  optional passphrase encryption at rest (`SECCERT_CA_PASSPHRASE`).
- Only the Intermediate signs at request time; the Root signs exactly once (the Intermediate).
- Every issuance and revocation is written to an append-only audit ledger.
- HTTP-01 is validated by SecCert reaching the requesting host inside the boundary — no
  inbound path from the public internet is required or used.
- ACME normally runs over HTTPS. In `native` TLS mode SecCert serves with a certificate it
  **self-issues** for its own hostname; otherwise run it behind a TLS-terminating proxy.

## License

[Apache 2.0](LICENSE) — Copyright 2026 Austin Probe.

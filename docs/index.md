# SecCert

**A mini ACME certificate authority for closed networks.**

SecCert is a self-hosted [ACME](https://datatracker.ietf.org/doc/html/rfc8555) (RFC 8555)
server: point any standard ACME client — certbot, acme.sh, Caddy, Traefik, lego, `step` —
at it and your internal services get short-lived, auto-renewing TLS certificates from a CA
**you** run and trust, with no path to the public internet. Think of it as a tiny Let's
Encrypt for your `.mil` / `.internal` enclave.

It is part of the **SecRouter** family and pairs naturally with SecRouter's TLS front end.

## Why it exists

Closed and regulated networks (CMMC enclaves, GovCloud, lab/OT segments) can't reach
Let's Encrypt, yet still want the ACME workflow: no manual CSRs, no long-lived certs, no
expiry surprises. SecCert delivers that with a trust anchor that never leaves your boundary.

- **Standards-based** — real RFC 8555; existing ACME clients work unmodified.
- **Two-tier PKI** — a self-signed Root signs an Intermediate; only the Intermediate signs
  leaves. Publish the Root once as the enclave trust anchor.
- **Offline** — key generation, issuance, and HTTP-01 validation all happen in-network.
- **Small & auditable** — Python + FastAPI + `cryptography`, one container, SQLite state,
  an append-only issuance ledger.

## Quickstart

```bash
docker run -d --name seccert -p 14000:14000 \
  -v seccert-data:/var/lib/seccert \
  -e SECCERT_EXTERNAL_URL=http://ca.internal.example:14000 \
  secrouter/seccert:latest

# distribute the trust anchor, then issue:
curl -o seccert-root.pem http://ca.internal.example:14000/ca.crt
certbot certonly --standalone \
  --server http://ca.internal.example:14000/acme/directory \
  -d app.internal.example --agree-tos -m ops@internal.example
```

```{toctree}
:maxdepth: 2
:caption: Guide

deployment
clients
trust
security
reference
```

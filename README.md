# SecCert — a mini ACME CA for closed networks

**Automatic TLS certificates inside an air-gapped enclave — no path to the public internet.**
SecCert is a self-hosted [ACME](https://datatracker.ietf.org/doc/html/rfc8555) (RFC 8555)
certificate authority: point any standard ACME client (certbot, acme.sh, Caddy, Traefik,
lego, `step`) at it and your internal services get short-lived, auto-renewing certs from a
CA **you** run and trust. Think "a tiny Let's Encrypt for your `.mil`/`.internal` network."

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![ACME](https://img.shields.io/badge/ACME-RFC%208555-444)](https://datatracker.ietf.org/doc/html/rfc8555)

Part of the [SecRouter suite](https://github.com/secrouter/secdeploy#the-suite) — deployed
first on every target as the internal CA. Pairs naturally with
[SecRouter](https://github.com/secrouter/secrouter)'s TLS front end and
[SecSSO](https://github.com/secrouter/secsso) for optional admin login (see below).

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
  a hash-chained, tamper-evident issuance ledger.

## Quickstart

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
certbot certonly --standalone \
  --server http://ca.internal.example:14000/acme/directory \
  -d app.internal.example --agree-tos -m ops@internal.example
```

Or from source with [`uv`](https://docs.astral.sh/uv/):

```bash
uv run seccert           # serves on 0.0.0.0:14000
```

## Documentation

Full docs (deployment, client integration, trust-anchor distribution, security posture,
environment/endpoint reference) live in [`docs/`](docs/) and build with Sphinx:

```bash
uv run --with-requirements docs/requirements.txt sphinx-build -b html docs docs/_build
```

Start at [`docs/index.md`](docs/index.md) — or, once built, open `docs/_build/index.html`.

- [Deployment](docs/deployment.md) — container, TLS modes, SecSSO admin login, hardening.
- [ACME client integration](docs/clients.md) — certbot, acme.sh, Caddy, Traefik, lego.
- [Trust anchor distribution](docs/trust.md) — getting the Root into every OS/runtime.
- [Security posture](docs/security.md) — key handling, audit chain, control mapping.
- [Reference](docs/reference.md) — every `SECCERT_*` variable and every endpoint.

## Admin console & API

`GET /admin` — a dependency-free console: list & inspect issued certificates, revoke,
download the Root, and see CA info. Gated by a bearer token (`SECCERT_ADMIN_TOKEN`,
auto-generated and logged on first boot if unset) or, optionally, SecSSO login — see
[Deployment](docs/deployment.md#optional-secsso-admin-login).

## License

[Apache 2.0](LICENSE) — Copyright 2026 Austin Probe. See [CHANGELOG.md](CHANGELOG.md) for
release history.

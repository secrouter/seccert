# Deployment

SecCert ships as a single container with one persistent volume. It needs no config file —
everything is driven by `SECCERT_*` environment variables.

## Run the container

```bash
docker run -d --name seccert \
  -p 14000:14000 \
  -v seccert-data:/var/lib/seccert \
  -e SECCERT_EXTERNAL_URL=http://ca.internal.example:14000 \
  -e SECCERT_ADMIN_TOKEN=$(openssl rand -hex 24) \
  --restart unless-stopped \
  secrouter/seccert:latest
```

On first boot SecCert generates the **Root** and **Intermediate** into
`/var/lib/seccert/ca/` (owner-only) and creates the SQLite state at
`/var/lib/seccert/seccert.db`. Back up that volume — it *is* your CA.

`SECCERT_EXTERNAL_URL` is important: every ACME resource URL SecCert advertises is built
from it, so it must be the address clients actually use (including scheme and port).

## TLS

ACME is normally spoken over HTTPS. Two supported models:

:::{note}
**Behind a proxy (recommended)** — leave `SECCERT_TLS_MODE=none` and run SecCert behind a
TLS-terminating reverse proxy (the same pattern as SecRouter's front end). Point
`SECCERT_EXTERNAL_URL` at the proxy's `https://` address.
:::

**Native TLS** — set `SECCERT_TLS_MODE=native`. If you don't supply `SECCERT_TLS_CERT` /
`SECCERT_TLS_KEY`, SecCert **self-issues** a serving certificate for its own hostname from
its Intermediate. Clients that already trust the Root will trust it automatically.

## Compose demo

The repo ships a `docker-compose.yml` that runs SecCert plus a real `certbot` client that
obtains a certificate over HTTP-01 inside the compose network:

```bash
docker compose up --build
```

Watch the `client` service log for `=== issued ===` and the printed subject / issuer / SAN.

## Native (from source)

```bash
git clone https://github.com/secrouter/seccert.git
cd seccert
uv run seccert          # serves on 0.0.0.0:14000
```

## Key protection at rest

Set `SECCERT_CA_PASSPHRASE` to encrypt the Root and Intermediate private keys on disk
(PKCS#8, best-available encryption). Without it, keys rely on the owner-only data volume.

## Optional: SecSSO admin login

By default the admin console/API accept only `SECCERT_ADMIN_TOKEN`. To put the admin
plane behind your SecSSO IdP instead (the static token stays valid as break-glass), add:

```bash
# SECCERT_PUBLIC_URL is behind a TLS-terminating proxy (see TLS above) — the browser
# login's session cookie is only marked secure when this is an https:// address.
docker run -d --name seccert \
  -p 14000:14000 \
  -v seccert-data:/var/lib/seccert \
  -e SECCERT_EXTERNAL_URL=https://ca.internal.example \
  -e SECCERT_ADMIN_TOKEN=$(openssl rand -hex 24) \
  -e SECCERT_OIDC_ISSUER=https://sso.internal.example/application/o/seccert/ \
  -e SECCERT_OIDC_CLIENT_ID=seccert \
  -e SECCERT_OIDC_CLIENT_SECRET=<confidential client secret> \
  -e SECCERT_PUBLIC_URL=https://ca.internal.example \
  -e SECCERT_SESSION_SECRET=$(openssl rand -hex 32) \
  --restart unless-stopped \
  secrouter/seccert:latest
```

A login is only accepted as admin if it carries the `SECCERT_ADMIN_GROUP` group
(default `seccert-admins`) — everyone else is authenticated but not an admin. See the
full variable list in {doc}`reference` and the auth model in {doc}`security`.

## Hardening checklist

- Mount `/var/lib/seccert` on encrypted storage; restrict access to the CA operator.
- Set an explicit `SECCERT_ADMIN_TOKEN` (don't rely on the auto-generated one).
- Terminate TLS (proxy or native) — don't expose plain HTTP outside the host.
- Keep `SECCERT_LEAF_DAYS` short (default 90) so mis-issuance is self-healing.
- Distribute the Root out-of-band and verify its SHA-256 fingerprint (see `/health`).
- Periodically call `GET /admin/api/audit/verify` (or pull `/admin/api/evidence`) to
  confirm the audit ledger is intact.

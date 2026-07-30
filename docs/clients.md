# ACME client integration

SecCert implements RFC 8555, so any conformant ACME client works. Point the client's
**directory URL** at `${SECCERT_EXTERNAL_URL}/acme/directory` and make sure the client host
is reachable by SecCert on port 80 for the HTTP-01 challenge.

Below, `ca.internal.example:14000` is SecCert and `app.internal.example` is the service
getting a certificate.

## certbot

```bash
# standalone (certbot opens :80 to answer the challenge)
certbot certonly --standalone \
  --server http://ca.internal.example:14000/acme/directory \
  -d app.internal.example \
  --agree-tos -m ops@internal.example --non-interactive
```

Certificates land in `/etc/letsencrypt/live/app.internal.example/`. Renewal uses the same
server automatically (`certbot renew`).

## acme.sh

```bash
acme.sh --issue --standalone \
  --server http://ca.internal.example:14000/acme/directory \
  -d app.internal.example
```

## Caddy

```text
{
    acme_ca http://ca.internal.example:14000/acme/directory
}

app.internal.example {
    reverse_proxy localhost:8080
}
```

## Traefik (static config)

```yaml
certificatesResolvers:
  seccert:
    acme:
      caServer: http://ca.internal.example:14000/acme/directory
      email: ops@internal.example
      httpChallenge:
        entryPoint: web
```

## lego

```bash
lego --server http://ca.internal.example:14000/acme/directory \
     --email ops@internal.example \
     --http --domains app.internal.example run
```

## Notes for closed networks

- **HTTP-01 only** in this release. The requesting host must serve
  `http://<host>/.well-known/acme-challenge/<token>` on port 80, reachable from SecCert.
  Wildcards and unreachable hosts (which need DNS-01) are not yet supported.
- Clients must **trust the Root** to validate the issued chain — see
  {doc}`trust`. The served chain already includes the Intermediate.
- Some clients warn when the directory URL is plain `http://`. Prefer running SecCert
  behind TLS (or in native TLS mode) so the directory is `https://`.

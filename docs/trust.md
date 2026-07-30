# Distributing the trust anchor

Clients validate SecCert-issued certificates by trusting the **Root** — never the
Intermediate (the served chain already includes it). Fetch the Root once and distribute it
to every host, browser, and runtime in the enclave.

```bash
curl -o seccert-root.pem http://ca.internal.example:14000/ca.crt
```

Verify you have the right anchor by comparing its SHA-256 fingerprint against
`GET /health` (or the admin console):

```bash
openssl x509 -in seccert-root.pem -noout -fingerprint -sha256
```

## Operating systems

**Debian / Ubuntu**

```bash
sudo cp seccert-root.pem /usr/local/share/ca-certificates/seccert-root.crt
sudo update-ca-certificates
```

**RHEL / Fedora**

```bash
sudo cp seccert-root.pem /etc/pki/ca-trust/source/anchors/seccert-root.pem
sudo update-ca-trust
```

**macOS**

```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain seccert-root.pem
```

**Windows (PowerShell, admin)**

```powershell
Import-Certificate -FilePath seccert-root.pem `
  -CertStoreLocation Cert:\LocalMachine\Root
```

## Runtimes

- **OpenSSL / curl:** point `SSL_CERT_FILE` at the Root, or add it to the system bundle.
- **Python (requests/httpx):** `REQUESTS_CA_BUNDLE` / `SSL_CERT_FILE`, or `verify=` the PEM.
- **Node.js:** `NODE_EXTRA_CA_CERTS=/path/seccert-root.pem`.
- **Java:** `keytool -importcert -trustcacerts -alias seccert-root -file seccert-root.pem
  -keystore "$JAVA_HOME/lib/security/cacerts"`.

## Endpoints

| Endpoint | Returns |
|---|---|
| `GET /ca.crt` | Root, as a download (`seccert-root.pem`) |
| `GET /roots` | Root, as a PEM bundle (for automation) |
| `GET /intermediate.crt` | Intermediate (handy for debugging chains) |
| `GET /crl` | Certificate revocation list (DER) |

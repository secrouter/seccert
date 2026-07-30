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
- Every issuance and revocation is written to an append-only **audit ledger** (viewable in
  the console and via `GET /admin/api/audit`).

## Network

- HTTP-01 validation is a single outbound fetch from SecCert to the requesting host inside
  the boundary. No inbound path from the public internet is required or used.
- The admin API is gated by a bearer token (`SECCERT_ADMIN_TOKEN`); the trust-anchor and
  `/health` endpoints are intentionally open so hosts can bootstrap trust.

## Control mapping (not certification)

SecCert is designed to slot into a CMMC / NIST SP 800-171 enclave. It is a building block —
these are mappings and evidence pointers, **not** a certification claim.

| Area | Control (800-171 R2) | How SecCert helps |
|---|---|---|
| Cryptographic protection | SC 3.13.8, 3.13.11 | Issues the certs that enable TLS everywhere in-boundary; ECDSA P-384 CA |
| Boundary protection | SC 3.13.1/3.13.6 | Runs offline; no egress to public CAs; validation stays in-enclave |
| Audit & accountability | AU 3.3.1/3.3.2 | Append-only issuance/revocation ledger with timestamps |
| Identification & auth of devices | IA 3.5.2 | Machine/service identity via short-lived leaf certificates |
| Least functionality | CM 3.4.6 | Single-purpose service, one open trust-anchor endpoint, token-gated admin |

## Shared responsibility

SecCert issues and tracks certificates. The operator owns: protecting and backing up the
data volume, distributing and rotating the Root, terminating TLS with a FIPS-validated module
where required, running an accurate time source (validity windows depend on it), and
restricting network reachability to the ACME and admin ports.

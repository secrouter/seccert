"""SecCert PKI — a two-tier certificate authority (Root -> Intermediate -> leaf).

Built entirely on :mod:`cryptography`. On first start the CA generates a self-signed
**Root** and an **Intermediate** signed by it, persists the keys to the data volume
(owner-only), and thereafter signs ACME-issued **leaf** certificates with the
Intermediate. The Root is published as the trust anchor for the enclave; only the
Intermediate key is used at request time.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

# Public/private key type aliases used throughout.
PrivateKey = ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey
PublicKey = ec.EllipticCurvePublicKey | rsa.RSAPublicKey


def _utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def generate_private_key(key_type: str) -> PrivateKey:
    if key_type == "ecdsa-p256":
        return ec.generate_private_key(ec.SECP256R1())
    if key_type == "ecdsa-p384":
        return ec.generate_private_key(ec.SECP384R1())
    if key_type == "rsa-3072":
        return rsa.generate_private_key(public_exponent=65537, key_size=3072)
    if key_type == "rsa-4096":
        return rsa.generate_private_key(public_exponent=65537, key_size=4096)
    raise ValueError(f"unsupported key type: {key_type!r}")


def signature_hash(key: PrivateKey) -> hashes.HashAlgorithm:
    """Pick a sane signing digest for the CA key (SHA-384 for P-384, else SHA-256)."""
    if isinstance(key, ec.EllipticCurvePrivateKey) and key.curve.name == "secp384r1":
        return hashes.SHA384()
    return hashes.SHA256()


def _ski(pub: PublicKey) -> x509.SubjectKeyIdentifier:
    return x509.SubjectKeyIdentifier.from_public_key(pub)


def _serialize_key(key: PrivateKey, passphrase: str) -> bytes:
    enc: serialization.KeySerializationEncryption
    enc = (
        serialization.BestAvailableEncryption(passphrase.encode())
        if passphrase
        else serialization.NoEncryption()
    )
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc,
    )


def cert_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


@dataclass
class CertificateAuthority:
    """Loads (or, on first run, creates) the Root + Intermediate and issues leaves."""

    ca_dir: Path
    org: str
    root_cn: str
    intermediate_cn: str
    key_type: str = "ecdsa-p384"
    root_days: int = 7300
    intermediate_days: int = 1825
    passphrase: str = ""

    root_key: PrivateKey = None  # type: ignore[assignment]
    root_cert: x509.Certificate = None  # type: ignore[assignment]
    intermediate_key: PrivateKey = None  # type: ignore[assignment]
    intermediate_cert: x509.Certificate = None  # type: ignore[assignment]

    # ---- lifecycle ---------------------------------------------------------

    def load_or_create(self) -> "CertificateAuthority":
        self.ca_dir.mkdir(parents=True, exist_ok=True)
        root_key_p = self.ca_dir / "root.key"
        root_crt_p = self.ca_dir / "root.crt"
        int_key_p = self.ca_dir / "intermediate.key"
        int_crt_p = self.ca_dir / "intermediate.crt"

        if root_key_p.exists() and root_crt_p.exists():
            self.root_key = self._load_key(root_key_p)
            self.root_cert = x509.load_pem_x509_certificate(root_crt_p.read_bytes())
        else:
            self.root_key, self.root_cert = self._make_root()
            self._write_key(root_key_p, self.root_key)
            self._write_cert(root_crt_p, self.root_cert)

        if int_key_p.exists() and int_crt_p.exists():
            self.intermediate_key = self._load_key(int_key_p)
            self.intermediate_cert = x509.load_pem_x509_certificate(int_crt_p.read_bytes())
        else:
            self.intermediate_key, self.intermediate_cert = self._make_intermediate()
            self._write_key(int_key_p, self.intermediate_key)
            self._write_cert(int_crt_p, self.intermediate_cert)
        return self

    def _load_key(self, path: Path) -> PrivateKey:
        pw = self.passphrase.encode() if self.passphrase else None
        return serialization.load_pem_private_key(path.read_bytes(), password=pw)  # type: ignore[return-value]

    def _write_key(self, path: Path, key: PrivateKey) -> None:
        path.write_bytes(_serialize_key(key, self.passphrase))
        try:
            path.chmod(0o600)
        except OSError:  # pragma: no cover - non-POSIX
            pass

    def _write_cert(self, path: Path, cert: x509.Certificate) -> None:
        path.write_bytes(cert_pem(cert))
        try:
            path.chmod(0o644)
        except OSError:  # pragma: no cover - non-POSIX
            pass

    # ---- CA cert construction ---------------------------------------------

    def _make_root(self) -> tuple[PrivateKey, x509.Certificate]:
        key = generate_private_key(self.key_type)
        name = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.org),
                x509.NameAttribute(NameOID.COMMON_NAME, self.root_cn),
            ]
        )
        now = _utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - _dt.timedelta(minutes=5))
            .not_valid_after(now + _dt.timedelta(days=self.root_days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
            .add_extension(_ca_key_usage(), critical=True)
            .add_extension(_ski(key.public_key()), critical=False)
            .sign(key, signature_hash(key))
        )
        return key, cert

    def _make_intermediate(self) -> tuple[PrivateKey, x509.Certificate]:
        key = generate_private_key(self.key_type)
        name = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.org),
                x509.NameAttribute(NameOID.COMMON_NAME, self.intermediate_cn),
            ]
        )
        now = _utcnow()
        root_ski = self.root_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(self.root_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - _dt.timedelta(minutes=5))
            .not_valid_after(now + _dt.timedelta(days=self.intermediate_days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(_ca_key_usage(), critical=True)
            .add_extension(_ski(key.public_key()), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(root_ski.value),
                critical=False,
            )
            .sign(self.root_key, signature_hash(self.root_key))
        )
        return key, cert

    # ---- leaf issuance -----------------------------------------------------

    def issue_leaf(
        self,
        public_key: PublicKey,
        dns_names: list[str],
        not_after: _dt.datetime,
    ) -> x509.Certificate:
        """Sign a leaf server certificate for ``dns_names`` with the Intermediate."""
        if not dns_names:
            raise ValueError("at least one DNS name is required")
        now = _utcnow()
        int_ski = self.intermediate_cert.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        )
        is_rsa = isinstance(public_key, rsa.RSAPublicKey)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, dns_names[0])]))
            .issuer_name(self.intermediate_cert.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - _dt.timedelta(minutes=5))
            .not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=is_rsa,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage(
                    [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
                ),
                critical=False,
            )
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(h) for h in dns_names]),
                critical=False,
            )
            .add_extension(_ski(public_key), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(int_ski.value),
                critical=False,
            )
            .sign(self.intermediate_key, signature_hash(self.intermediate_key))
        )
        return cert

    def self_issue_server_cert(
        self, dns_names: list[str], days: int = 397
    ) -> tuple[PrivateKey, x509.Certificate]:
        """Mint a leaf (with a fresh key) for SecCert's own hostname — used for native TLS."""
        key = generate_private_key("ecdsa-p256")
        cert = self.issue_leaf(
            key.public_key(), dns_names, _utcnow() + _dt.timedelta(days=days)
        )
        return key, cert

    # ---- chain / trust anchor / CRL ---------------------------------------

    def chain_pem(self, leaf: x509.Certificate) -> bytes:
        """RFC 8555 chain: leaf first, then the Intermediate (Root is a trust anchor)."""
        return cert_pem(leaf) + cert_pem(self.intermediate_cert)

    def root_pem(self) -> bytes:
        return cert_pem(self.root_cert)

    def intermediate_pem(self) -> bytes:
        return cert_pem(self.intermediate_cert)

    def build_crl(
        self, entries: Iterable[tuple[int, _dt.datetime]]
    ) -> x509.CertificateRevocationList:
        now = _utcnow()
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self.intermediate_cert.subject)
            .last_update(now)
            .next_update(now + _dt.timedelta(days=7))
        )
        for serial, revoked_at in entries:
            revoked = (
                x509.RevokedCertificateBuilder()
                .serial_number(serial)
                .revocation_date(revoked_at)
                .build()
            )
            builder = builder.add_revoked_certificate(revoked)
        return builder.sign(self.intermediate_key, signature_hash(self.intermediate_key))


def _ca_key_usage() -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=False,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False,
    )

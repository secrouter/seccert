"""SecCert configuration — environment-first, with closed-network-friendly defaults.

Everything is driven by ``SECCERT_*`` environment variables so the container needs
no config file. :meth:`Config.from_env` reads them once at startup and validates the
enum-valued settings, failing fast on an unsafe/invalid configuration.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from pathlib import Path

CA_KEY_TYPES = {"ecdsa-p256", "ecdsa-p384", "rsa-3072", "rsa-4096"}
TLS_MODES = {"none", "native"}


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError as exc:  # pragma: no cover - trivial
        raise ValueError(f"{name} must be an integer, got {raw!r}") from exc


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Config:
    """Immutable runtime configuration for one SecCert instance."""

    # Storage
    data_dir: Path
    # Networking / ACME URL base
    host: str
    port: int
    external_url: str  # base URL clients use; every ACME resource URL is built from this
    # CA identity + key policy
    org: str
    root_cn: str
    intermediate_cn: str
    ca_key_type: str
    root_days: int
    intermediate_days: int
    # Leaf issuance policy
    leaf_days: int
    # HTTP-01 validation
    http01_port: int
    http01_timeout: float
    # TLS serving ("none" = plain HTTP behind a proxy; "native" = SecCert terminates TLS)
    tls_mode: str
    tls_cert: str
    tls_key: str
    # CA key protection at rest (optional passphrase; empty = keys stored unencrypted,
    # relying on the owner-only data volume)
    ca_passphrase: str
    # Admin
    admin_token: str
    admin_token_generated: bool
    # ACME options
    require_eab: bool
    terms_of_service: str

    @property
    def db_path(self) -> Path:
        return self.data_dir / "seccert.db"

    @property
    def ca_dir(self) -> Path:
        return self.data_dir / "ca"

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        # CA private keys live here — keep the directory owner-only.
        self.ca_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.ca_dir, 0o700)
        except OSError:  # pragma: no cover - non-POSIX fallback
            pass

    @staticmethod
    def from_env() -> "Config":
        port = _env_int("SECCERT_PORT", 14000)
        external = _env("SECCERT_EXTERNAL_URL", "").strip().rstrip("/")
        if not external:
            external = f"http://localhost:{port}"

        admin_token = _env("SECCERT_ADMIN_TOKEN", "").strip()
        generated = not admin_token
        if generated:
            # Usable out of the box, still unguessable; logged once at startup.
            admin_token = secrets.token_urlsafe(24)

        ca_key_type = _env("SECCERT_CA_KEY_TYPE", "ecdsa-p384").strip().lower()
        if ca_key_type not in CA_KEY_TYPES:
            raise ValueError(
                f"SECCERT_CA_KEY_TYPE must be one of {sorted(CA_KEY_TYPES)}, got {ca_key_type!r}"
            )

        tls_mode = _env("SECCERT_TLS_MODE", "none").strip().lower()
        if tls_mode not in TLS_MODES:
            raise ValueError(f"SECCERT_TLS_MODE must be one of {sorted(TLS_MODES)}, got {tls_mode!r}")

        return Config(
            data_dir=Path(_env("SECCERT_DATA_DIR", "./data")).expanduser(),
            host=_env("SECCERT_HOST", "0.0.0.0"),
            port=port,
            external_url=external,
            org=_env("SECCERT_ORG", "SecCert"),
            root_cn=_env("SECCERT_ROOT_CN", "SecCert Root CA"),
            intermediate_cn=_env("SECCERT_INTERMEDIATE_CN", "SecCert Intermediate CA"),
            ca_key_type=ca_key_type,
            root_days=_env_int("SECCERT_ROOT_DAYS", 7300),
            intermediate_days=_env_int("SECCERT_INTERMEDIATE_DAYS", 1825),
            leaf_days=_env_int("SECCERT_LEAF_DAYS", 90),
            http01_port=_env_int("SECCERT_HTTP01_PORT", 80),
            http01_timeout=float(_env("SECCERT_HTTP01_TIMEOUT", "5")),
            tls_mode=tls_mode,
            tls_cert=_env("SECCERT_TLS_CERT", ""),
            tls_key=_env("SECCERT_TLS_KEY", ""),
            ca_passphrase=_env("SECCERT_CA_PASSPHRASE", ""),
            admin_token=admin_token,
            admin_token_generated=generated,
            require_eab=_env_bool("SECCERT_REQUIRE_EAB", False),
            terms_of_service=_env("SECCERT_TOS", ""),
        )

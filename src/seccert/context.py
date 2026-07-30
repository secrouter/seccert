"""Shared application context passed to the routers."""

from __future__ import annotations

from dataclasses import dataclass

from .ca import CertificateAuthority
from .config import Config
from .store import Store


@dataclass
class Context:
    config: Config
    ca: CertificateAuthority
    store: Store

    # URL builders — every ACME resource URL is derived from the external base so the
    # advertised URLs stay correct behind a TLS-terminating proxy.
    def url(self, path: str) -> str:
        return f"{self.config.external_url}{path}"

    def directory_url(self) -> str:
        return self.url("/acme/directory")

    def account_url(self, acc_id: str) -> str:
        return self.url(f"/acme/account/{acc_id}")

    def order_url(self, order_id: str) -> str:
        return self.url(f"/acme/order/{order_id}")

    def finalize_url(self, order_id: str) -> str:
        return self.url(f"/acme/order/{order_id}/finalize")

    def authz_url(self, authz_id: str) -> str:
        return self.url(f"/acme/authz/{authz_id}")

    def challenge_url(self, chall_id: str) -> str:
        return self.url(f"/acme/challenge/{chall_id}")

    def certificate_url(self, cert_id: str) -> str:
        return self.url(f"/acme/certificate/{cert_id}")

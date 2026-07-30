"""HTTP-01 challenge validation (RFC 8555 §8.3).

SecCert fetches ``http://{host}/.well-known/acme-challenge/{token}`` from the identifier
inside the enclave and checks the body equals the expected key authorization. No inbound
path from the public internet is used.
"""

from __future__ import annotations

import httpx

from .acme.jws import jwk_thumbprint

WELL_KNOWN = "/.well-known/acme-challenge/"


def key_authorization(token: str, account_jwk: dict) -> str:
    """``token || '.' || base64url(SHA-256(JWK))`` — RFC 8555 §8.1."""
    return f"{token}.{jwk_thumbprint(account_jwk)}"


async def validate_http01(
    host: str,
    token: str,
    expected: str,
    *,
    port: int = 80,
    timeout: float = 5.0,
) -> tuple[bool, tuple[str, str] | None]:
    """Return ``(ok, None)`` on success or ``(False, (acme_error_kind, detail))``."""
    authority = host if port == 80 else f"{host}:{port}"
    url = f"http://{authority}{WELL_KNOWN}{token}"
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            resp = await client.get(url, headers={"User-Agent": "SecCert-ACME/1.0"})
    except httpx.HTTPError as exc:
        return False, ("connection", f"failed to fetch {url}: {exc}")

    if resp.status_code != 200:
        return False, ("incorrectResponse", f"unexpected HTTP status {resp.status_code} from {url}")

    # RFC allows trailing whitespace/newlines around the key authorization.
    if resp.text.strip() != expected:
        return False, ("incorrectResponse", "key authorization did not match")
    return True, None

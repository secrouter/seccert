"""JWS handling for ACME — flattened JSON serialization (RFC 8555 §6.2).

Supports the signature algorithms ACME clients actually use: ECDSA (ES256/ES384/ES512)
and RSASSA-PKCS1-v1_5 (RS256). Also converts JWKs to public keys and computes the
RFC 7638 JWK thumbprint used for key authorizations.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from ..errors import AcmeError

# ES* -> (curve, hash, coordinate byte length)
_ES = {
    "ES256": (ec.SECP256R1, hashes.SHA256, 32),
    "ES384": (ec.SECP384R1, hashes.SHA384, 48),
    "ES512": (ec.SECP521R1, hashes.SHA512, 66),
}
_EC_CURVES = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1(), "P-521": ec.SECP521R1()}


def b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    try:
        return base64.urlsafe_b64decode(data + pad)
    except Exception as exc:  # noqa: BLE001
        raise AcmeError("malformed", "invalid base64url") from exc


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def jwk_to_public_key(jwk: dict[str, Any]):
    kty = jwk.get("kty")
    if kty == "EC":
        curve = _EC_CURVES.get(jwk.get("crv", ""))
        if curve is None:
            raise AcmeError("badPublicKey", f"unsupported curve {jwk.get('crv')!r}")
        x = int.from_bytes(b64url_decode(jwk["x"]), "big")
        y = int.from_bytes(b64url_decode(jwk["y"]), "big")
        return ec.EllipticCurvePublicNumbers(x, y, curve).public_key()
    if kty == "RSA":
        n = int.from_bytes(b64url_decode(jwk["n"]), "big")
        e = int.from_bytes(b64url_decode(jwk["e"]), "big")
        return rsa.RSAPublicNumbers(e, n).public_key()
    raise AcmeError("badPublicKey", f"unsupported key type {kty!r}")


def jwk_thumbprint(jwk: dict[str, Any]) -> str:
    """RFC 7638 SHA-256 thumbprint over the JWK's required members, lexicographically."""
    kty = jwk.get("kty")
    if kty == "EC":
        members = {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
    elif kty == "RSA":
        members = {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}
    else:
        raise AcmeError("badPublicKey", f"unsupported key type {kty!r}")
    canonical = json.dumps(members, separators=(",", ":"), sort_keys=True).encode()
    return b64url_encode(hashlib.sha256(canonical).digest())


@dataclass
class ParsedJWS:
    protected: dict[str, Any]
    payload: bytes
    signature: bytes
    signing_input: bytes

    @property
    def alg(self) -> str:
        return self.protected.get("alg", "")

    @property
    def nonce(self) -> str:
        return self.protected.get("nonce", "")

    @property
    def url(self) -> str:
        return self.protected.get("url", "")

    @property
    def jwk(self) -> dict[str, Any] | None:
        return self.protected.get("jwk")

    @property
    def kid(self) -> str | None:
        return self.protected.get("kid")

    def payload_json(self) -> dict[str, Any]:
        """Decoded JSON payload, or ``{}`` for a POST-as-GET (empty payload)."""
        if self.payload == b"":
            return {}
        try:
            obj = json.loads(self.payload)
        except ValueError as exc:
            raise AcmeError("malformed", "payload is not valid JSON") from exc
        if not isinstance(obj, dict):
            raise AcmeError("malformed", "payload must be a JSON object")
        return obj


def parse_jws(body: dict[str, Any]) -> ParsedJWS:
    if not isinstance(body, dict) or not {"protected", "payload", "signature"} <= body.keys():
        raise AcmeError("malformed", "request is not a well-formed flattened JWS")
    try:
        protected = json.loads(b64url_decode(body["protected"]))
    except ValueError as exc:
        raise AcmeError("malformed", "protected header is not valid JSON") from exc
    if not isinstance(protected, dict):
        raise AcmeError("malformed", "protected header must be a JSON object")
    if "jwk" in protected and "kid" in protected:
        raise AcmeError("malformed", "protected header has both jwk and kid")
    if not protected.get("alg"):
        raise AcmeError("malformed", "protected header missing alg")

    payload = b64url_decode(body["payload"]) if body["payload"] != "" else b""
    signature = b64url_decode(body["signature"])
    signing_input = (body["protected"] + "." + body["payload"]).encode("ascii")
    return ParsedJWS(protected=protected, payload=payload, signature=signature, signing_input=signing_input)


def verify_signature(jwk: dict[str, Any], alg: str, signing_input: bytes, signature: bytes) -> None:
    """Verify the JWS signature or raise :class:`AcmeError`."""
    public_key = jwk_to_public_key(jwk)
    if alg in _ES:
        _curve, hash_cls, size = _ES[alg]
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise AcmeError("badSignatureAlgorithm", "alg/key mismatch")
        if len(signature) != 2 * size:
            raise AcmeError("malformed", "malformed ECDSA signature")
        r = int.from_bytes(signature[:size], "big")
        s = int.from_bytes(signature[size:], "big")
        der = encode_dss_signature(r, s)
        try:
            public_key.verify(der, signing_input, ec.ECDSA(hash_cls()))
        except Exception as exc:  # noqa: BLE001
            raise AcmeError("unauthorized", "JWS signature verification failed") from exc
    elif alg == "RS256":
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise AcmeError("badSignatureAlgorithm", "alg/key mismatch")
        try:
            public_key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
        except Exception as exc:  # noqa: BLE001
            raise AcmeError("unauthorized", "JWS signature verification failed") from exc
    else:
        raise AcmeError("badSignatureAlgorithm", f"unsupported alg {alg!r}")

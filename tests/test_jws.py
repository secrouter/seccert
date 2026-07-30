"""Unit tests for the JWS / JWK layer."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from seccert.acme.jws import b64url_encode, jwk_thumbprint, jwk_to_public_key, verify_signature
from seccert.errors import AcmeError


def _ec_jwk(key: ec.EllipticCurvePrivateKey) -> dict:
    n = key.public_key().public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64url_encode(n.x.to_bytes(32, "big")),
        "y": b64url_encode(n.y.to_bytes(32, "big")),
    }


def _int_bytes(i: int) -> bytes:
    return i.to_bytes((i.bit_length() + 7) // 8, "big")


def test_thumbprint_is_key_order_independent():
    jwk = _ec_jwk(ec.generate_private_key(ec.SECP256R1()))
    shuffled = {k: jwk[k] for k in reversed(list(jwk))}
    assert jwk_thumbprint(jwk) == jwk_thumbprint(shuffled)


def test_jwk_to_public_key_roundtrip():
    key = ec.generate_private_key(ec.SECP256R1())
    pub = jwk_to_public_key(_ec_jwk(key))
    assert pub.public_numbers() == key.public_key().public_numbers()


def test_verify_es256_accepts_valid_and_rejects_tampered():
    key = ec.generate_private_key(ec.SECP256R1())
    jwk = _ec_jwk(key)
    signing_input = b"protected.payload"
    r, s = decode_dss_signature(key.sign(signing_input, ec.ECDSA(hashes.SHA256())))
    sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")

    verify_signature(jwk, "ES256", signing_input, sig)  # must not raise
    with pytest.raises(AcmeError):
        verify_signature(jwk, "ES256", b"different-input", sig)


def test_verify_rs256():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    n = key.public_key().public_numbers()
    jwk = {"kty": "RSA", "n": b64url_encode(_int_bytes(n.n)), "e": b64url_encode(_int_bytes(n.e))}
    signing_input = b"a.b"
    sig = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    verify_signature(jwk, "RS256", signing_input, sig)


def test_unsupported_alg_rejected():
    jwk = _ec_jwk(ec.generate_private_key(ec.SECP256R1()))
    with pytest.raises(AcmeError):
        verify_signature(jwk, "HS256", b"x", b"y")

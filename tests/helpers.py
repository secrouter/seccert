"""Test helpers: a threaded HTTP-01 responder and a minimal ACME client.

The ``MiniACME`` client speaks real RFC 8555 JWS over the FastAPI TestClient, exactly as
certbot/acme.sh would — proving interop without needing an external ACME client installed.
"""

from __future__ import annotations

import base64
import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class Challenge01Server:
    """Serves ``/.well-known/acme-challenge/<token>`` from an in-memory map (like a host under test)."""

    def __init__(self) -> None:
        self.tokens: dict[str, str] = {}
        tokens = self.tokens

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):  # silence
                pass

            def do_GET(self):  # noqa: N802
                prefix = "/.well-known/acme-challenge/"
                if self.path.startswith(prefix):
                    token = self.path[len(prefix):]
                    if token in tokens:
                        body = tokens[token].encode()
                        self.send_response(200)
                        self.send_header("Content-Type", "application/octet-stream")
                        self.send_header("Content-Length", str(len(body)))
                        self.end_headers()
                        self.wfile.write(body)
                        return
                self.send_response(404)
                self.end_headers()

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def start(self) -> "Challenge01Server":
        self._thread.start()
        return self

    def stop(self) -> None:
        self.httpd.shutdown()

    def publish(self, token: str, key_authorization: str) -> None:
        self.tokens[token] = key_authorization


def make_csr(names: list[str]) -> tuple[ec.EllipticCurvePrivateKey, x509.CertificateSigningRequest]:
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, csr


class MiniACME:
    """A tiny ES256 ACME client driving the app through a TestClient."""

    def __init__(self, client) -> None:
        self.client = client
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.nonce: str | None = None
        self.kid: str | None = None
        self.dir: dict = {}

    # -- key material --
    def jwk(self) -> dict:
        nums = self.key.public_key().public_numbers()
        return {
            "crv": "P-256",
            "kty": "EC",
            "x": b64(nums.x.to_bytes(32, "big")),
            "y": b64(nums.y.to_bytes(32, "big")),
        }

    def thumbprint(self) -> str:
        jwk = self.jwk()
        canon = json.dumps(
            {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]},
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        return b64(hashlib.sha256(canon).digest())

    def _sign(self, signing_input: bytes) -> bytes:
        der = self.key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    # -- protocol --
    def directory(self) -> dict:
        self.dir = self.client.get("/acme/directory").json()
        return self.dir

    def refresh_nonce(self) -> None:
        r = self.client.get(self.dir["newNonce"])
        self.nonce = r.headers["Replay-Nonce"]

    def post(self, url: str, payload, use_kid: bool = True):
        protected: dict = {"alg": "ES256", "nonce": self.nonce, "url": url}
        if use_kid and self.kid:
            protected["kid"] = self.kid
        else:
            protected["jwk"] = self.jwk()
        pb = b64(json.dumps(protected).encode())
        yb = "" if payload is None else b64(json.dumps(payload).encode())
        sig = self._sign((pb + "." + yb).encode("ascii"))
        r = self.client.post(
            url,
            json={"protected": pb, "payload": yb, "signature": b64(sig)},
            headers={"Content-Type": "application/jose+json"},
        )
        if "Replay-Nonce" in r.headers:
            self.nonce = r.headers["Replay-Nonce"]
        return r

    def new_account(self):
        r = self.post(self.dir["newAccount"], {"termsOfServiceAgreed": True}, use_kid=False)
        if "Location" in r.headers:
            self.kid = r.headers["Location"]
        return r

    def new_order(self, names: list[str]):
        return self.post(
            self.dir["newOrder"],
            {"identifiers": [{"type": "dns", "value": n} for n in names]},
        )


def chain_first_cert_der(chain_pem: str) -> bytes:
    return x509.load_pem_x509_certificates(chain_pem.encode())[0].public_bytes(Encoding.DER)

"""End-to-end ACME flow against the running app, driven by a real JWS client."""

from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding

from helpers import MiniACME, b64, chain_first_cert_der, make_csr

ADMIN = {"Authorization": "Bearer test-admin-token"}


def _issue(acme: MiniACME, http01, names: list[str]):
    """Run the whole account -> order -> challenge -> finalize -> download flow."""
    acme.directory()
    acme.refresh_nonce()
    acme.new_account()

    resp = acme.new_order(names)
    assert resp.status_code == 201, resp.text
    order = resp.json()
    order_url = resp.headers["Location"]

    for authz_url in order["authorizations"]:
        authz = acme.post(authz_url, None).json()
        chall = next(c for c in authz["challenges"] if c["type"] == "http-01")
        http01.publish(chall["token"], f"{chall['token']}.{acme.thumbprint()}")
        cr = acme.post(chall["url"], {})
        assert cr.status_code == 200, cr.text
        assert cr.json()["status"] == "valid", cr.json()

    order = acme.post(order_url, None).json()
    assert order["status"] == "ready", order

    csr_key, csr = make_csr(names)
    order = acme.post(order["finalize"], {"csr": b64(csr.public_bytes(Encoding.DER))}).json()
    assert order["status"] == "valid", order
    assert "certificate" in order

    chain = acme.post(order["certificate"], None)
    assert chain.headers["content-type"].startswith("application/pem-certificate-chain")
    return csr_key, chain.text


def _verify_chain(chain_pem: str):
    certs = x509.load_pem_x509_certificates(chain_pem.encode())
    assert len(certs) == 2, "chain must be leaf + intermediate"
    leaf, intermediate = certs
    intermediate.public_key().verify(
        leaf.signature, leaf.tbs_certificate_bytes, ec.ECDSA(leaf.signature_hash_algorithm)
    )
    return leaf, intermediate


def test_full_issue_flow(client, http01):
    acme = MiniACME(client)
    csr_key, chain = _issue(acme, http01, ["localhost"])
    leaf, _ = _verify_chain(chain)
    sans = leaf.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value.get_values_for_type(x509.DNSName)
    assert sans == ["localhost"]
    assert leaf.public_key().public_numbers() == csr_key.public_key().public_numbers()


def test_new_account_is_idempotent(client, http01):
    acme = MiniACME(client)
    acme.directory()
    acme.refresh_nonce()
    first = acme.new_account()
    assert first.status_code == 201
    kid = acme.kid
    again = acme.new_account()
    assert again.status_code == 200  # existing account returned
    assert again.headers["Location"] == kid


def test_http01_failure_marks_invalid(client, http01):
    acme = MiniACME(client)
    acme.directory()
    acme.refresh_nonce()
    acme.new_account()
    order = acme.new_order(["localhost"]).json()
    authz = acme.post(order["authorizations"][0], None).json()
    chall = next(c for c in authz["challenges"] if c["type"] == "http-01")
    # deliberately do NOT publish the token → the responder returns 404
    resp = acme.post(chall["url"], {})
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "invalid"
    assert body["error"]["type"].startswith("urn:ietf:params:acme:error:")


def test_bad_nonce_is_rejected_with_fresh_nonce(client, http01):
    acme = MiniACME(client)
    acme.directory()
    acme.refresh_nonce()
    acme.new_account()
    acme.nonce = "obviously-not-a-real-nonce"
    resp = acme.new_order(["localhost"])
    assert resp.status_code == 400
    assert resp.json()["type"].endswith(":badNonce")
    assert "Replay-Nonce" in resp.headers  # client can retry


def test_finalize_rejects_mismatched_csr(client, http01):
    acme = MiniACME(client)
    acme.directory()
    acme.refresh_nonce()
    acme.new_account()
    resp = acme.new_order(["localhost"])
    order = resp.json()
    order_url = resp.headers["Location"]
    authz = acme.post(order["authorizations"][0], None).json()
    chall = next(c for c in authz["challenges"] if c["type"] == "http-01")
    http01.publish(chall["token"], f"{chall['token']}.{acme.thumbprint()}")
    acme.post(chall["url"], {})
    order = acme.post(order_url, None).json()
    # CSR asks for a different name than the order authorized
    _, csr = make_csr(["evil.localhost"])
    resp = acme.post(order["finalize"], {"csr": b64(csr.public_bytes(Encoding.DER))})
    assert resp.status_code == 400
    assert resp.json()["type"].endswith(":badCSR")


def test_revoke_via_account_key(client, http01):
    acme = MiniACME(client)
    _, chain = _issue(acme, http01, ["localhost"])
    leaf_der = chain_first_cert_der(chain)
    resp = acme.post(acme.dir["revokeCert"], {"certificate": b64(leaf_der)})
    assert resp.status_code == 200
    certs = client.get("/admin/api/certificates", headers=ADMIN).json()
    assert certs["revoked"] == 1 and certs["valid"] == 0


def test_admin_requires_token(client, http01):
    assert client.get("/admin/api/certificates").status_code == 401
    assert client.get("/admin/api/certificates", headers=ADMIN).status_code == 200

"""Unit tests for the two-tier CA."""

from __future__ import annotations

import datetime as dt

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID

from seccert.ca import CertificateAuthority, generate_private_key


def _ca(tmp_path):
    return CertificateAuthority(
        ca_dir=tmp_path / "ca", org="SecCert", root_cn="SecCert Root", intermediate_cn="SecCert Int"
    ).load_or_create()


def _verify(child, parent):
    parent.public_key().verify(
        child.signature, child.tbs_certificate_bytes, ec.ECDSA(child.signature_hash_algorithm)
    )


def test_hierarchy_is_a_ca(tmp_path):
    ca = _ca(tmp_path)
    for cert, pathlen in ((ca.root_cert, 1), (ca.intermediate_cert, 0)):
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        assert bc.ca and bc.path_length == pathlen
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        assert ku.key_cert_sign and ku.crl_sign
    _verify(ca.intermediate_cert, ca.root_cert)


def test_leaf_issuance(tmp_path):
    ca = _ca(tmp_path)
    leaf_key = generate_private_key("ecdsa-p256")
    not_after = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=90)
    leaf = ca.issue_leaf(leaf_key.public_key(), ["a.internal", "b.internal"], not_after)

    sans = leaf.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value.get_values_for_type(x509.DNSName)
    assert sans == ["a.internal", "b.internal"]

    ku = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
    assert ku.digital_signature and not ku.key_cert_sign
    eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.SERVER_AUTH in eku

    _verify(leaf, ca.intermediate_cert)
    assert leaf.public_key().public_numbers() == leaf_key.public_key().public_numbers()


def test_persistence_reloads_same_root(tmp_path):
    ca1 = _ca(tmp_path)
    ca2 = _ca(tmp_path)
    assert ca1.root_cert.fingerprint(hashes.SHA256()) == ca2.root_cert.fingerprint(hashes.SHA256())
    assert ca1.intermediate_cert.fingerprint(hashes.SHA256()) == ca2.intermediate_cert.fingerprint(
        hashes.SHA256()
    )


def test_crl_lists_revoked_serial(tmp_path):
    ca = _ca(tmp_path)
    leaf_key = generate_private_key("ecdsa-p256")
    leaf = ca.issue_leaf(
        leaf_key.public_key(), ["x.internal"], dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1)
    )
    crl = ca.build_crl([(leaf.serial_number, dt.datetime.now(dt.timezone.utc))])
    assert crl.get_revoked_certificate_by_serial_number(leaf.serial_number) is not None
    _verify_crl_signed_by_intermediate = crl.is_signature_valid(ca.intermediate_cert.public_key())
    assert _verify_crl_signed_by_intermediate

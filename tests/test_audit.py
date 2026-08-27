"""Tests for the audit hash chain, principal attribution, the optional OIDC admin gate, and
the verify/evidence admin endpoints (Spec B: suite audit / CMMC consistency)."""

from __future__ import annotations

import json
import sqlite3

import seccert.auth as auth_mod
from cryptography.hazmat.primitives.serialization import Encoding
from seccert.store import GENESIS, Store

from helpers import MiniACME, b64, make_csr

ADMIN = {"Authorization": "Bearer test-admin-token"}

# The pre-Spec-B audit schema (store.py's _SCHEMA before principal/prev_hash/hash existed),
# reproduced literally so the migration test below exercises the real upgrade path — an
# existing on-disk database that predates the hash chain — rather than just simulating its
# end state in-process.
_PRE_CHAIN_AUDIT_SCHEMA = """
CREATE TABLE audit (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts     TEXT NOT NULL,
    event  TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '{}'
);
"""


def _issue(client, http01, names: list[str]):
    """Run account -> order -> challenge -> finalize far enough to have a certificate, and
    return (acme client, finalized order dict)."""
    acme = MiniACME(client)
    acme.directory()
    acme.refresh_nonce()
    acme.new_account()

    resp = acme.new_order(names)
    order = resp.json()
    order_url = resp.headers["Location"]

    for authz_url in order["authorizations"]:
        authz = acme.post(authz_url, None).json()
        chall = next(c for c in authz["challenges"] if c["type"] == "http-01")
        http01.publish(chall["token"], f"{chall['token']}.{acme.thumbprint()}")
        acme.post(chall["url"], {})

    order = acme.post(order_url, None).json()
    _key, csr = make_csr(names)
    order = acme.post(order["finalize"], {"csr": b64(csr.public_bytes(Encoding.DER))}).json()
    return acme, order


def _account_id(acme: MiniACME) -> str:
    return acme.kid.rsplit("/", 1)[-1]


# ---- Store-level hash chain -------------------------------------------------------------


def test_chain_appends_and_verifies(tmp_path):
    store = Store(tmp_path / "audit.db")
    try:
        store.audit("account.created", principal="acme:acc1", account="acc1")
        store.audit("order.created", principal="acme:acc1", order="ord1")
        store.audit("certificate.revoked_by_admin", principal="token-admin", serial="123")

        result = store.verify_audit_chain()
        assert result == {"ok": True, "checked": 3, "startedAtId": 1}

        log = store.audit_log()
        assert len(log) == 3
        assert all(e["hash"] and e["prevHash"] for e in log)
        # audit_log is most-recent-first; the oldest entry is the last element.
        assert log[-1]["prevHash"] == GENESIS
    finally:
        store.close()


def test_tamper_detection(tmp_path):
    store = Store(tmp_path / "audit.db")
    try:
        store.audit("account.created", principal="acme:acc1", account="acc1")
        store.audit("order.created", principal="acme:acc1", order="ord1")
        store.audit("challenge.valid", principal="acme:acc1", identifier="example.com")

        # Mutate row 2's detail directly — its stored hash no longer matches its (now
        # different) content, so verification must catch the break at that row.
        with store._lock:
            store._db.execute(
                "UPDATE audit SET detail=? WHERE id=2", (json.dumps({"order": "TAMPERED"}),)
            )
            store._db.commit()

        result = store.verify_audit_chain()
        assert result["ok"] is False
        assert result["brokenAtId"] == 2
        assert result["checked"] == 1  # row 1 checked out fine before the break
    finally:
        store.close()


def test_tamper_detection_via_prev_hash_rewrite(tmp_path):
    """A row's own hash can be recomputed to match tampered content, but that then breaks
    the NEXT row's prev_hash linkage — the other half of what makes the chain tamper-evident."""
    store = Store(tmp_path / "audit.db")
    try:
        store.audit("account.created", principal="acme:acc1", account="acc1")
        store.audit("order.created", principal="acme:acc1", order="ord1")

        with store._lock:
            store._db.execute("UPDATE audit SET hash=? WHERE id=1", ("0" * 64,))
            store._db.commit()

        result = store.verify_audit_chain()
        assert result["ok"] is False
        # Row 1's own hash no longer matches its content (checked at row 1), OR — depending
        # on where the mismatch is first observed — row 2's prev_hash no longer matches row
        # 1's (rewritten) hash. Either way the chain must report broken, not ok.
        assert result["brokenAtId"] in (1, 2)
    finally:
        store.close()


def test_migration_from_pre_chain_database(tmp_path):
    """The real upgrade path: an existing database with the old (pre-Spec-B) audit schema,
    already holding rows, opened by the new Store — the ALTER TABLE migration must add the
    three new columns in place without touching existing data, and the store must then be
    fully usable (new chained rows append and verify)."""
    db_path = tmp_path / "legacy.db"
    raw = sqlite3.connect(str(db_path))
    raw.executescript(_PRE_CHAIN_AUDIT_SCHEMA)
    raw.execute(
        "INSERT INTO audit(ts, event, detail) VALUES (?,?,?)",
        ("2019-06-01T00:00:00+00:00", "certificate.issued", '{"serial": "1"}'),
    )
    raw.commit()
    raw.close()

    store = Store(db_path)
    try:
        cols = {r[1] for r in store._db.execute("PRAGMA table_info(audit)").fetchall()}
        assert {"principal", "prev_hash", "hash"} <= cols

        log = store.audit_log()
        assert len(log) == 1
        assert log[0]["event"] == "certificate.issued"
        assert log[0]["principal"] is None and log[0]["hash"] is None

        # Reopening (as would happen on every process restart) must be a no-op migration.
        store.close()
        store = Store(db_path)
        cols_again = {r[1] for r in store._db.execute("PRAGMA table_info(audit)").fetchall()}
        assert cols_again == cols

        store.audit("account.created", principal="acme:acc1", account="acc1")
        result = store.verify_audit_chain()
        assert result == {"ok": True, "checked": 1, "startedAtId": 2}
    finally:
        store.close()


def test_grandfathered_rows_are_excluded_not_broken(tmp_path):
    store = Store(tmp_path / "audit.db")
    try:
        # Simulate two pre-migration rows: written before principal/prev_hash/hash existed,
        # exactly as Store._migrate_audit_columns would find them on an existing database.
        with store._lock:
            store._db.execute(
                "INSERT INTO audit(ts, event, detail) VALUES (?,?,?)",
                ("2020-01-01T00:00:00+00:00", "certificate.issued", "{}"),
            )
            store._db.execute(
                "INSERT INTO audit(ts, event, detail) VALUES (?,?,?)",
                ("2020-01-02T00:00:00+00:00", "certificate.revoked", "{}"),
            )
            store._db.commit()

        # Only grandfathered rows exist so far — trivially ok, nothing to verify yet.
        assert store.verify_audit_chain() == {"ok": True, "checked": 0, "startedAtId": None}

        # The first NEW row starts its own chain from GENESIS, oblivious to the grandfathered
        # rows before it.
        store.audit("account.created", principal="acme:acc1", account="acc1")
        store.audit("order.created", principal="acme:acc1", order="ord1")

        result = store.verify_audit_chain()
        assert result["ok"] is True
        assert result["checked"] == 2
        assert result["startedAtId"] == 3  # ids 1-2 are the grandfathered rows

        log = store.audit_log()
        old_rows = [e for e in log if e["event"] in ("certificate.issued", "certificate.revoked")]
        assert len(old_rows) == 2
        assert all(e["principal"] is None and e["hash"] is None and e["prevHash"] is None for e in old_rows)
    finally:
        store.close()


# ---- End-to-end attribution (ACME + admin, over the real FastAPI app) -------------------


def test_acme_events_carry_acme_account_principal(client, http01):
    acme, order = _issue(client, http01, ["localhost"])
    assert "certificate" in order

    ctx = client.app.state.ctx
    expected = f"acme:{_account_id(acme)}"
    by_event = {}
    for e in ctx.store.audit_log():
        by_event.setdefault(e["event"], e)

    for ev in ("account.created", "order.created", "challenge.valid", "certificate.issued"):
        assert ev in by_event, f"missing audit event {ev!r}"
        assert by_event[ev]["principal"] == expected


def test_admin_revoke_carries_token_admin_principal(client, http01):
    _acme, order = _issue(client, http01, ["localhost"])
    ctx = client.app.state.ctx
    cert_id = order["certificate"].rsplit("/", 1)[-1]
    serial = ctx.store.get_certificate(cert_id)["serial"]

    r = client.post(f"/admin/api/certificates/{serial}/revoke", headers=ADMIN, json={"reason": 1})
    assert r.status_code == 200, r.text

    events = [e for e in ctx.store.audit_log() if e["event"] == "certificate.revoked_by_admin"]
    assert events and events[0]["principal"] == "token-admin"


def test_admin_revoke_carries_oidc_sub_when_sso_configured(client, http01, monkeypatch):
    _acme, order = _issue(client, http01, ["localhost"])
    ctx = client.app.state.ctx
    cert_id = order["certificate"].rsplit("/", 1)[-1]
    serial = ctx.store.get_certificate(cert_id)["serial"]

    fake = auth_mod.Principal(sub="alice@example.com", groups=[auth_mod.ADMIN_GROUP])
    monkeypatch.setattr(auth_mod, "auth_enabled", True)
    monkeypatch.setattr(auth_mod, "current_principal", lambda request: fake)

    # No Authorization header at all — the (faked) SSO session alone must satisfy require_admin.
    r = client.post(f"/admin/api/certificates/{serial}/revoke", json={"reason": 1})
    assert r.status_code == 200, r.text

    events = [e for e in ctx.store.audit_log() if e["event"] == "certificate.revoked_by_admin"]
    assert events and events[0]["principal"] == "alice@example.com"


def test_oidc_login_without_admin_group_falls_back_to_token(client, http01, monkeypatch):
    """A signed-in-but-not-admin principal must NOT satisfy require_admin; the static token
    must still work as break-glass."""
    _acme, order = _issue(client, http01, ["localhost"])
    ctx = client.app.state.ctx
    cert_id = order["certificate"].rsplit("/", 1)[-1]
    serial = ctx.store.get_certificate(cert_id)["serial"]

    not_admin = auth_mod.Principal(sub="bob@example.com", groups=["some-other-group"])
    monkeypatch.setattr(auth_mod, "auth_enabled", True)
    monkeypatch.setattr(auth_mod, "current_principal", lambda request: not_admin)

    denied = client.post(f"/admin/api/certificates/{serial}/revoke", json={"reason": 1})
    assert denied.status_code == 401

    allowed = client.post(f"/admin/api/certificates/{serial}/revoke", headers=ADMIN, json={"reason": 1})
    assert allowed.status_code == 200
    events = [e for e in ctx.store.audit_log() if e["event"] == "certificate.revoked_by_admin"]
    assert events and events[0]["principal"] == "token-admin"


# ---- verify / evidence endpoints ---------------------------------------------------------


def test_verify_and_evidence_endpoints_require_admin(client):
    assert client.get("/admin/api/audit/verify").status_code == 401
    assert client.get("/admin/api/evidence").status_code == 401
    assert client.get("/admin/api/audit/verify", headers=ADMIN).status_code == 200
    assert client.get("/admin/api/evidence", headers=ADMIN).status_code == 200


def test_verify_endpoint_reports_chain_state(client, http01):
    _issue(client, http01, ["localhost"])
    r = client.get("/admin/api/audit/verify", headers=ADMIN)
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["checked"] > 0
    assert body["startedAtId"] == 1
    assert "ts" in body


def test_evidence_bundle_is_sanitized_and_shaped(client, http01):
    _issue(client, http01, ["localhost"])
    r = client.get("/admin/api/evidence", headers=ADMIN)
    assert r.status_code == 200
    body = r.json()

    assert body["product"] == "seccert"
    assert body["generatedBy"] == "token-admin"
    for key in ("config", "auditChain", "auditRecent", "controls"):
        assert key in body

    # Never the admin token, the CA passphrase, or any key material — anywhere in the bundle.
    text = json.dumps(body)
    assert "test-admin-token" not in text
    assert "-----BEGIN" not in text  # no PEM key/cert material

    cfg = body["config"]
    assert "admin_token" not in cfg
    assert "ca_passphrase" not in cfg
    assert cfg["ca_passphrase_set"] is False
    assert cfg["admin_token_generated"] is False

    chain = body["auditChain"]
    assert chain["ok"] is True
    assert isinstance(body["auditRecent"], list) and body["auditRecent"]

    assert "AU-3.3.8 (audit tamper-evidence)" in body["controls"]
    assert "SC-3.13.10 (cryptographic key protection)" in body["controls"]
    assert "IA-3.5.1/3.5.2 (identification & authentication of the admin plane)" in body["controls"]

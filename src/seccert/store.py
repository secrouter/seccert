"""SQLite persistence for SecCert — accounts, orders, authorizations, challenges,
nonces, issued certificates, and an append-only audit ledger.

The store returns plain dicts; the ACME router is responsible for turning them into
RFC 8555 JSON with absolute URLs. All timestamps are ISO-8601 UTC strings.
"""

from __future__ import annotations

import datetime as _dt
import json
import secrets
import sqlite3
import threading
from pathlib import Path
from typing import Any

_SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    id          TEXT PRIMARY KEY,
    thumbprint  TEXT UNIQUE NOT NULL,
    jwk         TEXT NOT NULL,
    contact     TEXT NOT NULL DEFAULT '[]',
    status      TEXT NOT NULL DEFAULT 'valid',
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS nonces (
    nonce       TEXT PRIMARY KEY,
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS orders (
    id          TEXT PRIMARY KEY,
    account_id  TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'pending',
    identifiers TEXT NOT NULL,
    not_before  TEXT,
    not_after   TEXT,
    expires     TEXT NOT NULL,
    error       TEXT,
    cert_id     TEXT,
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS authorizations (
    id          TEXT PRIMARY KEY,
    order_id    TEXT NOT NULL,
    account_id  TEXT NOT NULL,
    identifier  TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'pending',
    expires     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS challenges (
    id           TEXT PRIMARY KEY,
    authz_id     TEXT NOT NULL,
    type         TEXT NOT NULL,
    token        TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending',
    validated_at TEXT,
    error        TEXT
);
CREATE TABLE IF NOT EXISTS certificates (
    id                TEXT PRIMARY KEY,
    serial            TEXT UNIQUE NOT NULL,
    account_id        TEXT NOT NULL,
    order_id          TEXT NOT NULL,
    sans              TEXT NOT NULL,
    leaf_pem          BLOB NOT NULL,
    chain_pem         BLOB NOT NULL,
    not_after         TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'valid',
    issued_at         TEXT NOT NULL,
    revoked_at        TEXT,
    revocation_reason INTEGER
);
CREATE TABLE IF NOT EXISTS audit (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts     TEXT NOT NULL,
    event  TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '{}'
);
"""


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def _id(n: int = 16) -> str:
    return secrets.token_urlsafe(n)


class Store:
    def __init__(self, path: Path | str) -> None:
        self._path = str(path)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(self._path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA foreign_keys=ON")
        with self._lock:
            self._db.executescript(_SCHEMA)
            self._db.commit()

    def close(self) -> None:
        self._db.close()

    # ---- audit -------------------------------------------------------------

    def audit(self, event: str, **detail: Any) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO audit(ts, event, detail) VALUES (?,?,?)",
                (_now(), event, json.dumps(detail, sort_keys=True)),
            )
            self._db.commit()

    def audit_log(self, limit: int = 200) -> list[dict[str, Any]]:
        rows = self._db.execute(
            "SELECT ts, event, detail FROM audit ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [{"ts": r["ts"], "event": r["event"], "detail": json.loads(r["detail"])} for r in rows]

    # ---- nonces ------------------------------------------------------------

    def new_nonce(self) -> str:
        nonce = _id(16)
        with self._lock:
            self._db.execute("INSERT INTO nonces(nonce, created_at) VALUES (?,?)", (nonce, _now()))
            self._db.commit()
        return nonce

    def consume_nonce(self, nonce: str) -> bool:
        if not nonce:
            return False
        with self._lock:
            cur = self._db.execute("DELETE FROM nonces WHERE nonce=?", (nonce,))
            self._db.commit()
            return cur.rowcount > 0

    # ---- accounts ----------------------------------------------------------

    def create_account(self, thumbprint: str, jwk: dict[str, Any], contact: list[str]) -> dict[str, Any]:
        acc_id = _id()
        with self._lock:
            self._db.execute(
                "INSERT INTO accounts(id, thumbprint, jwk, contact, status, created_at) "
                "VALUES (?,?,?,?, 'valid', ?)",
                (acc_id, thumbprint, json.dumps(jwk, sort_keys=True), json.dumps(contact), _now()),
            )
            self._db.commit()
        return self.get_account(acc_id)  # type: ignore[return-value]

    def get_account(self, acc_id: str) -> dict[str, Any] | None:
        row = self._db.execute("SELECT * FROM accounts WHERE id=?", (acc_id,)).fetchone()
        return self._account_row(row) if row else None

    def get_account_by_thumbprint(self, thumbprint: str) -> dict[str, Any] | None:
        row = self._db.execute("SELECT * FROM accounts WHERE thumbprint=?", (thumbprint,)).fetchone()
        return self._account_row(row) if row else None

    @staticmethod
    def _account_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "thumbprint": row["thumbprint"],
            "jwk": json.loads(row["jwk"]),
            "contact": json.loads(row["contact"]),
            "status": row["status"],
            "created_at": row["created_at"],
        }

    # ---- orders / authorizations / challenges ------------------------------

    def create_order(
        self,
        account_id: str,
        identifiers: list[str],
        not_before: str | None,
        not_after: str | None,
        expires: str,
    ) -> dict[str, Any]:
        order_id = _id()
        with self._lock:
            self._db.execute(
                "INSERT INTO orders(id, account_id, status, identifiers, not_before, not_after, "
                "expires, created_at) VALUES (?,?, 'pending', ?,?,?,?,?)",
                (order_id, account_id, json.dumps(identifiers), not_before, not_after, expires, _now()),
            )
            for ident in identifiers:
                authz_id = _id()
                chall_id = _id()
                token = _id(32)
                self._db.execute(
                    "INSERT INTO authorizations(id, order_id, account_id, identifier, status, expires) "
                    "VALUES (?,?,?,?, 'pending', ?)",
                    (authz_id, order_id, account_id, ident, expires),
                )
                self._db.execute(
                    "INSERT INTO challenges(id, authz_id, type, token, status) "
                    "VALUES (?,?, 'http-01', ?, 'pending')",
                    (chall_id, authz_id, token),
                )
            self._db.commit()
        return self.get_order(order_id)  # type: ignore[return-value]

    def list_order_ids(self, account_id: str) -> list[str]:
        rows = self._db.execute(
            "SELECT id FROM orders WHERE account_id=? ORDER BY created_at DESC", (account_id,)
        ).fetchall()
        return [r["id"] for r in rows]

    def get_order(self, order_id: str) -> dict[str, Any] | None:
        row = self._db.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
        if not row:
            return None
        return {
            "id": row["id"],
            "account_id": row["account_id"],
            "status": row["status"],
            "identifiers": json.loads(row["identifiers"]),
            "not_before": row["not_before"],
            "not_after": row["not_after"],
            "expires": row["expires"],
            "error": json.loads(row["error"]) if row["error"] else None,
            "cert_id": row["cert_id"],
        }

    def order_authorizations(self, order_id: str) -> list[dict[str, Any]]:
        rows = self._db.execute(
            "SELECT id FROM authorizations WHERE order_id=?", (order_id,)
        ).fetchall()
        return [self.get_authorization(r["id"]) for r in rows]  # type: ignore[misc]

    def get_authorization(self, authz_id: str) -> dict[str, Any] | None:
        row = self._db.execute("SELECT * FROM authorizations WHERE id=?", (authz_id,)).fetchone()
        if not row:
            return None
        challs = self._db.execute(
            "SELECT * FROM challenges WHERE authz_id=?", (authz_id,)
        ).fetchall()
        return {
            "id": row["id"],
            "order_id": row["order_id"],
            "account_id": row["account_id"],
            "identifier": row["identifier"],
            "status": row["status"],
            "expires": row["expires"],
            "challenges": [self._chall_row(c) for c in challs],
        }

    def get_challenge(self, chall_id: str) -> dict[str, Any] | None:
        row = self._db.execute("SELECT * FROM challenges WHERE id=?", (chall_id,)).fetchone()
        return self._chall_row(row) if row else None

    @staticmethod
    def _chall_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "authz_id": row["authz_id"],
            "type": row["type"],
            "token": row["token"],
            "status": row["status"],
            "validated_at": row["validated_at"],
            "error": json.loads(row["error"]) if row["error"] else None,
        }

    def set_challenge_result(
        self, chall_id: str, status: str, error: dict[str, Any] | None = None
    ) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE challenges SET status=?, validated_at=?, error=? WHERE id=?",
                (status, _now() if status == "valid" else None, json.dumps(error) if error else None, chall_id),
            )
            self._db.commit()

    def set_authorization_status(self, authz_id: str, status: str) -> None:
        with self._lock:
            self._db.execute("UPDATE authorizations SET status=? WHERE id=?", (status, authz_id))
            self._db.commit()

    def set_order_status(self, order_id: str, status: str, error: dict[str, Any] | None = None) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE orders SET status=?, error=? WHERE id=?",
                (status, json.dumps(error) if error else None, order_id),
            )
            self._db.commit()

    def refresh_order_status(self, order_id: str) -> dict[str, Any] | None:
        """Recompute order status from its authorizations (pending -> ready)."""
        order = self.get_order(order_id)
        if not order or order["status"] not in ("pending", "ready"):
            return order
        authzs = self.order_authorizations(order_id)
        if any(a["status"] == "invalid" for a in authzs):
            self.set_order_status(order_id, "invalid")
        elif all(a["status"] == "valid" for a in authzs):
            if order["status"] == "pending":
                self.set_order_status(order_id, "ready")
        return self.get_order(order_id)

    # ---- certificates ------------------------------------------------------

    def store_certificate(
        self,
        account_id: str,
        order_id: str,
        serial: str,
        sans: list[str],
        leaf_pem: bytes,
        chain_pem: bytes,
        not_after: str,
    ) -> str:
        cert_id = _id()
        with self._lock:
            self._db.execute(
                "INSERT INTO certificates(id, serial, account_id, order_id, sans, leaf_pem, "
                "chain_pem, not_after, status, issued_at) VALUES (?,?,?,?,?,?,?,?, 'valid', ?)",
                (cert_id, serial, account_id, order_id, json.dumps(sans), leaf_pem, chain_pem, not_after, _now()),
            )
            self._db.execute("UPDATE orders SET cert_id=?, status='valid' WHERE id=?", (cert_id, order_id))
            self._db.commit()
        return cert_id

    def get_certificate(self, cert_id: str) -> dict[str, Any] | None:
        row = self._db.execute("SELECT * FROM certificates WHERE id=?", (cert_id,)).fetchone()
        return self._cert_row(row) if row else None

    def get_certificate_by_serial(self, serial: str) -> dict[str, Any] | None:
        row = self._db.execute("SELECT * FROM certificates WHERE serial=?", (serial,)).fetchone()
        return self._cert_row(row) if row else None

    def list_certificates(self) -> list[dict[str, Any]]:
        rows = self._db.execute(
            "SELECT * FROM certificates ORDER BY issued_at DESC"
        ).fetchall()
        return [self._cert_row(r, with_pem=False) for r in rows]

    def revoke_certificate(self, serial: str, reason: int | None) -> bool:
        with self._lock:
            cur = self._db.execute(
                "UPDATE certificates SET status='revoked', revoked_at=?, revocation_reason=? "
                "WHERE serial=? AND status='valid'",
                (_now(), reason, serial),
            )
            self._db.commit()
            return cur.rowcount > 0

    def revoked_serials(self) -> list[tuple[int, _dt.datetime]]:
        rows = self._db.execute(
            "SELECT serial, revoked_at FROM certificates WHERE status='revoked'"
        ).fetchall()
        out: list[tuple[int, _dt.datetime]] = []
        for r in rows:
            out.append((int(r["serial"]), _dt.datetime.fromisoformat(r["revoked_at"])))
        return out

    @staticmethod
    def _cert_row(row: sqlite3.Row, with_pem: bool = True) -> dict[str, Any]:
        d = {
            "id": row["id"],
            "serial": row["serial"],
            "account_id": row["account_id"],
            "order_id": row["order_id"],
            "sans": json.loads(row["sans"]),
            "not_after": row["not_after"],
            "status": row["status"],
            "issued_at": row["issued_at"],
            "revoked_at": row["revoked_at"],
            "revocation_reason": row["revocation_reason"],
        }
        if with_pem:
            d["leaf_pem"] = bytes(row["leaf_pem"])
            d["chain_pem"] = bytes(row["chain_pem"])
        return d

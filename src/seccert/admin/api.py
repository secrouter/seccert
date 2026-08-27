"""Public trust-anchor endpoints and the token-gated (or SecSSO-gated) admin API + console."""

from __future__ import annotations

import datetime as _dt
import secrets
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from .. import auth
from ..context import Context
from .ui import CONSOLE_HTML

SECCERT_VERSION = "1.0.0"


def _fingerprint(cert) -> str:
    raw = cert.fingerprint(hashes.SHA256()).hex().upper()
    return ":".join(raw[i : i + 2] for i in range(0, len(raw), 2))


def _cert_summary(cert) -> dict[str, Any]:
    return {
        "subject": cert.subject.rfc4514_string(),
        "fingerprint_sha256": _fingerprint(cert),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "serial": str(cert.serial_number),
    }


def _sanitized_config(ctx: Context) -> dict[str, Any]:
    """Config for the evidence bundle — CA subject, validity windows, ACME/network settings.
    NEVER the CA passphrase, the admin token, or TLS key material (Spec B.6)."""
    c = ctx.config
    return {
        "org": c.org,
        "root_cn": c.root_cn,
        "intermediate_cn": c.intermediate_cn,
        "ca_key_type": c.ca_key_type,
        "root_days": c.root_days,
        "intermediate_days": c.intermediate_days,
        "leaf_days": c.leaf_days,
        "external_url": c.external_url,
        "http01_port": c.http01_port,
        "http01_timeout": c.http01_timeout,
        "tls_mode": c.tls_mode,
        "require_eab": c.require_eab,
        "terms_of_service": c.terms_of_service,
        "ca_passphrase_set": bool(c.ca_passphrase),  # posture only, never the value
        "admin_token_generated": c.admin_token_generated,  # posture only, never the token
    }


def _control_self_assessment(ctx: Context, chain: dict[str, Any]) -> dict[str, Any]:
    """Live control self-assessment (not a certification claim — see docs/security.md)."""
    ca_dir_mode = None
    try:
        ca_dir_mode = oct(ctx.config.ca_dir.stat().st_mode & 0o777)
    except OSError:  # pragma: no cover - platform/permissions edge case
        pass
    return {
        "SC-3.13.10 (cryptographic key protection)": {
            "evidence": "CA private keys at rest, permissions on config.ca_dir",
            "ca_dir": str(ctx.config.ca_dir),
            "ca_dir_mode": ca_dir_mode,
            "expected_mode": "0700",
            "passphrase_set": bool(ctx.config.ca_passphrase),
            "status": "0700 dir + optional passphrase encryption" if ca_dir_mode == "0o700" else "UNEXPECTED MODE",
        },
        "AU-3.3.1/3.3.2 (audit creation & traceability)": {
            "evidence": "audit table — every ACME/admin event carries a principal",
            "status": "active",
        },
        "AU-3.3.8 (audit tamper-evidence)": {
            "evidence": "auditChain — SHA-256 hash-chain verification (GET /admin/api/audit/verify)",
            "verified": chain["ok"],
            "eventsChecked": chain["checked"],
            "startedAtId": chain.get("startedAtId"),
            "status": "intact" if chain["ok"] else f"BROKEN at id {chain.get('brokenAtId')}",
        },
        "IA-3.5.1/3.5.2 (identification & authentication of the admin plane)": {
            "evidence": "auth.status() — which admin identity mode is in effect",
            "mode": "SecSSO OIDC (+ token break-glass)" if auth.auth_enabled else "static bearer token only",
            "admin_group": auth.ADMIN_GROUP if auth.auth_enabled else None,
            "status": "OIDC enforced" if auth.auth_enabled else "TOKEN ONLY (no SSO configured)",
        },
        "SC-3.13.8 (encryption in transit)": {
            "evidence": "config.tls_mode",
            "status": "native TLS" if ctx.config.tls_mode == "native" else "front-end termination",
        },
        "CM-3.4.6 (least functionality)": {
            "evidence": "single-purpose ACME CA; admin API gated; docs+openapi disabled",
            "status": "enforced",
        },
    }


def build_router(ctx: Context) -> APIRouter:
    router = APIRouter()

    def require_admin(request: Request) -> str:
        """Verify the caller may administer SecCert and return the *acting principal* for
        audit attribution.

        SecSSO admin login (resolved by the auth middleware, when SSO is configured) is the
        primary path: a valid principal that is a member of the admin group (see auth.py) —
        its OIDC `sub` becomes the principal. Otherwise, the static admin token is checked —
        always accepted as bootstrap / break-glass, and the ONLY credential when SSO is off —
        attributed as the literal `"token-admin"` (Spec B: no per-operator identity exists on
        that path, since the token is shared).
        """
        if auth.auth_enabled:
            principal = auth.current_principal(request)
            if principal is not None and auth.is_admin(principal):
                return principal.sub
        header = request.headers.get("authorization", "")
        token = header[7:].strip() if header[:7].lower() == "bearer " else ""
        if token and secrets.compare_digest(token, ctx.config.admin_token):
            return "token-admin"
        raise HTTPException(status_code=401, detail="SecSSO admin login or admin token required")

    # ---- landing + console ------------------------------------------------

    @router.get("/", include_in_schema=False)
    async def index() -> RedirectResponse:
        return RedirectResponse(url="/admin")

    @router.get("/admin", response_class=HTMLResponse, include_in_schema=False)
    async def console() -> HTMLResponse:
        return HTMLResponse(CONSOLE_HTML)

    # ---- public trust anchor + health -------------------------------------

    @router.get("/health")
    async def health() -> JSONResponse:
        return JSONResponse(
            {
                "status": "ok",
                "service": "seccert",
                "version": SECCERT_VERSION,
                "ca": {
                    "root": _cert_summary(ctx.ca.root_cert),
                    "intermediate": _cert_summary(ctx.ca.intermediate_cert),
                },
                "auth": auth.status(),  # admin-plane SSO posture (off by default)
            }
        )

    @router.get("/ca.crt")
    async def ca_crt() -> Response:
        return Response(
            ctx.ca.root_pem(),
            media_type="application/x-pem-file",
            headers={"Content-Disposition": 'attachment; filename="seccert-root.pem"'},
        )

    @router.get("/roots")
    async def roots() -> Response:
        return Response(ctx.ca.root_pem(), media_type="application/pem-certificate-chain")

    @router.get("/intermediate.crt")
    async def intermediate_crt() -> Response:
        return Response(ctx.ca.intermediate_pem(), media_type="application/x-pem-file")

    @router.get("/crl")
    async def crl() -> Response:
        crl_obj = ctx.ca.build_crl(ctx.store.revoked_serials())
        return Response(crl_obj.public_bytes(Encoding.DER), media_type="application/pkix-crl")

    # ---- admin API (token-gated) ------------------------------------------

    @router.get("/admin/api/ca")
    async def admin_ca(request: Request) -> JSONResponse:
        require_admin(request)
        return JSONResponse(
            {
                "org": ctx.config.org,
                "key_type": ctx.config.ca_key_type,
                "leaf_days": ctx.config.leaf_days,
                "root": _cert_summary(ctx.ca.root_cert),
                "intermediate": _cert_summary(ctx.ca.intermediate_cert),
            }
        )

    @router.get("/admin/api/certificates")
    async def admin_certificates(request: Request) -> JSONResponse:
        require_admin(request)
        certs = ctx.store.list_certificates()
        return JSONResponse(
            {
                "count": len(certs),
                "valid": sum(1 for c in certs if c["status"] == "valid"),
                "revoked": sum(1 for c in certs if c["status"] == "revoked"),
                "certificates": certs,
            }
        )

    @router.post("/admin/api/certificates/{serial}/revoke")
    async def admin_revoke(request: Request, serial: str) -> JSONResponse:
        principal = require_admin(request)
        cert = ctx.store.get_certificate_by_serial(serial)
        if not cert:
            raise HTTPException(status_code=404, detail="unknown certificate")
        if cert["status"] == "revoked":
            return JSONResponse({"serial": serial, "status": "revoked", "already": True})
        reason: int | None = None
        try:
            body = await request.json()
            if isinstance(body, dict) and isinstance(body.get("reason"), int):
                reason = body["reason"]
        except Exception:  # noqa: BLE001 - optional body
            pass
        ctx.store.revoke_certificate(serial, reason)
        ctx.store.audit("certificate.revoked_by_admin", principal=principal, serial=serial, reason=reason)
        return JSONResponse({"serial": serial, "status": "revoked"})

    @router.get("/admin/api/audit")
    async def admin_audit(request: Request) -> JSONResponse:
        require_admin(request)
        return JSONResponse({"events": ctx.store.audit_log(200)})

    @router.get("/admin/api/audit/verify")
    async def admin_audit_verify(request: Request) -> JSONResponse:
        """AU-3.3.8 — verify the audit hash chain. See Store.verify_audit_chain for the
        grandfathering rule: rows written before the Spec B migration have no hash at all and
        are excluded, rather than reported as tampered; `startedAtId` names the first row that
        IS hash-chained."""
        require_admin(request)
        result = ctx.store.verify_audit_chain()
        return JSONResponse({**result, "ts": _dt.datetime.now(_dt.timezone.utc).isoformat()})

    @router.get("/admin/api/evidence")
    async def admin_evidence(request: Request) -> Response:
        """One-shot CMMC/NIST SP 800-171 evidence bundle (Spec B.6) — sanitized config,
        audit-chain verification, recent audit events, and a live control self-assessment.
        NEVER includes CA keys, the CA passphrase, or the admin token/session material."""
        principal = require_admin(request)
        chain = ctx.store.verify_audit_chain()
        now = _dt.datetime.now(_dt.timezone.utc)
        bundle = {
            "product": "seccert",
            "version": SECCERT_VERSION,
            "generatedAt": now.isoformat(),
            "generatedBy": principal,
            "config": _sanitized_config(ctx),
            "auditChain": {**chain, "ts": now.isoformat()},
            "auditRecent": ctx.store.audit_log(200),
            "controls": _control_self_assessment(ctx, chain),
        }
        today = now.date().isoformat()
        return JSONResponse(
            bundle,
            headers={"Content-Disposition": f'attachment; filename="seccert-evidence-{today}.json"'},
        )

    return router

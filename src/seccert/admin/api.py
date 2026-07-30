"""Public trust-anchor endpoints and the token-gated admin API + console."""

from __future__ import annotations

import secrets
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from ..context import Context
from .ui import CONSOLE_HTML


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


def build_router(ctx: Context) -> APIRouter:
    router = APIRouter()

    def require_admin(request: Request) -> None:
        header = request.headers.get("authorization", "")
        token = header[7:].strip() if header[:7].lower() == "bearer " else ""
        if not token or not secrets.compare_digest(token, ctx.config.admin_token):
            raise HTTPException(status_code=401, detail="admin token required")

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
                "version": "1.0.0",
                "ca": {
                    "root": _cert_summary(ctx.ca.root_cert),
                    "intermediate": _cert_summary(ctx.ca.intermediate_cert),
                },
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
        require_admin(request)
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
        ctx.store.audit("certificate.revoked_by_admin", serial=serial, reason=reason)
        return JSONResponse({"serial": serial, "status": "revoked"})

    @router.get("/admin/api/audit")
    async def admin_audit(request: Request) -> JSONResponse:
        require_admin(request)
        return JSONResponse({"events": ctx.store.audit_log(200)})

    return router

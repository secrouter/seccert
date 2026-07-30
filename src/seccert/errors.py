"""ACME error responses — RFC 8555 §6.7 (``application/problem+json``)."""

from __future__ import annotations

from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse

ACME_ERROR_NS = "urn:ietf:params:acme:error:"

# Canonical ACME error type -> default HTTP status code.
_STATUS: dict[str, int] = {
    "malformed": 400,
    "badNonce": 400,
    "badSignatureAlgorithm": 400,
    "badPublicKey": 400,
    "badCSR": 400,
    "badRevocationReason": 400,
    "unauthorized": 401,
    "accountDoesNotExist": 400,
    "alreadyRevoked": 400,
    "unsupportedIdentifier": 400,
    "rejectedIdentifier": 400,
    "orderNotReady": 403,
    "connection": 400,
    "dns": 400,
    "incorrectResponse": 400,
    "serverInternal": 500,
    "userActionRequired": 401,
    "externalAccountRequired": 401,
    "unsupportedContact": 400,
}


class AcmeError(Exception):
    """An ACME problem document. Raise anywhere in request handling."""

    def __init__(
        self,
        kind: str,
        detail: str = "",
        *,
        status: int | None = None,
        subproblems: list[dict[str, Any]] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.kind = kind
        self.detail = detail
        self.status = status or _STATUS.get(kind, 400)
        self.subproblems = subproblems or []
        self.headers = headers or {}
        super().__init__(f"{kind}: {detail}")

    def to_dict(self) -> dict[str, Any]:
        body: dict[str, Any] = {"type": ACME_ERROR_NS + self.kind}
        if self.detail:
            body["detail"] = self.detail
        if self.subproblems:
            body["subproblems"] = self.subproblems
        return body

    def to_response(self) -> JSONResponse:
        return JSONResponse(
            self.to_dict(),
            status_code=self.status,
            media_type="application/problem+json",
            headers=self.headers,
        )


def install_error_handler(app: Any) -> None:
    @app.exception_handler(AcmeError)
    async def _handle(_request: Request, exc: AcmeError) -> JSONResponse:  # pragma: no cover - wiring
        return exc.to_response()

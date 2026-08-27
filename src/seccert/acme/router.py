"""ACME (RFC 8555) endpoints for SecCert.

Implements the account -> order -> authorization -> challenge -> finalize -> certificate
flow with HTTP-01 validation, plus revocation. HTTP-01 is validated synchronously inside
the challenge request (simplest correct behaviour for a small CA); clients still poll and
observe the resulting ``valid``/``invalid`` state as usual.
"""

from __future__ import annotations

import datetime as _dt
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import ExtensionOID
from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from ..context import Context
from ..errors import ACME_ERROR_NS, AcmeError
from ..validation import key_authorization, validate_http01
from .jws import ParsedJWS, b64url_decode, jwk_thumbprint, jwk_to_public_key, parse_jws, verify_signature


def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def _iso(dt: _dt.datetime) -> str:
    return dt.isoformat()


def build_router(ctx: Context) -> APIRouter:
    router = APIRouter()

    # ---- JWS request helpers ----------------------------------------------

    async def read_jws(request: Request) -> ParsedJWS:
        ctype = request.headers.get("content-type", "").split(";")[0].strip()
        if ctype != "application/jose+json":
            raise AcmeError("malformed", "Content-Type must be application/jose+json")
        try:
            body = await request.json()
        except Exception as exc:  # noqa: BLE001
            raise AcmeError("malformed", "request body is not valid JSON") from exc
        parsed = parse_jws(body)

        expected_url = ctx.config.external_url + request.url.path
        if parsed.url != expected_url:
            raise AcmeError("unauthorized", f"JWS 'url' {parsed.url!r} != {expected_url!r}")

        if not ctx.store.consume_nonce(parsed.nonce):
            raise AcmeError(
                "badNonce",
                "bad or already-used anti-replay nonce",
                headers={"Replay-Nonce": ctx.store.new_nonce()},
            )
        return parsed

    def resolve_account(parsed: ParsedJWS) -> dict[str, Any]:
        if not parsed.kid:
            raise AcmeError("malformed", "protected header must contain 'kid'")
        acc_id = parsed.kid.rsplit("/", 1)[-1]
        acc = ctx.store.get_account(acc_id)
        if not acc or acc["status"] != "valid":
            raise AcmeError("accountDoesNotExist", "unknown or deactivated account")
        return acc

    async def authed(request: Request) -> tuple[ParsedJWS, dict[str, Any]]:
        """Verify a kid-signed request and return (jws, account)."""
        parsed = await read_jws(request)
        acc = resolve_account(parsed)
        verify_signature(acc["jwk"], parsed.alg, parsed.signing_input, parsed.signature)
        return parsed, acc

    # ---- ACME object serializers ------------------------------------------

    def account_json(acc: dict[str, Any]) -> dict[str, Any]:
        return {
            "status": acc["status"],
            "contact": acc["contact"],
            "orders": ctx.url(f"/acme/account/{acc['id']}/orders"),
        }

    def challenge_json(chall: dict[str, Any]) -> dict[str, Any]:
        obj = {
            "type": chall["type"],
            "url": ctx.challenge_url(chall["id"]),
            "status": chall["status"],
            "token": chall["token"],
        }
        if chall.get("validated_at"):
            obj["validated"] = chall["validated_at"]
        if chall.get("error"):
            obj["error"] = chall["error"]
        return obj

    def authz_json(authz: dict[str, Any]) -> dict[str, Any]:
        return {
            "identifier": {"type": "dns", "value": authz["identifier"]},
            "status": authz["status"],
            "expires": authz["expires"],
            "challenges": [challenge_json(c) for c in authz["challenges"]],
        }

    def order_json(order: dict[str, Any]) -> dict[str, Any]:
        authzs = ctx.store.order_authorizations(order["id"])
        obj: dict[str, Any] = {
            "status": order["status"],
            "expires": order["expires"],
            "identifiers": [{"type": "dns", "value": v} for v in order["identifiers"]],
            "authorizations": [ctx.authz_url(a["id"]) for a in authzs],
            "finalize": ctx.finalize_url(order["id"]),
        }
        if order.get("not_before"):
            obj["notBefore"] = order["not_before"]
        if order.get("not_after"):
            obj["notAfter"] = order["not_after"]
        if order.get("error"):
            obj["error"] = order["error"]
        if order["status"] == "valid" and order.get("cert_id"):
            obj["certificate"] = ctx.certificate_url(order["cert_id"])
        return obj

    def own_or_403(resource_account_id: str, acc: dict[str, Any]) -> None:
        if resource_account_id != acc["id"]:
            raise AcmeError("unauthorized", "account does not own this resource")

    # ---- directory & nonce ------------------------------------------------

    @router.get("/acme/directory")
    async def directory() -> JSONResponse:
        meta: dict[str, Any] = {}
        if ctx.config.terms_of_service:
            meta["termsOfService"] = ctx.config.terms_of_service
        if ctx.config.require_eab:
            meta["externalAccountRequired"] = True
        return JSONResponse(
            {
                "newNonce": ctx.url("/acme/new-nonce"),
                "newAccount": ctx.url("/acme/new-account"),
                "newOrder": ctx.url("/acme/new-order"),
                "revokeCert": ctx.url("/acme/revoke-cert"),
                "meta": meta,
            }
        )

    @router.api_route("/acme/new-nonce", methods=["GET", "HEAD"])
    async def new_nonce(request: Request) -> Response:
        # The Replay-Nonce header is attached by middleware for every /acme response.
        status = 200 if request.method == "HEAD" else 204
        return Response(status_code=status, headers={"Cache-Control": "no-store"})

    # ---- accounts ---------------------------------------------------------

    @router.post("/acme/new-account")
    async def new_account(request: Request) -> JSONResponse:
        parsed = await read_jws(request)
        if not parsed.jwk:
            raise AcmeError("malformed", "new-account must be signed with an embedded 'jwk'")
        verify_signature(parsed.jwk, parsed.alg, parsed.signing_input, parsed.signature)
        payload = parsed.payload_json()

        thumbprint = jwk_thumbprint(parsed.jwk)
        existing = ctx.store.get_account_by_thumbprint(thumbprint)
        if existing:
            return JSONResponse(
                account_json(existing),
                status_code=200,
                headers={"Location": ctx.account_url(existing["id"])},
            )
        if payload.get("onlyReturnExisting"):
            raise AcmeError("accountDoesNotExist", "no account for this key")
        if ctx.config.require_eab and "externalAccountBinding" not in payload:
            raise AcmeError("externalAccountRequired", "external account binding required")

        contact = payload.get("contact", []) or []
        acc = ctx.store.create_account(thumbprint, parsed.jwk, contact)
        ctx.store.audit("account.created", principal=f"acme:{acc['id']}", account=acc["id"])
        return JSONResponse(
            account_json(acc), status_code=201, headers={"Location": ctx.account_url(acc["id"])}
        )

    @router.post("/acme/account/{acc_id}")
    async def account(request: Request, acc_id: str) -> JSONResponse:
        parsed, acc = await authed(request)
        if acc["id"] != acc_id:
            raise AcmeError("unauthorized", "account mismatch")
        return JSONResponse(account_json(acc), headers={"Location": ctx.account_url(acc["id"])})

    @router.post("/acme/account/{acc_id}/orders")
    async def account_orders(request: Request, acc_id: str) -> JSONResponse:
        parsed, acc = await authed(request)
        if acc["id"] != acc_id:
            raise AcmeError("unauthorized", "account mismatch")
        return JSONResponse({"orders": [ctx.order_url(o) for o in ctx.store.list_order_ids(acc["id"])]})

    # ---- orders -----------------------------------------------------------

    @router.post("/acme/new-order")
    async def new_order(request: Request) -> JSONResponse:
        parsed, acc = await authed(request)
        payload = parsed.payload_json()
        identifiers = payload.get("identifiers")
        if not isinstance(identifiers, list) or not identifiers:
            raise AcmeError("malformed", "order must contain a non-empty 'identifiers' array")

        names: list[str] = []
        for ident in identifiers:
            if not isinstance(ident, dict) or ident.get("type") != "dns" or not ident.get("value"):
                raise AcmeError("unsupportedIdentifier", "only 'dns' identifiers are supported")
            value = str(ident["value"]).lower().rstrip(".")
            if value.startswith("*."):
                raise AcmeError(
                    "rejectedIdentifier", "wildcards require dns-01, which is not enabled"
                )
            names.append(value)

        expires = _iso(_now() + _dt.timedelta(days=7))
        order = ctx.store.create_order(
            acc["id"], names, payload.get("notBefore"), payload.get("notAfter"), expires
        )
        ctx.store.audit(
            "order.created", principal=f"acme:{acc['id']}", order=order["id"], identifiers=names
        )
        return JSONResponse(
            order_json(order), status_code=201, headers={"Location": ctx.order_url(order["id"])}
        )

    @router.post("/acme/order/{order_id}")
    async def get_order(request: Request, order_id: str) -> JSONResponse:
        parsed, acc = await authed(request)
        order = ctx.store.refresh_order_status(order_id)
        if not order:
            raise AcmeError("malformed", "unknown order", status=404)
        own_or_403(order["account_id"], acc)
        return JSONResponse(order_json(order))

    @router.post("/acme/authz/{authz_id}")
    async def get_authz(request: Request, authz_id: str) -> JSONResponse:
        parsed, acc = await authed(request)
        authz = ctx.store.get_authorization(authz_id)
        if not authz:
            raise AcmeError("malformed", "unknown authorization", status=404)
        own_or_403(authz["account_id"], acc)
        return JSONResponse(authz_json(authz))

    # ---- challenges (HTTP-01) ---------------------------------------------

    @router.post("/acme/challenge/{chall_id}")
    async def challenge(request: Request, chall_id: str) -> JSONResponse:
        parsed, acc = await authed(request)
        chall = ctx.store.get_challenge(chall_id)
        if not chall:
            raise AcmeError("malformed", "unknown challenge", status=404)
        authz = ctx.store.get_authorization(chall["authz_id"])
        assert authz is not None
        own_or_403(authz["account_id"], acc)

        link = {"Link": f'<{ctx.authz_url(authz["id"])}>;rel="up"'}
        if chall["status"] in ("valid", "invalid"):
            return JSONResponse(challenge_json(chall), headers=link)

        expected = key_authorization(chall["token"], acc["jwk"])
        ok, err = await validate_http01(
            authz["identifier"],
            chall["token"],
            expected,
            port=ctx.config.http01_port,
            timeout=ctx.config.http01_timeout,
        )
        if ok:
            ctx.store.set_challenge_result(chall_id, "valid")
            ctx.store.set_authorization_status(authz["id"], "valid")
            ctx.store.audit(
                "challenge.valid", principal=f"acme:{acc['id']}", identifier=authz["identifier"]
            )
        else:
            kind, detail = err  # type: ignore[misc]
            error_obj = {"type": ACME_ERROR_NS + kind, "detail": detail}
            ctx.store.set_challenge_result(chall_id, "invalid", error_obj)
            ctx.store.set_authorization_status(authz["id"], "invalid")
            ctx.store.set_order_status(authz["order_id"], "invalid", error_obj)
            ctx.store.audit(
                "challenge.invalid",
                principal=f"acme:{acc['id']}",
                identifier=authz["identifier"],
                detail=detail,
            )
        ctx.store.refresh_order_status(authz["order_id"])
        return JSONResponse(challenge_json(ctx.store.get_challenge(chall_id)), headers=link)  # type: ignore[arg-type]

    # ---- finalize / certificate -------------------------------------------

    @router.post("/acme/order/{order_id}/finalize")
    async def finalize(request: Request, order_id: str) -> JSONResponse:
        parsed, acc = await authed(request)
        order = ctx.store.refresh_order_status(order_id)
        if not order:
            raise AcmeError("malformed", "unknown order", status=404)
        own_or_403(order["account_id"], acc)
        if order["status"] != "ready":
            raise AcmeError("orderNotReady", f"order is '{order['status']}', not 'ready'")

        payload = parsed.payload_json()
        if "csr" not in payload:
            raise AcmeError("badCSR", "finalize payload must contain 'csr'")
        try:
            csr = x509.load_der_x509_csr(b64url_decode(payload["csr"]))
        except Exception as exc:  # noqa: BLE001
            raise AcmeError("badCSR", "could not parse CSR") from exc
        if not csr.is_signature_valid:
            raise AcmeError("badCSR", "CSR signature is invalid")

        try:
            san = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            csr_names = {n.lower().rstrip(".") for n in san.value.get_values_for_type(x509.DNSName)}
        except x509.ExtensionNotFound:
            csr_names = set()
        if csr_names != set(order["identifiers"]):
            raise AcmeError("badCSR", "CSR SAN set must exactly match the order identifiers")

        if order.get("not_after"):
            not_after = _dt.datetime.fromisoformat(order["not_after"])
        else:
            not_after = _now() + _dt.timedelta(days=ctx.config.leaf_days)

        leaf = ctx.ca.issue_leaf(csr.public_key(), order["identifiers"], not_after)
        chain = ctx.ca.chain_pem(leaf)
        serial = str(leaf.serial_number)
        cert_id = ctx.store.store_certificate(
            acc["id"], order_id, serial, order["identifiers"],
            leaf.public_bytes(Encoding.PEM), chain, _iso(not_after),
        )
        ctx.store.audit(
            "certificate.issued",
            principal=f"acme:{acc['id']}",
            serial=serial,
            identifiers=order["identifiers"],
        )
        return JSONResponse(order_json(ctx.store.get_order(order_id)))  # type: ignore[arg-type]

    @router.post("/acme/certificate/{cert_id}")
    async def certificate(request: Request, cert_id: str) -> Response:
        parsed, acc = await authed(request)
        cert = ctx.store.get_certificate(cert_id)
        if not cert:
            raise AcmeError("malformed", "unknown certificate", status=404)
        own_or_403(cert["account_id"], acc)
        return Response(cert["chain_pem"], media_type="application/pem-certificate-chain")

    # ---- revocation -------------------------------------------------------

    @router.post("/acme/revoke-cert")
    async def revoke_cert(request: Request) -> Response:
        parsed = await read_jws(request)
        payload = parsed.payload_json()
        if "certificate" not in payload:
            raise AcmeError("malformed", "payload must contain 'certificate'")
        try:
            cert = x509.load_der_x509_certificate(b64url_decode(payload["certificate"]))
        except Exception as exc:  # noqa: BLE001
            raise AcmeError("malformed", "could not parse certificate") from exc
        serial = str(cert.serial_number)
        stored = ctx.store.get_certificate_by_serial(serial)
        if not stored:
            raise AcmeError("malformed", "unknown certificate")

        # Authorize: account key that owns the cert (kid), or the certificate key itself (jwk).
        if parsed.kid:
            acc = resolve_account(parsed)
            verify_signature(acc["jwk"], parsed.alg, parsed.signing_input, parsed.signature)
            own_or_403(stored["account_id"], acc)
        elif parsed.jwk:
            verify_signature(parsed.jwk, parsed.alg, parsed.signing_input, parsed.signature)
            supplied = jwk_to_public_key(parsed.jwk).public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo
            )
            actual = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
            if supplied != actual:
                raise AcmeError("unauthorized", "signing key is not the certificate key")
        else:
            raise AcmeError("malformed", "revocation must be signed with 'kid' or 'jwk'")

        if stored["status"] == "revoked":
            raise AcmeError("alreadyRevoked", "certificate is already revoked")
        reason = payload.get("reason")
        ctx.store.revoke_certificate(serial, reason if isinstance(reason, int) else None)
        # Attribute to the certificate's owning account either way: the 'kid' path IS that
        # account; the 'jwk' (cert-key self-revocation) path never resolved an account object,
        # but the cert being revoked always belongs to one — `stored["account_id"]`.
        ctx.store.audit(
            "certificate.revoked", principal=f"acme:{stored['account_id']}", serial=serial, reason=reason
        )
        return Response(status_code=200)

    return router

# SPDX-License-Identifier: Apache-2.0
"""Optional SSO auth for SecCert's admin plane — SecSSO (OIDC) integration, off by default.

This gates the management surface only: the console at ``/admin`` and the control API under
``/admin/api/*`` (certificate list/revoke, audit log/verify, evidence export). The public trust
anchor (``/ca.crt``, ``/roots``, ``/intermediate.crt``, ``/crl``, ``/health``) and the whole ACME
protocol surface (``/acme/*``) are unaffected — ACME clients authenticate with their own account
key (JWS), never with this.

Two ways in, both validated against the SAME SecSSO issuer:

  * **Bearer JWT** — a CLI/script presents ``Authorization: Bearer <token>`` and it's verified
    against SecSSO's published JWKS (RS256, issuer, audience).
  * **Browser login (BFF)** — the console logs in through SecSSO with Authorization Code + PKCE run
    entirely server-side; the browser's only credential is an httpOnly ``seccert_session`` cookie.

Either way, the caller must also be a **member of the admin group** (``SECCERT_ADMIN_GROUP``,
default ``seccert-admins``) — a valid SecSSO login is necessary but not sufficient. The static
``SECCERT_ADMIN_TOKEN`` is always still accepted as a bootstrap / break-glass credential (and is
the only credential when SSO is off), so an air-gapped or pre-SSO deployment keeps working
unchanged.

**Off by default.** With no OIDC env set, ``auth_enabled`` is False, the middleware is inert, and
``require_admin`` (in ``admin/api.py``) falls back to the static token exactly as before. Auth
turns on when ``SECCERT_OIDC_ISSUER`` + ``SECCERT_OIDC_AUDIENCE`` are set (bearer); the browser
login additionally needs the confidential-client secret + this service's public URL + a session
secret.

The audit ledger's ``principal`` field for admin-initiated events reflects whichever path
authorized the request: the OIDC ``sub`` when SSO resolved a principal, else the literal
``"token-admin"`` for the static break-glass token — see ``admin/api.py``'s ``require_admin``.

Depends only on **PyJWT[crypto]** + the stdlib — the same OIDC library the rest of the suite uses
(mirrors secllm's ``auth.py`` almost verbatim; see that module for the fuller narrative).

NOTE: NO ``from __future__ import annotations`` here, for the same reason as secllm's module —
FastAPI/Starlette are imported lazily inside ``install()``, so with stringized annotations the
route params (``request: Request``) would be unresolvable against this module's globals and every
``/auth`` route would 422. Runtime ``X | None`` / ``list[str]`` hints are valid on 3.11+ regardless,
so eager annotations cost nothing.
"""

import asyncio
import base64
import hashlib
import json
import os
import secrets
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

import jwt

# ── Config (env) ──────────────────────────────────────────────────────────────────────────────
ISSUER = os.environ.get("SECCERT_OIDC_ISSUER", "").strip().rstrip("/")
CLIENT_ID = os.environ.get("SECCERT_OIDC_CLIENT_ID", "").strip()
# Token audience to require. Defaults to the client id (Authentik mints id_tokens with
# aud == client_id). Set explicitly only if your access tokens carry a different audience.
AUDIENCE = os.environ.get("SECCERT_OIDC_AUDIENCE", "").strip() or CLIENT_ID
CLIENT_SECRET = os.environ.get("SECCERT_OIDC_CLIENT_SECRET", "").strip()
PUBLIC_URL = os.environ.get("SECCERT_PUBLIC_URL", "").strip().rstrip("/")
SESSION_SECRET = os.environ.get("SECCERT_SESSION_SECRET", "").strip()
SESSION_TTL = int(os.environ.get("SECCERT_SESSION_TTL", "43200"))  # 12h
# Admin group: a valid login must carry this group to administer SecCert. Empty ⇒ any
# authenticated SecSSO user is an admin (an explicit opt-out; the default keeps admin separate
# from ordinary use).
ADMIN_GROUP = os.environ.get("SECCERT_ADMIN_GROUP", "seccert-admins").strip()
# Optional explicit endpoints — skip OIDC discovery (air-gapped setups that don't expose
# /.well-known, or to pin them). When unset they're discovered from the issuer on first use.
JWKS_URL = os.environ.get("SECCERT_OIDC_JWKS_URL", "").strip()
AUTHORIZE_URL = os.environ.get("SECCERT_OIDC_AUTHORIZE_URL", "").strip()
TOKEN_URL = os.environ.get("SECCERT_OIDC_TOKEN_URL", "").strip()

# Bearer needs only issuer + audience. The browser login (BFF) additionally needs the confidential-
# client secret, this service's public URL (to build redirect_uri), and a session-signing secret.
bearer_ready = bool(ISSUER and AUDIENCE)
sso_ready = bool(ISSUER and CLIENT_ID and CLIENT_SECRET and PUBLIC_URL and SESSION_SECRET)
auth_enabled = bearer_ready or sso_ready

SESSION_COOKIE = "seccert_session"
FLOW_COOKIE = "seccert_oidc_flow"
FLOW_TTL_SECONDS = 600  # 10 min — one IdP round-trip, no longer
SCOPE = "openid profile email groups"
# Own iss/aud for the HS256 cookies, DISJOINT from each other so a captured flow cookie can never
# be replayed as a session cookie (or vice versa) even though both are signed with SESSION_SECRET.
SESSION_ISS = "seccert-session"
FLOW_ISS = "seccert-oidc-flow"


@dataclass
class Principal:
    """The authenticated caller — identity + groups (the group drives the admin check)."""

    sub: str
    email: str | None = None
    display_name: str | None = None
    groups: list[str] = field(default_factory=list)


def is_admin(p: Principal) -> bool:
    """Whether principal ``p`` may administer SecCert: a member of ``ADMIN_GROUP`` (or any
    authenticated user when ``ADMIN_GROUP`` is explicitly blank)."""
    return not ADMIN_GROUP or ADMIN_GROUP in p.groups


# ── OIDC discovery (cached per process) ─────────────────────────────────────────────────────────
_discovery: dict | None = None


def _discover() -> dict:
    global _discovery
    if _discovery is None:
        with urllib.request.urlopen(f"{ISSUER}/.well-known/openid-configuration", timeout=10) as r:
            _discovery = json.loads(r.read().decode("utf-8"))
    return _discovery


def _jwks_url() -> str:
    return JWKS_URL or _discover()["jwks_uri"]


def _authorize_url() -> str:
    return AUTHORIZE_URL or _discover()["authorization_endpoint"]


def _token_url() -> str:
    return TOKEN_URL or _discover()["token_endpoint"]


# ── Bearer JWT (RS256, JWKS) ────────────────────────────────────────────────────────────────────
_jwk_client: "jwt.PyJWKClient | None" = None


def _jwks() -> "jwt.PyJWKClient":
    global _jwk_client
    if _jwk_client is None:
        _jwk_client = jwt.PyJWKClient(_jwks_url())  # caches keys; refetches only on a kid miss
    return _jwk_client


def _principal_from_claims(claims: dict) -> Principal:
    sub = claims.get("sub")
    if not sub:
        raise jwt.InvalidTokenError("token missing 'sub'")
    groups = claims.get("groups")
    return Principal(
        sub=str(sub),
        email=claims.get("email") if isinstance(claims.get("email"), str) else None,
        display_name=claims.get("name") if isinstance(claims.get("name"), str) else None,
        groups=[str(g) for g in groups] if isinstance(groups, list) else [],
    )


def verify_bearer(token: str) -> Principal:
    """Verify a SecSSO access/id token against the published JWKS: RS256 (never an attacker-
    forgeable alg), issuer, audience, expiry. Raises ``jwt.PyJWTError`` on any failure."""
    key = _jwks().get_signing_key_from_jwt(token).key
    claims = jwt.decode(token, key, algorithms=["RS256"], issuer=ISSUER, audience=AUDIENCE)
    return _principal_from_claims(claims)


# ── Session + flow cookies (HS256, own trust domain) ────────────────────────────────────────────
def mint_session(p: Principal) -> str:
    now = int(time.time())
    return jwt.encode(
        {"sub": p.sub, "email": p.email, "name": p.display_name, "groups": p.groups,
         "iss": SESSION_ISS, "aud": SESSION_ISS, "iat": now, "exp": now + SESSION_TTL},
        SESSION_SECRET, algorithm="HS256",
    )


def verify_session(token: str) -> Principal:
    claims = jwt.decode(token, SESSION_SECRET, algorithms=["HS256"], issuer=SESSION_ISS, audience=SESSION_ISS)
    return _principal_from_claims(claims)


def _sign_flow(state: str, verifier: str, nonce: str, nxt: str) -> str:
    now = int(time.time())
    return jwt.encode(
        {"state": state, "verifier": verifier, "nonce": nonce, "next": nxt,
         "iss": FLOW_ISS, "aud": FLOW_ISS, "iat": now, "exp": now + FLOW_TTL_SECONDS},
        SESSION_SECRET, algorithm="HS256",
    )


def _verify_flow(token: str) -> dict:
    claims = jwt.decode(token, SESSION_SECRET, algorithms=["HS256"], issuer=FLOW_ISS, audience=FLOW_ISS)
    for k in ("state", "verifier", "nonce", "next"):
        if not isinstance(claims.get(k), str):
            raise jwt.InvalidTokenError("malformed OIDC flow cookie")
    return claims


# ── PKCE + Authorization Code exchange + id_token verification ──────────────────────────────────
def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _new_verifier() -> str:
    return _b64url(secrets.token_bytes(32))  # RFC 7636: 43-char high-entropy verifier


def _challenge_s256(verifier: str) -> str:
    return _b64url(hashlib.sha256(verifier.encode("ascii")).digest())


def _build_authorize_url(state: str, nonce: str, challenge: str, redirect_uri: str) -> str:
    q = urllib.parse.urlencode({
        "response_type": "code", "client_id": CLIENT_ID, "redirect_uri": redirect_uri,
        "scope": SCOPE, "state": state, "nonce": nonce,
        "code_challenge": challenge, "code_challenge_method": "S256",
    })
    return f"{_authorize_url()}?{q}"


def _exchange_code(code: str, verifier: str, redirect_uri: str) -> dict:
    body = urllib.parse.urlencode({
        "grant_type": "authorization_code", "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET,
        "redirect_uri": redirect_uri, "code": code, "code_verifier": verifier,
    }).encode("ascii")
    req = urllib.request.Request(
        _token_url(), data=body,
        headers={"content-type": "application/x-www-form-urlencoded"}, method="POST")
    with urllib.request.urlopen(req, timeout=10) as r:
        tok = json.loads(r.read().decode("utf-8"))
    if not isinstance(tok.get("id_token"), str):
        raise jwt.InvalidTokenError("token response missing id_token")
    return tok


def _verify_id_token(id_token: str, nonce: str) -> Principal:
    key = _jwks().get_signing_key_from_jwt(id_token).key
    claims = jwt.decode(id_token, key, algorithms=["RS256"], issuer=ISSUER, audience=CLIENT_ID)
    if claims.get("nonce") != nonce:
        raise jwt.InvalidTokenError("id_token nonce mismatch")
    return _principal_from_claims(claims)


def _safe_next(raw: str | None) -> str:
    """Open-redirect guard: only a same-origin relative path (single leading '/', no '//', no
    control/space chars) is honored; anything else falls back to '/admin'."""
    if not raw or not raw.startswith("/") or raw.startswith("//"):
        return "/admin"
    if any(ord(c) <= 32 or ord(c) == 127 for c in raw):
        return "/admin"
    return raw


def _secure_cookie() -> bool:
    return PUBLIC_URL.lower().startswith("https")


# ── Principal resolution (bearer OR session) ────────────────────────────────────────────────────
def _resolve_sync(bearer: str | None, session: str | None) -> Principal | None:
    if session:
        try:
            return verify_session(session)
        except jwt.PyJWTError:
            pass
    if bearer and bearer_ready:
        try:
            return verify_bearer(bearer)
        except jwt.PyJWTError:
            pass
    return None


async def _resolve(request) -> Principal | None:
    """Resolve the caller from the session cookie (browser) or the bearer header (CLI). JWKS
    verification can do a one-time network fetch, so it runs in a thread to keep the loop free.
    NOTE: an opaque static admin token presented as a bearer simply fails JWT verification here
    (→ None); require_admin then accepts it separately as the break-glass credential."""
    hdr = request.headers.get("authorization", "")
    bearer = hdr[7:].strip() if hdr[:7].lower() == "bearer " else None
    session = request.cookies.get(SESSION_COOKIE)
    if not bearer and not session:
        return None
    return await asyncio.to_thread(_resolve_sync, bearer, session)


def current_principal(request) -> "Principal | None":
    """The principal the middleware resolved for this request (None when auth is off or anonymous)."""
    return getattr(request.state, "principal", None)


def install(app) -> None:
    """Wire the ``/auth/*`` routes + a principal-resolving middleware onto the FastAPI app.
    Inert for request handling when auth is disabled (middleware short-circuits), so always safe to
    call. Does NOT itself 401 the admin API — that's ``admin.api.require_admin``, which also honors
    the static break-glass token; this middleware only resolves the principal onto request.state."""
    from fastapi import APIRouter, Request, Response
    from fastapi.responses import JSONResponse, RedirectResponse
    from starlette.middleware.base import BaseHTTPMiddleware

    router = APIRouter()

    @router.get("/auth/status")
    def auth_status_route(request: Request) -> JSONResponse:
        """Whether SSO is enforced, whether browser login is available, and — since the session
        cookie is httpOnly — WHO the current session belongs to (+ whether they're an admin), so
        the console can show "signed in as … / Sign out" and the right controls."""
        p = current_principal(request)
        return JSONResponse({
            "auth_enabled": auth_enabled, "sso": sso_ready, "bearer": bearer_ready,
            "admin_group": ADMIN_GROUP,
            "user": {"sub": p.sub, "name": p.display_name or p.email or p.sub, "admin": is_admin(p)} if p else None,
        })

    @router.get("/auth/login")
    async def auth_login(request: Request):
        if not sso_ready:
            return JSONResponse({"error": "sso_not_configured"}, status_code=503)
        try:
            nxt = _safe_next(request.query_params.get("next"))
            state, nonce, verifier = secrets.token_urlsafe(16), secrets.token_urlsafe(16), _new_verifier()
            redirect_uri = f"{PUBLIC_URL}/auth/callback"
            url = await asyncio.to_thread(_build_authorize_url, state, nonce, _challenge_s256(verifier), redirect_uri)
            resp = RedirectResponse(url, status_code=302)
            resp.set_cookie(FLOW_COOKIE, _sign_flow(state, verifier, nonce, nxt), max_age=FLOW_TTL_SECONDS,
                            httponly=True, samesite="lax", secure=_secure_cookie(), path="/")
            return resp
        except Exception:  # noqa: BLE001 — never leak IdP/network internals; generic bounce
            return RedirectResponse("/admin?auth_error=login_failed", status_code=302)

    @router.get("/auth/callback")
    async def auth_callback(request: Request):
        if not sso_ready:
            return JSONResponse({"error": "sso_not_configured"}, status_code=503)
        try:
            code, state = request.query_params.get("code"), request.query_params.get("state")
            flow_token = request.cookies.get(FLOW_COOKIE)
            if not code or not state or not flow_token:
                raise jwt.InvalidTokenError("callback missing code/state/flow")
            flow = _verify_flow(flow_token)
            if flow["state"] != state:
                raise jwt.InvalidTokenError("state mismatch")
            redirect_uri = f"{PUBLIC_URL}/auth/callback"
            tok = await asyncio.to_thread(_exchange_code, code, flow["verifier"], redirect_uri)
            principal = await asyncio.to_thread(_verify_id_token, tok["id_token"], flow["nonce"])
            resp = RedirectResponse(_safe_next(flow["next"]), status_code=302)
            resp.set_cookie(SESSION_COOKIE, mint_session(principal), max_age=SESSION_TTL,
                            httponly=True, samesite="lax", secure=_secure_cookie(), path="/")
            resp.delete_cookie(FLOW_COOKIE, path="/")
            return resp
        except Exception:  # noqa: BLE001
            return RedirectResponse("/admin?auth_error=login_failed", status_code=302)

    @router.post("/auth/logout")
    def auth_logout() -> Response:
        resp = Response(status_code=204)
        resp.delete_cookie(SESSION_COOKIE, path="/")
        return resp

    class AuthMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            request.state.principal = await _resolve(request) if auth_enabled else None
            return await call_next(request)

    app.include_router(router)
    app.add_middleware(AuthMiddleware)


def status() -> dict:
    """Auth summary for /health."""
    return {"auth_enabled": auth_enabled, "sso_login": sso_ready, "bearer": bearer_ready,
            **({"issuer": ISSUER, "audience": AUDIENCE, "admin_group": ADMIN_GROUP} if auth_enabled else {})}

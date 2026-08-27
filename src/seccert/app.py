"""FastAPI application factory — wires the CA, store, ACME router, and admin console."""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from starlette.responses import Response

from . import auth
from .acme.router import build_router as build_acme_router
from .admin.api import build_router as build_admin_router
from .ca import CertificateAuthority
from .config import Config
from .context import Context
from .errors import install_error_handler
from .store import Store

log = logging.getLogger("seccert")


def create_app(config: Config | None = None) -> FastAPI:
    config = config or Config.from_env()
    config.ensure_dirs()

    ca = CertificateAuthority(
        ca_dir=config.ca_dir,
        org=config.org,
        root_cn=config.root_cn,
        intermediate_cn=config.intermediate_cn,
        key_type=config.ca_key_type,
        root_days=config.root_days,
        intermediate_days=config.intermediate_days,
        passphrase=config.ca_passphrase,
    ).load_or_create()
    store = Store(config.db_path)
    ctx = Context(config=config, ca=ca, store=store)

    app = FastAPI(title="SecCert", version="1.0.0", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.ctx = ctx
    install_error_handler(app)

    @app.middleware("http")
    async def replay_nonce(request: Request, call_next) -> Response:
        response = await call_next(request)
        # Every ACME response carries a fresh anti-replay nonce (RFC 8555 §6.5).
        if request.url.path.startswith("/acme"):
            response.headers["Replay-Nonce"] = store.new_nonce()
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    app.include_router(build_acme_router(ctx))
    app.include_router(build_admin_router(ctx))
    # Optional SSO for the admin plane (off unless SECCERT_OIDC_* is set) — adds /auth/* + a
    # principal-resolving middleware. The ACME surface (/acme/*) is untouched; see auth.py.
    auth.install(app)

    if config.admin_token_generated:
        log.warning(
            "SECCERT_ADMIN_TOKEN was not set; generated one for this session: %s",
            config.admin_token,
        )
    log.info(
        "SecCert ready — external_url=%s data_dir=%s ca_key=%s",
        config.external_url,
        config.data_dir,
        config.ca_key_type,
    )
    return app

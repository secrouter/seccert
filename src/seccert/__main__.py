"""``python -m seccert`` / ``seccert`` entrypoint."""

from __future__ import annotations

import logging
from urllib.parse import urlparse

import uvicorn

from .app import create_app
from .ca import cert_pem
from .config import Config


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    config = Config.from_env()
    app = create_app(config)

    ssl_kwargs: dict[str, str] = {}
    if config.tls_mode == "native":
        if config.tls_cert and config.tls_key:
            ssl_kwargs = {"ssl_certfile": config.tls_cert, "ssl_keyfile": config.tls_key}
        else:
            # Self-issue a serving certificate for our own hostname from the Intermediate.
            host = urlparse(config.external_url).hostname or "localhost"
            key, cert = app.state.ctx.ca.self_issue_server_cert([host])
            cert_path = config.data_dir / "server.crt"
            key_path = config.data_dir / "server.key"
            cert_path.write_bytes(cert_pem(cert))
            from cryptography.hazmat.primitives import serialization

            key_path.write_bytes(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
            try:
                key_path.chmod(0o600)
            except OSError:
                pass
            ssl_kwargs = {"ssl_certfile": str(cert_path), "ssl_keyfile": str(key_path)}

    uvicorn.run(app, host=config.host, port=config.port, **ssl_kwargs)


if __name__ == "__main__":
    main()

# SecCert — mini ACME CA. Small, non-root, single service.
FROM python:3.13-slim

# uv for fast, reproducible installs
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SECCERT_DATA_DIR=/var/lib/seccert \
    SECCERT_HOST=0.0.0.0 \
    SECCERT_PORT=14000

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src

# Install the package + its dependencies into the system environment.
RUN uv pip install --system --no-cache . \
    && useradd --uid 10001 --no-create-home --home-dir /var/lib/seccert --shell /usr/sbin/nologin seccert \
    && mkdir -p /var/lib/seccert \
    && chown -R seccert:seccert /var/lib/seccert

USER seccert
VOLUME ["/var/lib/seccert"]
EXPOSE 14000

# Simple liveness check against the open /health endpoint.
HEALTHCHECK --interval=30s --timeout=4s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request,os,sys; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('SECCERT_PORT','14000')+'/health',timeout=3).status==200 else 1)"

ENTRYPOINT ["seccert"]

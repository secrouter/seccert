"""Pytest fixtures: an HTTP-01 responder and a freshly-configured SecCert app + client."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from helpers import Challenge01Server


@pytest.fixture
def http01():
    server = Challenge01Server().start()
    yield server
    server.stop()


@pytest.fixture
def client(http01, tmp_path, monkeypatch):
    monkeypatch.setenv("SECCERT_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SECCERT_EXTERNAL_URL", "http://testserver")
    monkeypatch.setenv("SECCERT_HTTP01_PORT", str(http01.port))
    monkeypatch.setenv("SECCERT_ADMIN_TOKEN", "test-admin-token")
    # Import inside the fixture so env vars are read fresh per test.
    from seccert.app import create_app

    return TestClient(create_app())

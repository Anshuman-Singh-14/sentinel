"""Security headers, and Sentinel passing its own header checker (04-security.md section 9).

The API's headers come from ``SecurityHeadersMiddleware`` on every response,
including errors. The production nginx front end is checked the same way,
live, by the CI production-profile job (scripts/self_header_check.py),
because its config lives outside the backend image.
"""

from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.config import get_settings
from app.engine.schemas import Severity
from app.main import create_app
from app.tools.header_tls.translator import _header_findings, header_map

REQUIRED = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "cross-origin-resource-policy": "same-origin",
    "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
}


@pytest.mark.parametrize(
    ("method", "path", "status"),
    [
        ("GET", "/health", 200),
        ("GET", "/no-such-route", 404),
        ("GET", "/api/v1/tools", 401),
        ("POST", "/api/v1/auth/login", 422),  # validation error
    ],
)
def test_every_response_carries_the_headers(
    client: TestClient, method: str, path: str, status: int
) -> None:
    response = client.request(method, path, json={})
    assert response.status_code == status
    for name, value in REQUIRED.items():
        assert response.headers[name] == value, name
    assert "permissions-policy" in response.headers
    assert "strict-transport-security" not in response.headers  # dev/test: HTTP only


@pytest.fixture
def production_app(monkeypatch: pytest.MonkeyPatch) -> Iterator[FastAPI]:
    monkeypatch.setenv("ENVIRONMENT", "production")
    get_settings.cache_clear()
    try:
        yield create_app()
    finally:
        monkeypatch.undo()
        get_settings.cache_clear()


def test_production_api_passes_its_own_header_checker(production_app: FastAPI) -> None:
    with TestClient(production_app) as client:
        response = client.get("/health")
        assert client.get("/docs").status_code == 404  # no interactive docs in production
    assert response.headers["strict-transport-security"].startswith("max-age=31536000")
    findings = _header_findings(header_map(list(response.headers.items())), True, "sentinel")
    problems = [f.item for f in findings if f.severity is not Severity.INFO]
    assert problems == []
    assert {f.status.value for f in findings} == {"PASS"}

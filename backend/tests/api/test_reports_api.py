"""Report endpoints: authentication, RBAC and validation (no database needed)."""

import uuid
from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient

from app.core.auth.dependencies import Principal
from app.core.auth.roles import Role
from tests.conftest import FakeAudit


@pytest.mark.parametrize("role", list(Role))
def test_every_role_can_list_formats(
    client: TestClient, authenticate: Callable[[Role], Principal], role: Role
) -> None:
    authenticate(role)
    response = client.get("/api/v1/reports/formats")
    assert response.status_code == 200
    formats = {f["format"]: f for f in response.json()}
    assert set(formats) == {"pdf", "csv", "json", "txt"}
    assert formats["pdf"]["media_type"] == "application/pdf"


def test_reports_require_authentication(client: TestClient) -> None:
    for method, path in (
        ("GET", "/api/v1/reports"),
        ("GET", f"/api/v1/reports/{uuid.uuid4()}/download"),
        ("POST", "/api/v1/reports"),
    ):
        response = client.request(method, path, json={})
        assert response.status_code == 401, path


def test_viewers_cannot_request_reports(
    client: TestClient, authenticate: Callable[[Role], Principal], fake_audit: FakeAudit
) -> None:
    authenticate(Role.VIEWER)
    response = client.post(
        "/api/v1/reports",
        json={"source_type": "tool_run", "source_id": str(uuid.uuid4()), "format": "pdf"},
    )
    assert response.status_code == 403
    assert fake_audit.actions() == ["auth.access.denied"]


@pytest.mark.parametrize(
    "body",
    [
        {"source_type": "audit", "source_id": str(uuid.uuid4()), "format": "pdf"},
        {"source_type": "tool_run", "source_id": "not-a-uuid", "format": "pdf"},
        {"source_type": "tool_run", "source_id": str(uuid.uuid4()), "format": "../pdf"},
        {"source_type": "tool_run", "source_id": str(uuid.uuid4()), "format": "pdf", "x": 1},
    ],
)
def test_report_requests_are_validated(
    client: TestClient,
    authenticate: Callable[[Role], Principal],
    fake_audit: FakeAudit,
    body: dict[str, str],
) -> None:
    authenticate(Role.ANALYST)
    response = client.post("/api/v1/reports", json=body)
    assert response.status_code == 422


def test_audit_export_is_admin_only(
    client: TestClient, authenticate: Callable[[Role], Principal], fake_audit: FakeAudit
) -> None:
    authenticate(Role.ANALYST)
    assert client.get("/api/v1/admin/audit/export").status_code == 403
    assert fake_audit.actions() == ["auth.access.denied"]

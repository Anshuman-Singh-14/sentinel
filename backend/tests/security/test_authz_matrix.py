"""Authorization matrix: every API route, every role (04-security.md section 11).

``ROUTES`` is the single declared source of truth for who may call what. The
inventory test fails when a route is added without being classified here, so
no endpoint can ship without someone deciding its minimum role. The other
tests then check, black-box, that each route refuses anonymous callers with
401 and lower roles with 403, before any handler or database code runs.

Ownership rules inside handlers (only the requester or an admin may cancel a
run) are covered by the integration tests.
"""

import re
import uuid
from collections.abc import Callable

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.auth.dependencies import Principal
from app.core.auth.roles import Role
from tests.conftest import FakeAudit

PUBLIC = "public"
ROLE_ORDER = [Role.VIEWER, Role.ANALYST, Role.ADMIN]

# (method, path template) -> minimum role, or PUBLIC.
ROUTES: dict[tuple[str, str], str | Role] = {
    ("GET", "/health"): PUBLIC,
    ("GET", "/ready"): PUBLIC,
    ("POST", "/api/v1/auth/login"): PUBLIC,
    ("POST", "/api/v1/auth/refresh"): PUBLIC,
    ("POST", "/api/v1/auth/logout"): PUBLIC,  # ends whatever session the cookie names
    ("GET", "/api/v1/auth/me"): Role.VIEWER,
    ("POST", "/api/v1/auth/password"): Role.VIEWER,
    ("GET", "/api/v1/admin/users"): Role.ADMIN,
    ("POST", "/api/v1/admin/users"): Role.ADMIN,
    ("PATCH", "/api/v1/admin/users/{user_id}"): Role.ADMIN,
    ("GET", "/api/v1/admin/users/{user_id}/sessions"): Role.ADMIN,
    ("DELETE", "/api/v1/admin/sessions/{session_id}"): Role.ADMIN,
    ("GET", "/api/v1/admin/audit"): Role.ADMIN,
    ("GET", "/api/v1/admin/audit/export"): Role.ADMIN,
    ("POST", "/api/v1/admin/audit/verify"): Role.ADMIN,
    ("GET", "/api/v1/admin/alerts"): Role.ADMIN,
    ("POST", "/api/v1/admin/alerts/{alert_id}/acknowledge"): Role.ADMIN,
    ("GET", "/api/v1/tools"): Role.VIEWER,
    ("POST", "/api/v1/tools/{tool_id}/runs"): Role.ANALYST,
    ("POST", "/api/v1/tools/{tool_id}/runs/upload"): Role.ANALYST,
    ("GET", "/api/v1/runs"): Role.VIEWER,
    ("GET", "/api/v1/runs/{run_id}"): Role.VIEWER,
    ("POST", "/api/v1/runs/{run_id}/cancel"): Role.ANALYST,
    ("POST", "/api/v1/runs/{run_id}/ws-ticket"): Role.VIEWER,
    ("GET", "/api/v1/scope"): Role.VIEWER,
    ("GET", "/api/v1/scope/acknowledgement"): Role.VIEWER,
    ("POST", "/api/v1/scope/acknowledgement"): Role.ANALYST,
    ("GET", "/api/v1/admin/scope"): Role.ADMIN,
    ("POST", "/api/v1/admin/scope"): Role.ADMIN,
    ("PATCH", "/api/v1/admin/scope/{entry_id}"): Role.ADMIN,
    ("DELETE", "/api/v1/admin/scope/{entry_id}"): Role.ADMIN,
    ("GET", "/api/v1/playbooks"): Role.VIEWER,
    ("POST", "/api/v1/playbooks/{playbook_id}/runs"): Role.ANALYST,
    ("GET", "/api/v1/playbook-runs"): Role.VIEWER,
    ("GET", "/api/v1/playbook-runs/{playbook_run_id}"): Role.VIEWER,
    ("POST", "/api/v1/playbook-runs/{playbook_run_id}/cancel"): Role.ANALYST,
    ("POST", "/api/v1/playbook-runs/{playbook_run_id}/ws-ticket"): Role.VIEWER,
    ("GET", "/api/v1/reports/formats"): Role.VIEWER,
    ("POST", "/api/v1/reports"): Role.ANALYST,
    ("GET", "/api/v1/reports"): Role.VIEWER,
    ("GET", "/api/v1/reports/{report_id}"): Role.VIEWER,
    ("GET", "/api/v1/reports/{report_id}/download"): Role.VIEWER,
    ("GET", "/api/v1/fim/baselines"): Role.VIEWER,
    ("PATCH", "/api/v1/fim/baselines/{baseline_id}"): Role.ANALYST,
    ("DELETE", "/api/v1/fim/baselines/{baseline_id}"): Role.ANALYST,
}

PROTECTED = sorted(k for k, v in ROUTES.items() if v != PUBLIC)


def concrete(path: str) -> str:
    """Fill path parameters: ids get a UUID, names a valid slug."""
    path = re.sub(r"\{(tool_id|playbook_id)\}", "echo", path)
    return re.sub(r"\{[a-z_]+\}", str(uuid.uuid4()), path)


def test_every_route_is_classified(app: FastAPI) -> None:
    schema = app.openapi()
    served = {(m.upper(), p) for p, ops in schema["paths"].items() for m in ops}
    assert served - ROUTES.keys() == set(), "classify new routes in ROUTES"
    assert ROUTES.keys() - served == set(), "ROUTES lists routes that no longer exist"


@pytest.mark.parametrize(("method", "path"), PROTECTED)
def test_anonymous_callers_get_401(client: TestClient, method: str, path: str) -> None:
    response = client.request(method, concrete(path), json={})
    assert response.status_code == 401, response.text
    assert response.json()["error"]["code"] == "authentication_required"


DENIALS = [
    (method, path, role)
    for (method, path) in PROTECTED
    for role in ROLE_ORDER
    if ROLE_ORDER.index(role) < ROLE_ORDER.index(Role(ROUTES[(method, path)]))
]


@pytest.mark.parametrize(("method", "path", "role"), DENIALS)
def test_lower_roles_get_403_and_are_audited(
    client: TestClient,
    authenticate: Callable[[Role], Principal],
    fake_audit: FakeAudit,
    method: str,
    path: str,
    role: Role,
) -> None:
    authenticate(role)
    response = client.request(method, concrete(path), json={})
    assert response.status_code == 403, response.text
    assert response.json()["error"]["code"] == "permission_denied"
    assert fake_audit.actions() == ["auth.access.denied"]


def test_matrix_covers_the_spec_examples() -> None:
    # 04-security.md section 11: "viewer cannot run tools, analyst cannot view audit".
    assert ("POST", "/api/v1/tools/{tool_id}/runs", Role.VIEWER) in DENIALS
    assert ("GET", "/api/v1/admin/audit", Role.ANALYST) in DENIALS
    assert len(DENIALS) >= 30

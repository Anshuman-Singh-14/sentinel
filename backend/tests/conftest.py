"""Shared test configuration.

Settings are read from the environment at import time, so safe dummy values
are set before any ``app`` module is imported. Unit tests never touch real
services: dependency checks are monkeypatched.
"""

import os

# Assigned, not setdefault: tests often run inside the dev container, whose
# environment points at the real services and selects console logging.
# The integration profile (`docker compose --profile test run --rm test`)
# supplies TEST_* URLs for the separate test database; otherwise the URLs
# point nowhere and integration tests skip themselves.
os.environ["ENVIRONMENT"] = "test"
os.environ["LOG_LEVEL"] = "INFO"
os.environ["DATABASE_URL"] = os.environ.get(
    "TEST_DATABASE_URL", "postgresql://test:test@127.0.0.1:1/test"
)
os.environ["REDIS_URL"] = os.environ.get("TEST_REDIS_URL", "redis://:test@127.0.0.1:1/0")
os.environ["CORS_ORIGINS"] = "http://localhost:5173"
for _name in ("LOG_FORMAT", "LOG_FILE_PATH", "TRUSTED_PROXIES"):
    os.environ.pop(_name, None)

import io  # noqa: E402
import json  # noqa: E402
import uuid  # noqa: E402
from collections.abc import Callable, Iterator  # noqa: E402
from dataclasses import dataclass, field  # noqa: E402
from typing import Any  # noqa: E402

import pytest  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.config import get_settings  # noqa: E402
from app.core.audit import ActorType, get_audit_service  # noqa: E402
from app.core.audit.context import Actor  # noqa: E402
from app.core.auth.dependencies import Principal, get_principal  # noqa: E402
from app.core.auth.roles import Role  # noqa: E402
from app.core.logging import configure_logging  # noqa: E402
from app.main import create_app  # noqa: E402


@dataclass
class LogCapture:
    stream: io.StringIO

    @property
    def text(self) -> str:
        return self.stream.getvalue()

    def lines(self) -> list[dict[str, Any]]:
        """Every captured line, parsed. Fails the test if any line is not JSON."""
        return [json.loads(line) for line in self.text.splitlines() if line.strip()]

    def events(self, name: str) -> list[dict[str, Any]]:
        return [line for line in self.lines() if line.get("event") == name]


@pytest.fixture
def app() -> FastAPI:
    return create_app()


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def logs(app: FastAPI) -> LogCapture:
    """Route all logging (JSON, the test environment's format) into a buffer.

    Depends on ``app`` so it runs after create_app, which configures logging
    to stdout.
    """
    capture = LogCapture(io.StringIO())
    configure_logging(get_settings(), service="api", stream=capture.stream)
    return capture


@dataclass
class FakeAudit:
    """Stands in for AuditService in unit tests: records calls, touches no database."""

    records: list[dict[str, Any]] = field(default_factory=list)

    async def record(self, action: Any, **kwargs: Any) -> None:
        self.records.append({"action": str(action), **kwargs})

    def actions(self) -> list[str]:
        return [record["action"] for record in self.records]


@pytest.fixture
def fake_audit(app: FastAPI) -> Iterator[FakeAudit]:
    audit = FakeAudit()
    app.dependency_overrides[get_audit_service] = lambda: audit
    yield audit
    app.dependency_overrides.pop(get_audit_service, None)


@pytest.fixture
def authenticate(app: FastAPI) -> Iterator[Callable[[Role], Principal]]:
    """Make requests run as a principal with the given role, without a database.

    Unit tests use this to exercise RBAC. The real session lookup is covered
    by the integration tests (tests/integration).
    """

    def _as(role: Role = Role.VIEWER) -> Principal:
        user_id, session_id = uuid.uuid4(), uuid.uuid4()
        principal = Principal(
            user_id=user_id,
            username=f"unit-{role.value}",
            role=role,
            session_id=session_id,
            actor=Actor(
                actor_type=ActorType.USER,
                user_id=user_id,
                username=f"unit-{role.value}",
                role=role.value,
                session_id=session_id,
            ),
        )
        app.dependency_overrides[get_principal] = lambda: principal
        return principal

    yield _as
    app.dependency_overrides.pop(get_principal, None)

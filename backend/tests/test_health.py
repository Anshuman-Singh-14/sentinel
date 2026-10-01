from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from app import __version__
from app.api import health
from app.config import Settings
from app.main import create_app


@pytest.fixture
def client() -> Iterator[TestClient]:
    with TestClient(create_app()) as test_client:
        yield test_client


def _stub_checks(monkeypatch: pytest.MonkeyPatch, *, postgres: bool, redis: bool) -> None:
    async def fake_postgres(settings: Settings) -> bool:
        return postgres

    async def fake_redis(settings: Settings) -> bool:
        return redis

    monkeypatch.setattr(health, "check_postgres", fake_postgres)
    monkeypatch.setattr(health, "check_redis", fake_redis)


def test_health_reports_ok_and_version(client: TestClient) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": __version__}


def test_ready_when_all_dependencies_up(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_checks(monkeypatch, postgres=True, redis=True)

    response = client.get("/ready")

    assert response.status_code == 200
    assert response.json() == {"status": "ready", "checks": {"postgres": "ok", "redis": "ok"}}


@pytest.mark.parametrize(("postgres", "redis"), [(False, True), (True, False), (False, False)])
def test_not_ready_names_failing_dependency(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, postgres: bool, redis: bool
) -> None:
    _stub_checks(monkeypatch, postgres=postgres, redis=redis)

    response = client.get("/ready")

    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "not_ready"
    assert body["checks"] == {
        "postgres": "ok" if postgres else "fail",
        "redis": "ok" if redis else "fail",
    }


async def test_real_checks_fail_closed_on_unreachable_services() -> None:
    """Unreachable services return False (not an exception) within the timeout."""
    settings = Settings(
        database_url="postgresql://x:x@127.0.0.1:1/x",
        redis_url="redis://:x@127.0.0.1:1/0",
        readiness_timeout_seconds=0.5,
    )

    assert await health.check_postgres(settings) is False
    assert await health.check_redis(settings) is False


def test_security_headers_present(client: TestClient) -> None:
    response = client.get("/health")

    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]


def test_cors_wildcard_is_rejected() -> None:
    with pytest.raises(ValueError, match="explicit allowlist"):
        Settings(
            database_url="postgresql://x:x@db/x",
            redis_url="redis://redis/0",
            cors_origins="*",
        )

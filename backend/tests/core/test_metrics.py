"""/metrics (ADR 0016): off without a token, bearer-protected, bounded labels.

These tests run without Postgres and Redis, so the business metrics report
both dependencies as down: that path (a scrape never 500s) is part of the
contract. Real numbers are covered in tests/integration/test_metrics.py.
"""

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.config import Settings, get_settings
from app.main import create_app

TOKEN = "t" * 40
# One directory per test process: prometheus_client binds its multiprocess
# files to the first directory it sees.
METRICS_DIR = Path("/tmp/sentinel-test-metrics")  # noqa: S108


@pytest.fixture
def metrics_client(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    monkeypatch.setenv("METRICS_TOKEN", TOKEN)
    monkeypatch.setenv("METRICS_MULTIPROC_DIR", str(METRICS_DIR))
    get_settings.cache_clear()
    with TestClient(create_app()) as client:
        yield client
    monkeypatch.undo()
    get_settings.cache_clear()


def auth(token: str = TOKEN) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_off_without_a_token(client: TestClient) -> None:
    response = client.get("/metrics", headers=auth())
    assert response.status_code == 404


@pytest.mark.parametrize(
    "headers",
    [{}, auth("wrong" * 10), {"Authorization": f"Basic {TOKEN}"}, {"Authorization": TOKEN}],
)
def test_refuses_without_the_right_bearer_token(
    metrics_client: TestClient, headers: dict[str, str]
) -> None:
    response = metrics_client.get("/metrics", headers=headers)
    assert response.status_code == 401
    assert TOKEN not in response.text
    assert response.json()["error"]["code"] == "authentication_required"


def test_exposes_http_metrics_by_route_template(metrics_client: TestClient) -> None:
    metrics_client.get("/health")
    metrics_client.get("/api/v1/runs/0190a8b4-0000-7000-8000-000000000000")  # 401, templated

    response = metrics_client.get("/metrics", headers=auth())

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    body = response.text
    assert 'sentinel_http_requests_total{method="GET",route="/health",status="2xx"}' in body
    assert 'route="/api/v1/runs/{run_id}"' in body
    assert "0190a8b4" not in body  # identifiers never become labels
    assert "sentinel_http_request_duration_seconds_bucket" in body
    assert 'route="/metrics"' not in body  # scrapes do not count themselves


def test_dependencies_down_still_answers(metrics_client: TestClient) -> None:
    body = metrics_client.get("/metrics", headers=auth()).text

    assert 'sentinel_dependency_up{component="postgres"} 0.0' in body
    assert 'sentinel_dependency_up{component="redis"} 0.0' in body


def test_short_tokens_are_refused_and_empty_disables() -> None:
    base = {"database_url": "postgresql://u:p@h/d", "redis_url": "redis://h"}
    with pytest.raises(ValidationError, match="at least 32"):
        Settings(**base, metrics_token="short")  # type: ignore[arg-type]
    assert Settings(**base, metrics_token="").metrics_token is None  # type: ignore[arg-type]

"""/metrics against real Postgres and Redis (ADR 0016): business metrics match the data."""

import re
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.config import get_settings
from app.core.auth.roles import Role
from app.core.runs.dispatch import get_dispatcher
from tests.core.test_metrics import METRICS_DIR, TOKEN
from tests.integration.conftest import Database, csrf, login


class Captured:
    def send(self, item_id: Any, *_: Any) -> str:
        return f"task-{item_id}"

    def revoke(self, task_id: str) -> None:
        return None


@pytest.fixture
def app(monkeypatch: pytest.MonkeyPatch) -> Iterator[FastAPI]:
    monkeypatch.setenv("METRICS_TOKEN", TOKEN)
    monkeypatch.setenv("METRICS_MULTIPROC_DIR", str(METRICS_DIR))
    get_settings.cache_clear()
    from app.main import create_app

    application = create_app()
    application.dependency_overrides[get_dispatcher] = Captured
    yield application
    monkeypatch.undo()
    get_settings.cache_clear()


def value(body: str, series: str) -> float:
    match = re.search(rf"^{re.escape(series)} (\S+)$", body, re.MULTILINE)
    assert match, f"{series} not in metrics"
    return float(match.group(1))


def test_business_metrics_reflect_the_database(
    client: TestClient, db: Database, make_user: Callable[..., Any]
) -> None:
    make_user("ana", Role.ANALYST)
    login(client, "ana")
    for _ in range(2):
        response = client.post(
            "/api/v1/tools/echo/runs", json={"params": {"message": "hi"}}, headers=csrf(client)
        )
        assert response.status_code == 202, response.text
    db.execute(
        "UPDATE tool_runs SET status = 'COMPLETED', duration_ms = 1500, completed_at = now()"
    )

    body = client.get("/metrics", headers={"Authorization": f"Bearer {TOKEN}"}).text

    assert value(body, 'sentinel_tool_runs{status="COMPLETED",tool_id="echo"}') == 2
    assert value(body, 'sentinel_tool_run_duration_seconds_sum{tool_id="echo"}') == 3.0
    assert value(body, 'sentinel_tool_run_duration_seconds_count{tool_id="echo"}') == 2
    assert value(body, 'sentinel_tool_run_duration_p95_seconds{tool_id="echo"}') == 1.5
    assert value(body, 'sentinel_queue_depth{queue="default"}') == 0
    assert value(body, 'sentinel_dependency_up{component="postgres"}') == 1
    assert value(body, 'sentinel_dependency_up{component="redis"}') == 1
    assert value(body, "sentinel_audit_events") >= 3  # login + two run requests

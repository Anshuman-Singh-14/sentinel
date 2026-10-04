"""Threat intel end to end on real Postgres and Redis (Phase 8 acceptance).

Provider APIs are mocked with httpx.MockTransport (no network): the tool's
``http_transport`` test seam routes its client there. Everything else is
real: API, run service, worker body, Redis cache and rate window, audit.

ADR 0009 checklist for Phase 8: the Web Defensive Audit's intel step now
runs, and the Phase 13 exporters render the new tool's findings.
"""

import csv
import io
import json
import uuid
from collections.abc import Callable, Coroutine, Iterator
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel, ConfigDict

from app.config import get_settings
from app.core.auth.roles import Role
from app.core.runs import events
from app.core.runs.dispatch import get_dispatcher
from app.core.tasks.tool_task import execute_run
from app.db import session as db_session
from app.engine.base_tool import BaseTool, RawOutput, ToolContext
from app.engine.registry import registry
from app.engine.schemas import Finding, ToolCategory
from app.playbooks.dispatch import get_playbook_dispatcher
from app.playbooks.engine import execute_playbook
from app.playbooks.loader import definitions, describe, get_definition
from app.playbooks.schemas import PlaybookDefinition
from app.reports.dispatch import get_report_dispatcher
from app.reports.generate import generate_report
from app.tools.threat_intel.tool import ThreatIntelTool
from tests.integration.conftest import Database, csrf, login, run

ABUSE_KEY = "abuse-integration-key-123456"
VT_KEY = "vt-integration-key-123456"
PUBLIC_IP = "45.33.32.156"


def abuse(score: int) -> dict[str, Any]:
    return {
        "data": {
            "abuseConfidenceScore": score,
            "totalReports": 40,
            "numDistinctUsers": 9,
            "lastReportedAt": "2026-10-03T21:14:00+00:00",
            "countryCode": "US",
            "isp": "Example",
        }
    }


def vt(malicious: int) -> dict[str, Any]:
    stats = {"malicious": malicious, "suspicious": 0, "harmless": 60, "undetected": 10}
    return {"data": {"attributes": {"last_analysis_stats": stats}}}


class MockProviders:
    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.status = {"api.abuseipdb.com": 200, "www.virustotal.com": 200}

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        host = request.url.host
        status = self.status.get(host, 404)
        if status != 200:
            return httpx.Response(status, json={"error": "down"})
        body = abuse(90) if host == "api.abuseipdb.com" else vt(malicious=1)
        return httpx.Response(200, json=body)


class Captured:
    def __init__(self) -> None:
        self.sent: list[uuid.UUID] = []

    def send(self, item_id: uuid.UUID, *_: Any) -> str:
        self.sent.append(item_id)
        return f"task-{item_id}"

    def revoke(self, task_id: str) -> None:
        return None


class NoParams(BaseModel):
    model_config = ConfigDict(extra="forbid")


class FakeDnsTool(BaseTool[NoParams]):
    """Stands in for dns_lookup (no network in tests): yields resolved IPs."""

    tool_id = "ti_fake_dns"
    name = "Fake DNS"
    description = "test"
    version = "1.0.0"
    category = ToolCategory.RECON
    params_model = NoParams

    async def run(self, params: NoParams, ctx: ToolContext) -> RawOutput:
        return {"resolved_ips": [PUBLIC_IP, "10.20.30.40"]}

    def translate(self, raw: RawOutput, params: NoParams) -> list[Finding]:
        return []


PLAYBOOK = PlaybookDefinition.model_validate(
    {
        "id": "ti_audit",
        "name": "Intel playbook",
        "version": "1.0.0",
        "description": "test",
        "target_input": "target",
        "inputs": {"target": {"kind": "string", "title": "Target"}},
        "steps": [
            {"id": "dns", "name": "DNS", "tool_id": "ti_fake_dns"},
            {
                "id": "intel",
                "name": "Threat intelligence",
                "tool_id": "threat_intel",
                # The same reference the shipped Web Defensive Audit uses.
                "params": {"indicators": "{{ steps.dns.resolved_ips }}"},
                "optional": True,
                "on_failure": "continue",
            },
        ],
    }
)


@pytest.fixture(autouse=True)
def registrations() -> Iterator[None]:
    registry.register(FakeDnsTool)
    definitions()[PLAYBOOK.id] = PLAYBOOK
    yield
    definitions().pop(PLAYBOOK.id, None)
    registry._tools.pop(FakeDnsTool.tool_id, None)


@pytest.fixture
def providers(monkeypatch: pytest.MonkeyPatch) -> Iterator[MockProviders]:
    """AbuseIPDB and VirusTotal configured (Shodan not), traffic mocked."""
    mock = MockProviders()
    monkeypatch.setenv("ABUSEIPDB_API_KEY", ABUSE_KEY)
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", VT_KEY)
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    get_settings.cache_clear()
    ThreatIntelTool.http_transport = httpx.MockTransport(mock)
    yield mock
    ThreatIntelTool.http_transport = None
    monkeypatch.undo()
    get_settings.cache_clear()


@pytest.fixture
def no_providers(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in ("ABUSEIPDB_API_KEY", "VIRUSTOTAL_API_KEY", "SHODAN_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    get_settings.cache_clear()
    yield
    monkeypatch.undo()
    get_settings.cache_clear()


@pytest.fixture
def dispatchers(app: FastAPI) -> Iterator[None]:
    for dependency in (get_dispatcher, get_playbook_dispatcher, get_report_dispatcher):
        app.dependency_overrides[dependency] = Captured
    yield
    for dependency in (get_dispatcher, get_playbook_dispatcher, get_report_dispatcher):
        app.dependency_overrides.pop(dependency, None)


@pytest.fixture
def analyst(client: TestClient, make_user: Callable[..., Any], dispatchers: None) -> Any:
    user_id = make_user("ana", Role.ANALYST)
    assert login(client, "ana").status_code == 200
    return user_id


def as_worker[T](factory: Callable[[], Coroutine[Any, Any, T]]) -> T:
    saved = (db_session._engine, db_session._sessionmaker)
    saved_redis = (events._client, events._client_loop)
    db_session.forget_engine()
    events.forget_client()

    async def go() -> T:
        try:
            return await factory()
        finally:
            await db_session.dispose_engine()
            await events.close_redis()

    try:
        return run(go())
    finally:
        db_session._engine, db_session._sessionmaker = saved
        events._client, events._client_loop = saved_redis


def start_intel(client: TestClient, indicators: str) -> Any:
    return client.post(
        "/api/v1/tools/threat_intel/runs",
        json={"params": {"indicators": indicators}},
        headers=csrf(client),
    )


# --- tests -------------------------------------------------------------------------------


def test_catalogue_reports_which_providers_are_configured(
    client: TestClient, analyst: Any, providers: MockProviders
) -> None:
    tools = {t["tool_id"]: t for t in client.get("/api/v1/tools").json()}
    intel = tools["threat_intel"]
    assert intel["available"] is True and intel["category"] == "INTEL"
    status = {p["id"]: p["configured"] for p in intel["status"]["providers"]}
    assert status == {"abuseipdb": True, "virustotal": True, "shodan": False}
    assert ABUSE_KEY not in json.dumps(intel) and VT_KEY not in json.dumps(intel)
    assert tools["echo"]["available"] is True  # tools without requirements are unaffected


def test_lookup_end_to_end_with_partial_privacy_and_cache(
    client: TestClient, db: Database, analyst: Any, providers: MockProviders
) -> None:
    response = start_intel(client, f"{PUBLIC_IP}, example.com, 10.0.0.9")
    assert response.status_code == 202, response.text
    run_id = response.json()["run_id"]
    assert response.json()["target"] == f"{PUBLIC_IP} (+2 more)"
    assert as_worker(lambda: execute_run(uuid.UUID(run_id))) == "COMPLETED"

    detail = client.get(f"/api/v1/runs/{run_id}").json()
    items = [f["item"] for f in detail["findings"]]
    assert items[0] == f"{PUBLIC_IP} is flagged by AbuseIPDB (abuse score 90/100, 40 report(s))"
    assert detail["findings"][0]["severity"] == "HIGH"
    assert any(i.startswith("example.com is flagged by VirusTotal") for i in items)
    assert any(i.startswith("10.0.0.9 was not looked up") for i in items)
    # 3 lookups: the IP on both providers, the domain on VirusTotal. Never the private IP.
    assert len(providers.requests) == 3
    assert all("10.0.0.9" not in str(r.url) for r in providers.requests)
    # Keys never reach storage.
    stored = json.dumps(db.execute("SELECT raw_data, errors FROM tool_runs")[0], default=str)
    assert ABUSE_KEY not in stored and VT_KEY not in stored
    assert db.audit("tool.run.completed")[0]["details"]["tool_id"] == "threat_intel"

    # Same indicators again: answered from the Redis cache, no provider traffic.
    again = start_intel(client, f"{PUBLIC_IP}, example.com").json()["run_id"]
    assert as_worker(lambda: execute_run(uuid.UUID(again))) == "COMPLETED"
    assert len(providers.requests) == 3
    raw = client.get(f"/api/v1/runs/{again}").json()["raw_data"]
    assert raw["cache_hits"] == 3 and raw["requests_made"] == 0


def test_one_provider_down_gives_partial_results(
    client: TestClient, analyst: Any, providers: MockProviders
) -> None:
    providers.status["www.virustotal.com"] = 503
    run_id = start_intel(client, PUBLIC_IP).json()["run_id"]
    assert as_worker(lambda: execute_run(uuid.UUID(run_id))) == "COMPLETED"
    detail = client.get(f"/api/v1/runs/{run_id}").json()
    assert [e["code"] for e in detail["errors"]] == ["provider_rate_limited"]
    assert detail["errors"][0]["message"].startswith("VirusTotal:")
    assert any("AbuseIPDB" in f["item"] for f in detail["findings"])


def test_every_provider_down_fails_the_run(
    client: TestClient, analyst: Any, providers: MockProviders
) -> None:
    providers.status = {"api.abuseipdb.com": 500, "www.virustotal.com": 401}
    run_id = start_intel(client, PUBLIC_IP).json()["run_id"]
    assert as_worker(lambda: execute_run(uuid.UUID(run_id))) == "FAILED"
    errors = client.get(f"/api/v1/runs/{run_id}").json()["errors"]
    # Each provider's own reason is kept, then the overall failure.
    codes = [e["code"] for e in errors]
    assert sorted(codes[:-1]) == ["provider_auth", "provider_http_error"]  # concurrent: any order
    assert codes[-1] == "provider_error"
    final = errors[-1]["message"]
    assert "AbuseIPDB" in final and "rejected the API key" in final


def test_without_keys_the_tool_is_unavailable_and_playbooks_skip_it(
    client: TestClient, db: Database, analyst: Any, no_providers: None
) -> None:
    intel = {t["tool_id"]: t for t in client.get("/api/v1/tools").json()}["threat_intel"]
    assert intel["available"] is False and "ABUSEIPDB_API_KEY" in intel["unavailable_reason"]
    refused = start_intel(client, PUBLIC_IP)
    assert refused.status_code == 409
    assert "No threat-intelligence provider" in refused.json()["error"]["message"]
    assert db.execute("SELECT count(*) AS n FROM tool_runs")[0]["n"] == 0

    shipped = describe(get_definition("web_defensive_audit"))
    step = next(s for s in shipped.steps if s.id == "intel")
    assert step.available is False and "ABUSEIPDB_API_KEY" in (step.unavailable_reason or "")
    assert shipped.available is True  # the step is optional

    started = client.post(
        f"/api/v1/playbooks/{PLAYBOOK.id}/runs",
        json={"inputs": {"target": "x"}},
        headers=csrf(client),
    )
    playbook_run_id = started.json()["playbook_run_id"]
    assert as_worker(lambda: execute_playbook(uuid.UUID(playbook_run_id))) == "COMPLETED"
    steps = client.get(f"/api/v1/playbook-runs/{playbook_run_id}").json()["steps"]
    intel_step = next(s for s in steps if s["step_id"] == "intel")
    assert intel_step["status"] == "SKIPPED"
    assert intel_step["error"]["code"] == "tool_unavailable"


def test_playbook_intel_step_runs_and_exports(
    client: TestClient, analyst: Any, providers: MockProviders
) -> None:
    shipped = describe(get_definition("web_defensive_audit"))
    assert next(s for s in shipped.steps if s.id == "intel").available is True

    started = client.post(
        f"/api/v1/playbooks/{PLAYBOOK.id}/runs",
        json={"inputs": {"target": "x"}},
        headers=csrf(client),
    )
    playbook_run_id = started.json()["playbook_run_id"]
    assert as_worker(lambda: execute_playbook(uuid.UUID(playbook_run_id))) == "COMPLETED"
    detail = client.get(f"/api/v1/playbook-runs/{playbook_run_id}").json()
    intel_step = next(s for s in detail["steps"] if s["step_id"] == "intel")
    assert intel_step["status"] == "COMPLETED"
    # The reference resolved to the DNS step's list, private address included.
    assert intel_step["resolved_params"] == {"indicators": [PUBLIC_IP, "10.20.30.40"]}
    top = detail["findings"][0]
    assert top["step_id"] == "intel" and top["severity"] == "HIGH"

    # Phase 13 exporters render the new findings without changes.
    for fmt in ("pdf", "csv"):
        report_id = client.post(
            "/api/v1/reports",
            json={"source_type": "playbook_run", "source_id": playbook_run_id, "format": fmt},
            headers=csrf(client),
        ).json()["report_id"]
        rid = uuid.UUID(report_id)
        assert as_worker(lambda: generate_report(rid)) == "COMPLETED"  # noqa: B023
        content = client.get(f"/api/v1/reports/{report_id}/download").content
        if fmt == "pdf":
            assert content.startswith(b"%PDF-")
        else:
            rows = list(csv.DictReader(io.StringIO(content.decode("utf-8-sig"))))
            assert rows[0]["source"] == "intel" and "AbuseIPDB" in rows[0]["item"]

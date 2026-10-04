"""Orchestration: concurrency, partial results, cache, privacy, translation."""

import asyncio
import json
import os
from typing import Any

import httpx
import pytest

from app.config import get_settings
from app.engine.base_tool import ToolContext
from app.engine.schemas import Confidence, Severity
from app.tools.threat_intel import providers as provider_registry
from app.tools.threat_intel import service, translator
from app.tools.threat_intel.indicators import classify
from app.tools.threat_intel.providers.base import ProviderHttp
from app.tools.threat_intel.tests.fakes import (
    ALL_KEYS,
    SHODAN_HOST,
    MemoryCache,
    OpenLimiter,
    Recorder,
    abuse_payload,
    abuseipdb,
    context,
    http_for,
    json_response,
    shodan,
    virustotal,
    vt_payload,
)
from app.tools.threat_intel.tool import ThreatIntelTool

INDICATORS = [classify(v) for v in ("45.33.32.156", "example.com", "10.0.0.8")]


def routes() -> dict[str, object]:
    return {
        "abuse.test": lambda r: json_response(abuse_payload(92)),
        "vt.test": lambda r: json_response(vt_payload(malicious=1)),
        "shodan.test": lambda r: json_response(SHODAN_HOST),
    }


async def run(
    recorder: Recorder, cache: MemoryCache | None = None, limit_seconds: float = 5.0
) -> tuple[dict[str, Any], ToolContext]:
    ctx = context()
    raw = await service.investigate(
        INDICATORS,
        [abuseipdb(), virustotal(), shodan()],
        http_for(recorder),
        cache or MemoryCache(),
        ctx,
        timeout_seconds=limit_seconds,
        cache_ttl_seconds=60,
    )
    return raw, ctx


async def test_all_supported_pairs_are_looked_up_and_private_ips_never_sent() -> None:
    recorder = Recorder(routes())  # type: ignore[arg-type]
    raw, ctx = await run(recorder)
    # IP: 3 providers; domain: VirusTotal only; 10.0.0.8: nobody.
    assert raw["lookups_planned"] == 4 and len(raw["results"]) == 4 and ctx.errors == []
    sent = " ".join(str(r.url) for r in recorder.requests)
    assert "10.0.0.8" not in sent
    assert [(r["indicator"], r["provider"]) for r in raw["results"]] == [
        ("45.33.32.156", "abuseipdb"),
        ("45.33.32.156", "virustotal"),
        ("45.33.32.156", "shodan"),
        ("example.com", "virustotal"),
    ]
    assert not any(key in json.dumps(raw) for key in ALL_KEYS)


async def test_one_failing_provider_gives_partial_results() -> None:
    table = routes()
    table["vt.test"] = lambda r: json_response({}, 500)
    raw, ctx = await run(Recorder(table))  # type: ignore[arg-type]
    assert {r["provider"] for r in raw["results"]} == {"abuseipdb", "shodan"}
    assert len(raw["failures"]) == 2  # the IP and the domain
    assert [e.code for e in ctx.errors] == ["provider_http_error"]
    assert (
        ctx.errors[0].message.startswith("VirusTotal:") and "2 lookup(s)" in ctx.errors[0].message
    )


async def test_slow_provider_times_out_without_blocking_the_others() -> None:
    class SlowTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            if request.url.host == "shodan.test":
                await asyncio.sleep(5)
            return Recorder(routes())(request)  # type: ignore[arg-type]

    ctx = context()
    client = httpx.AsyncClient(transport=SlowTransport(), timeout=10)
    raw = await service.investigate(
        INDICATORS,
        [abuseipdb(), virustotal(), shodan()],
        ProviderHttp(client, OpenLimiter()),
        MemoryCache(),
        ctx,
        timeout_seconds=0.2,
        cache_ttl_seconds=60,
    )
    assert {r["provider"] for r in raw["results"]} == {"abuseipdb", "virustotal"}
    assert raw["failures"][0]["code"] == "timeout"


async def test_cache_answers_repeat_lookups() -> None:
    cache = MemoryCache()
    first = Recorder(routes())  # type: ignore[arg-type]
    await run(first, cache)
    second = Recorder(routes())  # type: ignore[arg-type]
    raw, _ = await run(second, cache)
    assert second.requests == [] and raw["cache_hits"] == 4 and len(raw["results"]) == 4


async def test_translation_names_the_source_and_applies_documented_severities() -> None:
    raw, _ = await run(Recorder(routes()))  # type: ignore[arg-type]
    findings = translator.translate(raw)
    by_item = {f.item: f for f in findings}
    abuse = by_item["45.33.32.156 is flagged by AbuseIPDB (abuse score 92/100, 12 report(s))"]
    assert abuse.severity is Severity.HIGH and abuse.confidence is Confidence.HIGH
    assert "score >= 75 is HIGH" in abuse.severity_rationale
    assert abuse.evidence["source"] == "AbuseIPDB"
    assert abuse.references[0] == "https://www.abuseipdb.com/check/45.33.32.156"
    vt = next(f for f in findings if f.item.startswith("example.com is flagged by VirusTotal"))
    assert vt.severity is Severity.MEDIUM and vt.confidence is Confidence.LOW
    shodan_finding = next(f for f in findings if "Shodan associates 2 CVE(s)" in f.item)
    assert shodan_finding.severity is Severity.MEDIUM
    assert shodan_finding.confidence is Confidence.LOW
    assert any(f.item.startswith("10.0.0.8 was not looked up") for f in findings)
    assert findings[0].severity is Severity.HIGH  # sorted most severe first
    # Every non-summary finding names its source.
    for finding in findings:
        if finding.category != "THREAT_INTEL" or "indicator(s) checked" in finding.item:
            continue
        if "not looked up" in finding.item:
            continue
        assert finding.evidence.get("source")


@pytest.mark.parametrize(
    ("score", "severity"),
    [(0, Severity.INFO), (5, Severity.LOW), (40, Severity.MEDIUM), (75, Severity.HIGH)],
)
async def test_abuseipdb_severity_bands(score: int, severity: Severity) -> None:
    recorder = Recorder({"abuse.test": lambda r: json_response(abuse_payload(score))})
    raw = await service.investigate(
        [INDICATORS[0]],
        [abuseipdb()],
        http_for(recorder),
        MemoryCache(),
        context(),
        timeout_seconds=5,
        cache_ttl_seconds=60,
    )
    finding = next(f for f in translator.translate(raw) if "AbuseIPDB" in f.item)
    assert finding.severity is severity


def test_availability_follows_configured_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    # Settings need these even though nothing connects (tests/conftest.py sets them
    # only for tests under tests/).
    monkeypatch.setenv("DATABASE_URL", os.environ.get("DATABASE_URL", "postgresql://t:t@h:1/t"))
    monkeypatch.setenv("REDIS_URL", os.environ.get("REDIS_URL", "redis://h:1/0"))
    for name in ("ABUSEIPDB_API_KEY", "VIRUSTOTAL_API_KEY", "SHODAN_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    get_settings.cache_clear()
    try:
        none = ThreatIntelTool.availability()
        assert not none.available and "ABUSEIPDB_API_KEY" in (none.reason or "")
        assert [p["configured"] for p in none.details["providers"]] == [False, False, False]
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "a-real-looking-key")
        get_settings.cache_clear()
        some = ThreatIntelTool.availability()
        assert some.available
        assert {p["id"]: p["configured"] for p in some.details["providers"]}["virustotal"]
        assert "a-real-looking-key" not in json.dumps(some.details)
        assert [p.provider_id for p in provider_registry.configured(get_settings())] == [
            "virustotal"
        ]
    finally:
        monkeypatch.undo()
        get_settings.cache_clear()

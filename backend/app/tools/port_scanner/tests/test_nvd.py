"""NVD client against httpx.MockTransport: no network in unit tests."""

from typing import Any

import httpx
import pytest

from app.tools.port_scanner import nvd
from app.tools.port_scanner.nvd import NvdClient, NvdUnavailable, parse_response

CPE = "cpe:2.3:a:beasts:vsftpd:2.3.4"


def cve(cve_id: str, score: float | None, version: str = "V31", **extra: Any) -> dict[str, Any]:
    metrics: dict[str, Any] = {}
    if score is not None:
        key = {"V31": "cvssMetricV31", "V30": "cvssMetricV30", "V2": "cvssMetricV2"}[version]
        metrics[key] = [
            {"type": "Primary", "cvssData": {"baseScore": score, "vectorString": "AV:N"}}
        ]
    return {
        "cve": {
            "id": cve_id,
            "descriptions": [
                {"lang": "es", "value": "x"},
                {"lang": "en", "value": f"{cve_id} desc"},
            ],
            "metrics": metrics,
            "published": "2011-07-07T00:00:00",
            **extra,
        }
    }


PAYLOAD = {
    "vulnerabilities": [
        cve("CVE-2011-2523", 9.8),
        cve("CVE-2000-0001", 5.0, "V2"),
        cve("CVE-2020-0002", None),
        cve("CVE-2021-0003", 7.5, vulnStatus="Rejected"),
        {"cve": {"id": "not-a-cve"}},
    ]
}


class MemoryCache:
    def __init__(self) -> None:
        self.data: dict[str, str] = {}

    async def get(self, key: str) -> str | None:
        return self.data.get(key)

    async def set(self, key: str, value: str, ttl_seconds: int) -> None:
        self.data[key] = value


class Limiter:
    def __init__(self, waits: list[float] | None = None) -> None:
        self.waits = waits or []
        self.calls = 0

    async def try_acquire(self, key: str, limit: int, window_seconds: int) -> float:
        self.calls += 1
        return self.waits.pop(0) if self.waits else 0.0


def client(handler: Any, *, cache: MemoryCache | None = None, limiter: Limiter | None = None,
           api_key: str | None = None) -> NvdClient:  # fmt: skip
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return NvdClient(
        http,
        cache or MemoryCache(),
        limiter or Limiter(),
        base_url="https://nvd.test/cves",
        api_key=api_key,
        cache_ttl_seconds=3600,
    )


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    slept: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        slept.append(seconds)

    monkeypatch.setattr("app.tools.port_scanner.nvd.asyncio.sleep", fake_sleep)
    return slept


def test_parse_sorts_by_score_and_drops_rejected() -> None:
    records = parse_response(PAYLOAD)
    assert [r.cve_id for r in records] == ["CVE-2011-2523", "CVE-2000-0001", "CVE-2020-0002"]
    assert records[0].score == 9.8 and records[0].cvss_version == "3.1"
    assert records[1].cvss_version == "2.0"
    assert records[2].score is None
    assert records[0].description == "CVE-2011-2523 desc"
    assert records[0].url == "https://nvd.nist.gov/vuln/detail/CVE-2011-2523"


def test_parse_caps_results() -> None:
    many = {"vulnerabilities": [cve(f"CVE-2020-{i:04d}", 5.0) for i in range(50)]}
    assert len(parse_response(many)) == nvd.MAX_CVES_PER_PRODUCT


async def test_query_then_cache() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=PAYLOAD)

    cache = MemoryCache()
    c = client(handler, cache=cache, api_key="k3y")
    records, cached = await c.cves_for(CPE)
    assert not cached and records[0].cve_id == "CVE-2011-2523"
    assert seen[0].url.params["virtualMatchString"] == CPE
    assert seen[0].headers["apiKey"] == "k3y"
    records2, cached2 = await c.cves_for(CPE)
    assert cached2 and records2 == records
    assert len(seen) == 1


async def test_empty_answers_are_cached_too() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"vulnerabilities": []})

    c = client(handler)
    assert (await c.cves_for(CPE))[0] == []
    assert (await c.cves_for(CPE))[1] is True
    assert calls == 1


async def test_throttling_is_retried_with_retry_after(no_sleep: list[float]) -> None:
    responses = [
        httpx.Response(403, headers={"Retry-After": "4"}),
        httpx.Response(200, json=PAYLOAD),
    ]
    c = client(lambda request: responses.pop(0))
    records, _ = await c.cves_for(CPE)
    assert records and no_sleep == [4.0]


async def test_persistent_throttling_gives_up() -> None:
    c = client(lambda request: httpx.Response(429))
    with pytest.raises(NvdUnavailable, match="HTTP 429"):
        await c.cves_for(CPE)


@pytest.mark.parametrize("status", [500, 401])
async def test_errors_are_unavailable(status: int) -> None:
    with pytest.raises(NvdUnavailable, match=f"HTTP {status}"):
        await client(lambda request: httpx.Response(status)).cves_for(CPE)


async def test_network_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("slow")

    with pytest.raises(NvdUnavailable, match="could not be reached"):
        await client(handler).cves_for(CPE)


async def test_garbage_json() -> None:
    with pytest.raises(NvdUnavailable, match="unreadable"):
        await client(lambda request: httpx.Response(200, content=b"<html>")).cves_for(CPE)


async def test_unknown_cpe_404_means_no_cves() -> None:
    assert (await client(lambda request: httpx.Response(404)).cves_for(CPE))[0] == []


async def test_rate_window_waits_then_proceeds(no_sleep: list[float]) -> None:
    limiter = Limiter(waits=[12.0])
    records, _ = await client(
        lambda r: httpx.Response(200, json=PAYLOAD), limiter=limiter
    ).cves_for(CPE)
    assert records and no_sleep == [12.0] and limiter.calls == 2


async def test_rate_window_too_long_gives_up() -> None:
    limiter = Limiter(waits=[45.0])
    with pytest.raises(NvdUnavailable, match="quota"):
        await client(lambda r: httpx.Response(200, json=PAYLOAD), limiter=limiter).cves_for(CPE)


def test_window_limit_depends_on_key() -> None:
    assert client(lambda r: httpx.Response(200)).window_limit == 4
    assert client(lambda r: httpx.Response(200), api_key="k").window_limit == 49

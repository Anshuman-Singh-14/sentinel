"""Each provider against a mocked API: parsing, 404, 429 handling, errors, key safety."""

import httpx
import pytest

from app.tools.threat_intel.indicators import classify
from app.tools.threat_intel.providers.base import ProviderError, Verdict, backoff_delay
from app.tools.threat_intel.tests.fakes import (
    ABUSE_KEY,
    ALL_KEYS,
    SHODAN_HOST,
    SHODAN_KEY,
    VT_KEY,
    FullLimiter,
    Recorder,
    abuse_payload,
    abuseipdb,
    http_for,
    json_response,
    shodan,
    virustotal,
    vt_payload,
)

IP = classify("45.33.32.156")


async def test_abuseipdb_parses_and_authenticates_with_a_header() -> None:
    recorder = Recorder({"abuse.test": lambda r: json_response(abuse_payload(92))})
    rep = await abuseipdb().lookup(http_for(recorder), IP)
    assert (rep.verdict, rep.score) == (Verdict.MALICIOUS, 92)
    assert rep.details["total_reports"] == 12 and (rep.link or "").endswith("/check/45.33.32.156")
    request = recorder.requests[0]
    assert request.headers["Key"] == ABUSE_KEY
    assert ABUSE_KEY not in str(request.url)
    assert request.url.params["ipAddress"] == "45.33.32.156"


@pytest.mark.parametrize(
    ("score", "verdict"), [(0, Verdict.HARMLESS), (10, Verdict.SUSPICIOUS), (80, Verdict.MALICIOUS)]
)
async def test_abuseipdb_verdicts(score: int, verdict: Verdict) -> None:
    recorder = Recorder({"abuse.test": lambda r: json_response(abuse_payload(score))})
    assert (await abuseipdb().lookup(http_for(recorder), IP)).verdict is verdict


async def test_virustotal_ip_domain_and_hash_paths() -> None:
    recorder = Recorder({"vt.test": lambda r: json_response(vt_payload(malicious=4))})
    http = http_for(recorder)
    for raw, path, gui in [
        ("45.33.32.156", "/api/v3/ip_addresses/45.33.32.156", "ip-address"),
        ("example.com", "/api/v3/domains/example.com", "domain"),
        ("a" * 64, f"/api/v3/files/{'a' * 64}", "file"),
    ]:
        rep = await virustotal().lookup(http, classify(raw))
        assert recorder.requests[-1].url.path == path
        assert f"/gui/{gui}/" in (rep.link or "")
    assert rep.verdict is Verdict.MALICIOUS and rep.score == 5  # 4 of 74 vendors
    assert rep.categories == ["malicious web sites", "phishing"]
    assert recorder.requests[0].headers["x-apikey"] == VT_KEY


async def test_not_found_is_a_result_not_an_error() -> None:
    recorder = Recorder(
        {
            "vt.test": lambda r: json_response({"error": {"code": "NotFoundError"}}, 404),
            "shodan.test": lambda r: json_response({"error": "No information available"}, 404),
        }
    )
    http = http_for(recorder)
    assert (await virustotal().lookup(http, IP)).verdict is Verdict.NOT_FOUND
    assert (await shodan().lookup(http, IP)).verdict is Verdict.NOT_FOUND


async def test_shodan_exposure_details() -> None:
    recorder = Recorder({"shodan.test": lambda r: json_response(SHODAN_HOST)})
    rep = await shodan().lookup(http_for(recorder), IP)
    assert rep.verdict is Verdict.UNKNOWN and rep.score is None
    assert rep.details["open_ports"] == [22, 80, 443, 3306]
    assert rep.details["vulns"] == ["CVE-2021-41617", "CVE-2023-38408"]
    # Shodan takes the key in the query string; it must never surface anywhere else.
    assert recorder.requests[0].url.params["key"] == SHODAN_KEY


async def test_429_is_retried_honouring_retry_after_then_succeeds() -> None:
    answers = iter(
        [json_response({}, 429, **{"Retry-After": "2"}), json_response(abuse_payload(30))]
    )
    recorder = Recorder({"abuse.test": lambda r: next(answers)})
    waits: list[float] = []
    http = http_for(recorder)

    async def record_sleep(seconds: float) -> None:
        waits.append(seconds)

    http.sleep = record_sleep
    rep = await abuseipdb().lookup(http, IP)
    assert rep.score == 30 and waits == [2.0] and len(recorder.requests) == 2


async def test_persistent_429_becomes_a_rate_limited_error() -> None:
    recorder = Recorder({"abuse.test": lambda r: json_response({}, 429)})
    with pytest.raises(ProviderError) as exc:
        await abuseipdb().lookup(http_for(recorder), IP)
    assert exc.value.code == "rate_limited" and len(recorder.requests) == 3


async def test_full_local_budget_refuses_without_calling_the_provider() -> None:
    recorder = Recorder({"abuse.test": lambda r: json_response(abuse_payload(0))})
    with pytest.raises(ProviderError) as exc:
        await abuseipdb().lookup(http_for(recorder, FullLimiter()), IP)
    assert exc.value.code == "rate_limited" and recorder.requests == []


def test_backoff_has_jitter_and_caps() -> None:
    assert backoff_delay(0, "3") == 3.0
    assert backoff_delay(0, "999") == 10.0
    assert all(0 <= backoff_delay(5, None) <= 8.0 for _ in range(50))


@pytest.mark.parametrize(
    ("status", "code"), [(401, "auth"), (403, "auth"), (500, "http_error"), (418, "http_error")]
)
async def test_http_errors_are_user_safe(status: int, code: str) -> None:
    recorder = Recorder({"shodan.test": lambda r: json_response({"error": "x"}, status)})
    with pytest.raises(ProviderError) as exc:
        await shodan().lookup(http_for(recorder), IP)
    assert exc.value.code == code


async def test_network_errors_never_leak_the_url_or_key() -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"cannot connect to {request.url}")  # URL includes the key

    recorder = Recorder({"shodan.test": boom})
    with pytest.raises(ProviderError) as exc:
        await shodan().lookup(http_for(recorder), IP)
    assert exc.value.code == "unreachable"
    for key in ALL_KEYS:
        assert key not in exc.value.message and key not in repr(shodan())


async def test_oversized_and_non_json_answers_are_rejected() -> None:
    big = httpx.Response(200, content=b'{"data": "' + b"x" * 1_100_000 + b'"}')
    recorder = Recorder({"abuse.test": lambda r: big})
    with pytest.raises(ProviderError) as exc:
        await abuseipdb().lookup(http_for(recorder), IP)
    assert exc.value.code == "too_large"
    recorder = Recorder({"abuse.test": lambda r: httpx.Response(200, content=b"<html>")})
    with pytest.raises(ProviderError) as exc:
        await abuseipdb().lookup(http_for(recorder), IP)
    assert exc.value.code == "bad_response"

"""Acceptance: correct findings against fixture servers (Phase 7).

Each test starts a real HTTP or HTTPS server on 127.0.0.1 and runs the tool
exactly as the worker would: pinned to the approved address, with a scope
check for any redirect target. The only swaps are the trust store (a private
test CA instead of the system CAs) and the allowed-port list (the fixtures
use random ports).
"""

import json
import ssl
import uuid
from collections.abc import Iterator
from typing import Any

import pytest
import structlog

from app.config import get_settings
from app.core.errors import ScopeDenied
from app.engine.base_tool import ToolContext
from app.engine.schemas import Finding, FindingStatus, Severity
from app.tools.header_tls import tool as tool_module
from app.tools.header_tls.schemas import HeaderTlsParams
from app.tools.header_tls.tests.fixtures import BAD_HEADERS, GOOD_HEADERS, Certs, make_certs, serve
from app.tools.header_tls.tool import HeaderTlsTool

CERTS: Certs = make_certs()


@pytest.fixture(autouse=True)
def test_trust_and_ports(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(
        tool_module, "trust_context", lambda: ssl.create_default_context(cafile=str(CERTS.ca))
    )
    settings = get_settings()
    monkeypatch.setattr(settings, "web_check_allowed_ports", [*range(1024, 65536), 80, 443])
    monkeypatch.setattr(settings, "web_check_timeout_seconds", 3.0)
    yield


class Scope:
    def __init__(self, allowed: dict[str, tuple[str, ...]] | None = None) -> None:
        self.allowed = allowed or {}
        self.asked: list[str] = []

    async def __call__(self, host: str) -> tuple[str, ...]:
        self.asked.append(host)
        if host in self.allowed:
            return self.allowed[host]
        raise ScopeDenied(f"{host} is not in the scan scope.")


def ctx(scope: Scope | None = None) -> ToolContext:
    return ToolContext(
        run_id=uuid.uuid4(),
        logger=structlog.get_logger(),
        authorized_addresses=("127.0.0.1",),
        scope_check=scope or Scope(),
    )


async def run(url: str, scope: Scope | None = None) -> tuple[dict[str, Any], list[Finding]]:
    params = HeaderTlsParams(url=url, check_http_redirect=False)
    tool = HeaderTlsTool()
    raw = await tool.run(params, ctx(scope))
    return raw, tool.translate(raw, params)


def by_key(findings: list[Finding]) -> dict[str, Finding]:
    return {f.item: f for f in findings}


def severities(findings: list[Finding]) -> list[Severity]:
    return [f.severity for f in findings]


async def test_good_https_site() -> None:
    async with serve(GOOD_HEADERS, pem=CERTS.good) as server:
        raw, findings = await run(f"https://localhost:{server.port}/")
    items = by_key(findings)
    # Pinned to 127.0.0.1, yet every handshake (fetch and TLS inspection) sent the real name.
    assert server.sni_seen and set(server.sni_seen) == {"localhost"}
    assert raw["final"]["url"] == f"https://localhost:{server.port}/"
    assert raw["tls"]["verified"] is True and raw["tls"]["protocol"] in ("TLSv1.2", "TLSv1.3")
    assert (
        items["Valid TLS certificate (" + raw["tls"]["protocol"] + ")"].status is FindingStatus.PASS
    )
    assert "HSTS is enabled" in items and "preload" in items["HSTS is enabled"].remediation
    assert "Content-Security-Policy is enforced" in items
    assert "Clickjacking protection is set" in items
    assert "Cookies use Secure, HttpOnly and SameSite" in items
    # A well-configured site has nothing above INFO.
    assert set(severities(findings)) == {Severity.INFO}, [
        (f.item, f.severity) for f in findings if f.severity is not Severity.INFO
    ]


async def test_bad_http_site() -> None:
    async with serve(BAD_HEADERS) as server:
        _, findings = await run(f"http://localhost:{server.port}/")
    items = by_key(findings)
    # Port 443 on 127.0.0.1 is closed in the test container: no HTTPS at all.
    assert items["The site is not available over HTTPS"].severity is Severity.HIGH
    assert "Strict-Transport-Security (HSTS) is missing" not in items  # HSTS is HTTPS-only
    csp = items["Content-Security-Policy has weaknesses"]
    assert "'unsafe-inline'" in csp.explanation and "wildcard" in csp.explanation
    assert items["No clickjacking protection"].severity is Severity.MEDIUM
    assert items["X-Content-Type-Options is missing"].severity is Severity.LOW
    assert items["Referrer-Policy leaks full URLs"].severity is Severity.LOW
    disclosure = items["Response headers reveal software versions"]
    assert "Apache/2.4.29" in disclosure.explanation and "PHP/7.2.24" in disclosure.explanation
    httponly = items["Cookies readable by JavaScript (no HttpOnly)"]
    assert httponly.severity is Severity.MEDIUM  # "sessionid" looks like a session cookie
    assert items["SameSite=None cookies without Secure"].severity is Severity.MEDIUM
    assert "nginx:" in items["No clickjacking protection"].remediation
    assert "Apache:" in items["No clickjacking protection"].remediation


async def test_cookie_values_are_never_stored() -> None:
    async with serve(BAD_HEADERS) as server:
        raw, findings = await run(f"http://localhost:{server.port}/")
    blob = json.dumps(raw) + json.dumps([f.model_dump(mode="json") for f in findings])
    assert "TOPSECRETVALUE" not in blob
    assert {c["name"] for c in raw["final"]["cookies"]} == {"sessionid", "prefs"}
    assert all(name != "set-cookie" for name, _ in raw["final"]["headers"])


async def test_missing_hsts_on_https() -> None:
    headers = [h for h in GOOD_HEADERS if h[0] != "Strict-Transport-Security"]
    async with serve(headers, pem=CERTS.good) as server:
        _, findings = await run(f"https://localhost:{server.port}/")
    assert (
        by_key(findings)["Strict-Transport-Security (HSTS) is missing"].severity is Severity.MEDIUM
    )


@pytest.mark.parametrize(
    ("pem_name", "expected_item"),
    [
        ("expired", "TLS certificate has expired"),
        ("self_signed", "Self-signed TLS certificate"),
        ("wrong_host", "TLS certificate does not match localhost"),
    ],
)
async def test_certificate_problems(pem_name: str, expected_item: str) -> None:
    async with serve(GOOD_HEADERS, pem=getattr(CERTS, pem_name)) as server:
        raw, findings = await run(f"https://localhost:{server.port}/")
    items = by_key(findings)
    assert items[expected_item].severity is Severity.HIGH
    assert items[expected_item].status is FindingStatus.FAIL
    assert raw["tls"]["verified"] is False
    assert raw["tls"]["cert"] is not None  # details still read for the report
    # Headers were still assessed over the unverified connection.
    assert "HSTS is enabled" in items
    assert raw["hops"][0]["tls_unverified"] is True


async def test_expired_certificate_details() -> None:
    async with serve(GOOD_HEADERS, pem=CERTS.expired) as server:
        raw, findings = await run(f"https://localhost:{server.port}/")
    finding = by_key(findings)["TLS certificate has expired"]
    assert raw["tls"]["cert"]["days_remaining"] < 0
    assert "days ago" in finding.explanation
    assert finding.evidence["issuer"] == "CN=Sentinel Test CA"


async def test_http_redirect_to_https_is_followed_on_the_same_pinned_host() -> None:
    async with serve(GOOD_HEADERS, pem=CERTS.good) as https_server:
        location = f"https://localhost:{https_server.port}/"
        async with serve([("Location", location)], status="301 Moved Permanently") as http_server:
            scope = Scope()
            raw, findings = await run(f"http://localhost:{http_server.port}/", scope)
    assert [h["followed"] for h in raw["hops"]] == [True, False]
    assert raw["final"]["url"] == location
    assert scope.asked == []  # same host: no new resolution, pinned addresses reused
    assert "HSTS is enabled" in by_key(findings)


async def test_redirect_to_out_of_scope_host_is_not_followed() -> None:
    async with serve(
        [("Location", "http://169.254.169.254/latest/meta-data/")], status="302 Found"
    ) as server:
        scope = Scope()
        raw, findings = await run(f"http://localhost:{server.port}/", scope)
    assert scope.asked == ["169.254.169.254"]
    assert raw["final"] is None
    note = by_key(findings)["A redirect was not followed"]
    assert "outside the scan scope" in note.explanation


@pytest.mark.parametrize(
    "location",
    ["file:///etc/passwd", "gopher://localhost:70/", "http://user:pw@localhost/", "ftp://x/"],
)
async def test_redirect_to_disallowed_url_is_not_followed(location: str) -> None:
    async with serve([("Location", location)], status="302 Found") as server:
        raw, _ = await run(f"http://localhost:{server.port}/")
    assert raw["hops"][0]["followed"] is False
    assert raw["hops"][0]["note"].startswith("Not followed")
    assert len(raw["hops"]) == 1


async def test_redirect_loop_stops_at_the_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "web_check_max_redirects", 3)
    async with serve([("Location", "/again")], status="302 Found") as server:
        raw, _ = await run(f"http://localhost:{server.port}/")
    assert len(raw["hops"]) == 4
    assert "Redirect limit" in raw["hops"][-1]["note"]
    assert len(server.requests) == 4


async def test_unreachable() -> None:
    import socket

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    raw, findings = await run(f"http://localhost:{port}/")
    assert raw["final"] is None
    assert findings[0].item.startswith("Could not get a response")


async def test_tool_refuses_without_scope_approval() -> None:
    context = ToolContext(run_id=uuid.uuid4(), logger=structlog.get_logger())
    with pytest.raises(ScopeDenied):
        await HeaderTlsTool().run(HeaderTlsParams(url="https://localhost:8443/"), context)

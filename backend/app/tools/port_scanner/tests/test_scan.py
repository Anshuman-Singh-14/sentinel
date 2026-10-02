"""The scanner against real sockets on 127.0.0.1, plus translation and the tool wrapper."""

import asyncio
import socket
import uuid
from collections.abc import AsyncIterator
from typing import Any

import pytest
import structlog

from app.core.errors import ScopeDenied
from app.engine.base_tool import RunCancelled, ToolContext
from app.engine.schemas import Confidence, Severity
from app.tools.port_scanner import service
from app.tools.port_scanner.schemas import PortScanParams
from app.tools.port_scanner.tool import PortScannerTool, pick_address
from app.tools.port_scanner.translator import translate

CONFIG = service.ScanConfig(
    concurrency=10, connect_timeout=1.0, banner_timeout=0.5, grab_banners=True
)


def ctx(*, cancelled: bool = False, addresses: tuple[str, ...] = ()) -> ToolContext:
    async def cancel() -> bool:
        return cancelled

    return ToolContext(
        run_id=uuid.uuid4(),
        logger=structlog.get_logger(),
        cancel_check=cancel,
        authorized_addresses=addresses,
    )


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture
async def servers() -> AsyncIterator[dict[str, int]]:
    async def ssh(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(b"SSH-2.0-OpenSSH_7.4\r\n")
        await writer.drain()
        writer.close()

    async def http(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        request = await reader.read(1024)
        if request.startswith(b"HEAD / HTTP/1.0"):
            writer.write(b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nX-Secret: no\r\n\r\n")
            await writer.drain()
        writer.close()

    async def silent(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await asyncio.sleep(2)
        writer.close()

    started = [
        await asyncio.start_server(ssh, "127.0.0.1", 0),
        await asyncio.start_server(http, "127.0.0.1", 0),
        await asyncio.start_server(silent, "127.0.0.1", 0),
    ]
    ports = {
        name: s.sockets[0].getsockname()[1]
        for name, s in zip(("ssh", "http", "silent"), started, strict=True)
    }
    ports["closed"] = free_port()
    yield ports
    for s in started:
        s.close()


async def test_scan_finds_open_ports_banners_and_products(
    servers: dict[str, int], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(service, "HTTP_PORTS", frozenset({servers["http"]}))
    raw = await service.scan("127.0.0.1", sorted(servers.values()), CONFIG, ctx())

    by_port = {p["port"]: p for p in raw["open"]}
    assert set(by_port) == {servers["ssh"], servers["http"], servers["silent"]}
    assert raw["closed_count"] == 1 and raw["ports_scanned"] == 4

    ssh = by_port[servers["ssh"]]
    assert ssh["banner"] == "SSH-2.0-OpenSSH_7.4"
    assert ssh["product"]["name"] == "OpenSSH" and ssh["product"]["confidence"] == "MEDIUM"

    http = by_port[servers["http"]]
    # Only the status line and Server header are kept from the HTTP response.
    assert http["banner"] == "HTTP/1.1 200 OK\nServer: nginx/1.18.0"
    assert http["product"]["version"] == "1.18.0"

    assert by_port[servers["silent"]]["banner"] == ""
    assert by_port[servers["silent"]]["product"] is None


async def test_banners_can_be_disabled(servers: dict[str, int]) -> None:
    config = service.ScanConfig(10, 1.0, 0.5, grab_banners=False)
    raw = await service.scan("127.0.0.1", [servers["ssh"]], config, ctx())
    assert raw["open"][0]["banner"] == ""


async def test_unroutable_address_is_filtered() -> None:
    # TEST-NET-1 (RFC 5737) is never routed: connects time out or fail.
    config = service.ScanConfig(10, 0.3, 0.3, grab_banners=True)
    raw = await service.scan("192.0.2.1", [80, 443], config, ctx())
    assert raw["open"] == [] and raw["filtered_count"] + raw["closed_count"] == 2


async def test_cancellation(servers: dict[str, int]) -> None:
    with pytest.raises(RunCancelled):
        await service.scan("127.0.0.1", [servers["ssh"]], CONFIG, ctx(cancelled=True))


async def test_tool_refuses_without_scope_approval() -> None:
    with pytest.raises(ScopeDenied):
        await PortScannerTool().run(PortScanParams(target="lab-web"), ctx())


async def test_tool_scans_the_authorised_address_not_the_name(
    servers: dict[str, int], monkeypatch: pytest.MonkeyPatch
) -> None:
    params = PortScanParams(
        target="name-that-does-not-resolve",
        preset="custom",
        ports=str(servers["ssh"]),
        cve_lookup=False,
    )
    raw = await PortScannerTool().run(params, ctx(addresses=("127.0.0.1",)))
    assert raw["address"] == "127.0.0.1"
    assert raw["open"][0]["port"] == servers["ssh"]
    assert raw["cve_lookup"]["enabled"] is False


def test_pick_address_prefers_ipv4() -> None:
    assert pick_address(("::1", "127.0.0.1")) == "127.0.0.1"
    assert pick_address(("::1",)) == "::1"


# --- translation --------------------------------------------------------------------------


def raw_scan(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "target": "lab-banners",
        "address": "10.231.10.11",
        "ports_scanned": 100,
        "closed_count": 95,
        "filtered_count": 0,
        "open": [
            {"port": 21, "service": "FTP", "exposure": "cleartext_file",
             "banner": "220 (vsFTPd 2.3.4)", "tls": False,
             "product": {"name": "vsftpd", "version": "2.3.4",
             "cpe_candidates": ["cpe:2.3:a:beasts:vsftpd:2.3.4"], "confidence": "MEDIUM",
             "confidence_reason": "Matched on the banner.", "evidence": "vsFTPd 2.3.4"}},
            {"port": 23, "service": "Telnet", "exposure": "cleartext_admin", "banner": "login:",
             "tls": False, "product": None},
            {"port": 6379, "service": "Redis", "exposure": "database", "banner": "", "tls": False,
             "product": None},
            {"port": 2375, "service": "Docker API (no TLS)", "exposure": "container_api",
             "banner": "", "tls": False, "product": None},
            {"port": 4444, "service": "unknown", "exposure": "unknown", "banner": "hi",
             "tls": False, "product": None},
        ],
        "cve_lookup": {"enabled": True, "queried": [], "errors": []},
        "cves": {
            "cpe:2.3:a:beasts:vsftpd:2.3.4": [
                {"cve_id": "CVE-2011-2523", "score": 9.8, "cvss_version": "3.1", "vector": "AV:N",
                 "description": "vsftpd 2.3.4 contains a backdoor.", "published": "2019-11-27",
                 "url": "https://nvd.nist.gov/vuln/detail/CVE-2011-2523"},
            ]
        },
    }  # fmt: skip
    base.update(overrides)
    return base


PARAMS = PortScanParams(target="lab-banners")


def test_translate_exposures_and_cves() -> None:
    findings = translate(raw_scan(), PARAMS)
    by_item = {f.item: f for f in findings}
    assert by_item["5 open TCP port(s) on lab-banners"].severity is Severity.INFO
    assert by_item["Telnet exposed on port 23 (clear-text remote login)"].severity is Severity.HIGH
    assert by_item["Redis database port 6379 is reachable"].severity is Severity.HIGH
    assert by_item["Docker API (no TLS) exposed on port 2375"].severity is Severity.CRITICAL
    assert by_item["FTP exposed on port 21 (clear-text file transfer)"].severity is Severity.MEDIUM
    assert "announced" in by_item["Open port 4444 (service not identified)"].explanation

    cve = by_item["CVE-2011-2523 may affect vsftpd 2.3.4 (port 21)"]
    assert cve.severity is Severity.CRITICAL
    assert cve.confidence is Confidence.MEDIUM
    assert "CVSS v3.1 base score of 9.8" in cve.severity_rationale
    assert "Confidence MEDIUM" in cve.severity_rationale
    assert cve.references == ["https://nvd.nist.gov/vuln/detail/CVE-2011-2523", "CVE-2011-2523"]
    assert cve.evidence["banner"] == "220 (vsFTPd 2.3.4)"
    # Most severe first.
    assert findings[0].severity is Severity.CRITICAL


def test_product_without_cves_is_reported_once_lookup_ran() -> None:
    findings = translate(raw_scan(cves={}), PARAMS)
    assert any(f.item == "vsftpd 2.3.4 identified on port 21 (no CVEs found)" for f in findings)
    # If the lookup failed, we do not claim "no CVEs".
    failed = raw_scan(cves={}, cve_lookup={"enabled": True, "queried": [], "errors": ["down"]})
    assert not any("no CVEs found" in f.item for f in translate(failed, PARAMS))


def test_cve_without_score_and_v2_only() -> None:
    cves = {
        "cpe:2.3:a:beasts:vsftpd:2.3.4": [
            {"cve_id": "CVE-2099-0001", "score": None, "cvss_version": None, "vector": None,
             "description": "", "published": None, "url": "https://nvd.nist.gov/vuln/detail/CVE-2099-0001"},
            {"cve_id": "CVE-2000-0002", "score": 5.0, "cvss_version": "2.0", "vector": None,
             "description": "old", "published": None, "url": "https://nvd.nist.gov/vuln/detail/CVE-2000-0002"},
        ]
    }  # fmt: skip
    by_id = {f.references[1]: f for f in translate(raw_scan(cves=cves), PARAMS) if f.references[1:]}
    assert by_id["CVE-2099-0001"].severity is Severity.MEDIUM
    assert "no CVSS score" in by_id["CVE-2099-0001"].severity_rationale
    assert "CVSS v2" in by_id["CVE-2000-0002"].severity_rationale


def test_nothing_open() -> None:
    [finding] = translate(raw_scan(open=[], closed_count=100), PARAMS)
    assert finding.item == "No open TCP ports found on lab-banners"
    assert finding.status.value == "PASS"

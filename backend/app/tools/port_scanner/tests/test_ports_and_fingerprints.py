import pytest
from pydantic import ValidationError

from app.tools.port_scanner.fingerprint import MAX_BANNER_CHARS, identify, sanitize_banner
from app.tools.port_scanner.ports import PRESETS, TOP_100, TOP_1000, WEB_PRESET, parse_ports
from app.tools.port_scanner.schemas import PortScanParams

# --- ports ------------------------------------------------------------------------------


def test_presets_have_expected_sizes() -> None:
    assert len(TOP_100) == 100 and len(TOP_1000) == 1000
    assert set(TOP_100) <= set(TOP_1000)
    assert {21, 22, 23, 80, 443, 3306, 6379} <= set(TOP_100)
    assert 8080 in WEB_PRESET and 22 not in WEB_PRESET
    assert all(1 <= p <= 65535 for p in TOP_1000)


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        ("22", [22]),
        ("80,22,80", [22, 80]),
        (" 8000-8002 , 22 ", [22, 8000, 8001, 8002]),
        ("65535", [65535]),
    ],
)
def test_parse_ports(spec: str, expected: list[int]) -> None:
    assert parse_ports(spec, 1024) == expected


@pytest.mark.parametrize(
    ("spec", "message"),
    [
        ("", "at least one"),
        ("0", "between 1 and 65535"),
        ("65536", "between 1 and 65535"),
        ("10-5", "below its start"),
        ("22;80", "not a port or range"),
        ("-1", "not a port or range"),
        ("1-65535", "At most 1024"),
        ("1-600,1000-1600", "At most 1024"),
    ],
)
def test_parse_ports_rejects(spec: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        parse_ports(spec, 1024)


def test_params_validation() -> None:
    params = PortScanParams(target="Lab-Banners", preset="custom", ports="21,22")
    assert params.target == "lab-banners"
    assert params.port_list() == [21, 22]
    assert PortScanParams(target="10.231.10.11").port_list() == PRESETS["top-100"]
    with pytest.raises(ValidationError, match="only used with the 'custom' preset"):
        PortScanParams(target="x", preset="web", ports="22")
    with pytest.raises(ValidationError, match="at least one"):
        PortScanParams(target="x", preset="custom", ports="")
    for bad in ("http://x", "x:22", "a..b", ""):
        with pytest.raises(ValidationError):
            PortScanParams(target=bad)


def test_params_schema_is_form_friendly() -> None:
    schema = PortScanParams.model_json_schema()
    for name, prop in schema["properties"].items():
        assert "anyOf" not in prop and "$ref" not in prop, name
    assert schema["properties"]["preset"]["enum"] == ["top-100", "top-1000", "web", "custom"]


# --- banners ------------------------------------------------------------------------------


def test_sanitize_escapes_and_caps() -> None:
    assert sanitize_banner(b"220 ok\r\n") == "220 ok"
    assert sanitize_banner(b"\xff\xfd\x18login: ") == "\\xff\\xfd\\x18login:"
    assert sanitize_banner(b"<script>alert(1)</script>") == "<script>alert(1)</script>"
    long = sanitize_banner(b"A" * 5000)
    assert len(long) <= MAX_BANNER_CHARS + 1 and long.endswith("…")


@pytest.mark.parametrize(
    ("raw", "name", "version", "confidence", "cpe"),
    [
        (b"SSH-2.0-OpenSSH_7.4\r\n", "OpenSSH", "7.4", "MEDIUM", "cpe:2.3:a:openbsd:openssh:7.4"),
        (b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n", "OpenSSH", "8.9", "LOW", None),
        (b"220 (vsFTPd 2.3.4)\r\n", "vsftpd", "2.3.4", "MEDIUM",
         "cpe:2.3:a:vsftpd_project:vsftpd:2.3.4"),
        (b"220 host ESMTP Exim 4.87 Ubuntu\r\n", "Exim", "4.87", "LOW", "cpe:2.3:a:exim:exim:4.87"),
        (b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n", "nginx", "1.18.0", "MEDIUM",
         "cpe:2.3:a:f5:nginx:1.18.0"),
        (b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.29 (Ubuntu)\r\n", "Apache HTTP Server", "2.4.29",
         "LOW", None),
        (b"\x4a\x00\x00\x00\x0a5.5.62-0ubuntu0.14.04.1\x00rest", "MySQL", "5.5.62", "LOW",
         "cpe:2.3:a:oracle:mysql:5.5.62"),
        (b"220 mail ESMTP Postfix\r\n", "Postfix", None, "LOW", None),
    ],
)  # fmt: skip
def test_identify(
    raw: bytes, name: str, version: str | None, confidence: str, cpe: str | None
) -> None:
    product = identify(raw, sanitize_banner(raw))
    assert product is not None
    assert (product.name, product.version, product.confidence) == (name, version, confidence)
    if cpe:
        assert product.cpe_candidates[0] == cpe
    if version is None:
        assert product.cpe_candidates == []


def test_nginx_tries_both_cpe_vendors() -> None:
    product = identify(b"", "Server: nginx/1.18.0")
    assert product is not None
    assert product.cpe_candidates == ["cpe:2.3:a:f5:nginx:1.18.0", "cpe:2.3:a:nginx:nginx:1.18.0"]


def test_unknown_banner() -> None:
    assert identify(b"hello", "hello") is None

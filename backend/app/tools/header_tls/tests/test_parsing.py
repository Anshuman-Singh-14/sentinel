import pytest

from app.tools.header_tls.service import parse_set_cookie
from app.tools.header_tls.tls import CertInfo, hostname_matches
from app.tools.header_tls.translator import csp_issues, parse_csp, parse_hsts


def test_parse_set_cookie_drops_the_value() -> None:
    cookie = parse_set_cookie("sid=SECRET; Path=/; Secure; HttpOnly; SameSite=strict; Max-Age=60")
    assert cookie is not None
    assert cookie.name == "sid"
    assert (cookie.secure, cookie.http_only, cookie.same_site, cookie.persistent) == (
        True,
        True,
        "Strict",
        True,
    )
    assert "SECRET" not in repr(cookie)
    assert parse_set_cookie("garbage") is None


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("max-age=31536000; includeSubDomains; preload", (31536000, True, True)),
        ('max-age="600"', (600, False, False)),
        ("includeSubDomains", (None, True, False)),
    ],
)
def test_parse_hsts(value: str, expected: tuple[int | None, bool, bool]) -> None:
    assert parse_hsts(value) == expected


@pytest.mark.parametrize(
    ("policy", "fragments"),
    [
        ("default-src 'self'; object-src 'none'", []),
        ("script-src 'self' 'unsafe-inline'; object-src 'none'", ["'unsafe-inline'"]),
        # A nonce makes browsers ignore 'unsafe-inline' (CSP level 2+).
        ("script-src 'nonce-abc' 'unsafe-inline'; object-src 'none'", []),
        ("default-src *; object-src 'none'", ["wildcard"]),
        ("default-src https:", ["wildcard"]),
        ("script-src 'self' 'unsafe-eval'; object-src 'none'", ["'unsafe-eval'"]),
        ("img-src 'self'", ["no script-src", "object-src"]),
    ],
)
def test_csp_issues(policy: str, fragments: list[str]) -> None:
    issues = " | ".join(csp_issues(policy))
    if not fragments:
        assert issues == ""
    for fragment in fragments:
        assert fragment in issues


def test_parse_csp_keeps_first_directive() -> None:
    assert parse_csp("default-src 'self'; default-src *")["default-src"] == ["'self'"]


def cert(**overrides: object) -> CertInfo:
    base = dict(
        subject="CN=x", issuer="CN=ca", common_name="example.com", san_dns=["example.com"],
        san_ip=[], not_before="", not_after="", days_remaining=100, serial="1",
        signature_hash="sha256", key_type="RSA", key_bits=2048, self_signed=False,
    )  # fmt: skip
    base.update(overrides)
    return CertInfo(**base)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("host", "sans", "expected"),
    [
        ("example.com", ["example.com"], True),
        ("WWW.example.com", ["*.example.com"], True),
        ("a.b.example.com", ["*.example.com"], False),  # wildcard covers one label only
        ("example.com", ["*.example.com"], False),
        ("evil.com", ["*.com"], False),  # no wildcard on a public suffix level
        ("other.example", ["example.com"], False),
    ],
)
def test_hostname_matching(host: str, sans: list[str], expected: bool) -> None:
    assert hostname_matches(host, cert(san_dns=sans)) is expected


def test_ip_hosts_match_ip_sans_only() -> None:
    assert hostname_matches("10.0.0.1", cert(san_ip=["10.0.0.1"]))
    assert not hostname_matches("10.0.0.1", cert(san_dns=["10.0.0.1"]))

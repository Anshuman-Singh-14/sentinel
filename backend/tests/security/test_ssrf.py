"""SSRF guard: URL validation and redirect resolution (04-security.md sections 3 and 11).

Address-level checks (private, metadata, rebinding) are the scope policy's job
and are tested in test_scope_policy.py; the end-to-end redirect behaviour
against live sockets is in app/tools/header_tls/tests/test_checker.py.
"""

import pytest

from app.core.security.ssrf import parse_target_url, resolve_redirect

PORTS = frozenset({80, 443, 8080, 8443})


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("example.com", "https://example.com/"),
        ("https://Example.COM", "https://example.com/"),
        ("http://example.com:8080/a/b?x=1", "http://example.com:8080/a/b?x=1"),
        ("https://lab-web:8443", "https://lab-web:8443/"),
        ("https://10.231.10.10/", "https://10.231.10.10/"),
        ("https://[::1]:8443/", "https://[::1]:8443/"),
        ("https://example.com/#frag", "https://example.com/"),
    ],
)
def test_accepts(raw: str, expected: str) -> None:
    assert str(parse_target_url(raw, PORTS)) == expected


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ("", "Enter a URL"),
        ("file:///etc/passwd", "Only http"),
        ("gopher://example.com/", "Only http"),
        ("ftp://example.com/", "Only http"),
        ("javascript:alert(1)", "port|Only http|not a valid"),
        ("dict://localhost:11211/", "Only http"),
        ("http://user:pw@example.com/", "credentials"),
        ("http://@example.com/", "credentials"),
        ("http://example.com:22/", "Port 22 is not allowed"),
        ("http://example.com:6379/", "Port 6379 is not allowed"),
        ("http://example.com:99999/", "port"),
        ("http://exa mple.com/", "spaces or control"),
        ("http://example.com/\r\nX-Injected: 1", "spaces or control"),
        ("https://", "no host"),
        ("http://" + "a" * 2050, "limited to"),
        ("http://bad_host!.com/", "not a valid host"),
    ],
)
def test_rejects(raw: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        parse_target_url(raw, PORTS)


def test_pinned_url_keeps_host_for_header_and_sni() -> None:
    target = parse_target_url("https://example.com:8443/login?next=/", PORTS)
    assert target.url_for("93.184.216.34") == "https://93.184.216.34:8443/login?next=/"
    assert target.url_for("2001:db8::1") == "https://[2001:db8::1]:8443/login?next=/"
    assert target.host_header == "example.com:8443"
    default = parse_target_url("https://example.com/", PORTS)
    assert default.host_header == "example.com"


@pytest.mark.parametrize(
    ("location", "expected"),
    [
        ("https://example.com/x", "https://example.com/x"),
        ("/login", "http://site.test:8080/login"),
        ("//other.example/p", "http://other.example/p"),
        ("next?page=2", "http://site.test:8080/dir/next?page=2"),
    ],
)
def test_redirects_resolve_relative_locations(location: str, expected: str) -> None:
    current = parse_target_url("http://site.test:8080/dir/page", PORTS)
    assert str(resolve_redirect(current, location, PORTS)) == expected


@pytest.mark.parametrize(
    "location",
    [
        "file:///etc/passwd",
        "http://169.254.169.254:1234/",  # odd port
        "http://user@internal/",
        "gopher://x/",
    ],
)
def test_redirects_are_revalidated(location: str) -> None:
    current = parse_target_url("http://site.test/", PORTS)
    with pytest.raises(ValueError):
        resolve_redirect(current, location, PORTS)

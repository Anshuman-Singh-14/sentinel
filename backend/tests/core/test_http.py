import ipaddress

import pytest

from app.core.http import resolve_client_ip

TRUSTED = [ipaddress.ip_network("10.0.0.0/8")]


@pytest.mark.parametrize(
    ("peer", "xff", "expected"),
    [
        # Direct connection: the peer is the client, the header is ignored.
        ("203.0.113.9", "1.2.3.4", "203.0.113.9"),
        # Untrusted peer cannot spoof its address via X-Forwarded-For.
        ("198.51.100.7", "127.0.0.1", "198.51.100.7"),
        # Trusted proxy: take the rightmost untrusted hop.
        ("10.0.0.2", "203.0.113.9", "203.0.113.9"),
        # Client-supplied hops to the left are not believed.
        ("10.0.0.2", "6.6.6.6, 203.0.113.9", "203.0.113.9"),
        # Chain of trusted proxies.
        ("10.0.0.2", "203.0.113.9, 10.0.0.3", "203.0.113.9"),
        # Malformed hop: fall back to the proxy address.
        ("10.0.0.2", "not-an-ip", "10.0.0.2"),
        # Header absent.
        ("10.0.0.2", None, "10.0.0.2"),
        # No peer info at all.
        (None, "1.2.3.4", None),
    ],
)
def test_resolve_client_ip(peer: str | None, xff: str | None, expected: str | None) -> None:
    assert resolve_client_ip(peer, xff, TRUSTED) == expected


def test_no_trusted_proxies_means_header_ignored() -> None:
    assert resolve_client_ip("10.0.0.2", "203.0.113.9", []) == "10.0.0.2"

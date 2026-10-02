import pytest

from app.core.security.validators import normalize_domain


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("example.com", "example.com"),
        ("  Example.COM. ", "example.com"),
        ("sub.domain.example.co.uk", "sub.domain.example.co.uk"),
        ("bücher.de", "xn--bcher-kva.de"),
        ("a-b.example", "a-b.example"),
        (f"{'a' * 63}.com", f"{'a' * 63}.com"),
    ],
)
def test_accepts_and_normalises(raw: str, expected: str) -> None:
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ("", "Enter a domain"),
        ("   ", "Enter a domain"),
        ("192.168.1.1", "not an IP address"),
        ("::1", "not an IP address"),
        ("https://example.com", "not a URL"),
        ("example.com/path", "not a URL"),
        ("localhost", "fully qualified"),
        ("example", "fully qualified"),
        ("a..com", "empty label"),
        ("-bad.com", "not a valid domain label"),
        ("bad-.com", "not a valid domain label"),
        ("under_score.com", "not a valid domain label"),
        ("spa ce.com", "not a valid domain label"),
        ("semi;colon.com", "not a valid domain label"),
        (f"{'a' * 64}.com", "at most 63"),
        (".".join(["a" * 60] * 5), "at most 253"),
        ("example.123", "cannot be numeric"),
        ("postgres.internal", "reserved or private"),
        ("printer.local", "reserved or private"),
        ("app.localhost", "reserved or private"),
        ("1.168.192.in-addr.arpa", "reserved or private"),
        ("router.home.arpa", "reserved or private"),
        ("site.onion", "reserved or private"),
        ("x.test", "reserved or private"),
    ],
)
def test_rejects_with_reason(raw: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        normalize_domain(raw)


def test_reserved_check_is_by_label_not_substring() -> None:
    # "notlocal.com" ends with "local.com", not ".local".
    assert normalize_domain("notlocal.com") == "notlocal.com"
    assert normalize_domain("mytest.dev") == "mytest.dev"

"""SSRF guard for outbound URL fetches (04-security.md section 3, threat model T11).

Server-side request forgery turns "fetch this URL for me" into "make the
server attack something it can reach". The guard has four parts:

1. **URL shape** (``parse_target_url``): only ``http``/``https``, no
   credentials in the URL, only allowlisted ports, a valid host.
2. **Address check**: the host is resolved and checked by the scope policy
   (hard denylist, then allow rules) *before* any connection. That function
   lives in ``scope.py`` and is injected, so this module stays pure.
3. **Pinning**: the request goes to the checked IP literal; the original
   host is sent as the ``Host`` header and TLS SNI, and the certificate is
   verified against it. DNS cannot change between check and connect.
4. **Every redirect is a new request**: redirects are never followed
   automatically. Each ``Location`` is parsed, re-validated and re-checked
   (a new host is re-resolved and scope-checked), up to a fixed limit.
"""

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from app.core.security.validators import normalize_host

ALLOWED_SCHEMES = frozenset({"http", "https"})
DEFAULT_PORTS = {"http": 80, "https": 443}
MAX_URL_LENGTH = 2048


@dataclass(frozen=True, slots=True)
class TargetUrl:
    scheme: str
    host: str  # normalised host name or IP literal (no brackets)
    port: int
    path: str  # path plus query, always starting with "/"

    @property
    def is_https(self) -> bool:
        return self.scheme == "https"

    @property
    def host_is_ip(self) -> bool:
        try:
            ipaddress.ip_address(self.host)
        except ValueError:
            return False
        return True

    @property
    def default_port(self) -> bool:
        return self.port == DEFAULT_PORTS[self.scheme]

    @property
    def host_header(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return host if self.default_port else f"{host}:{self.port}"

    def __str__(self) -> str:
        return urlunsplit((self.scheme, self.host_header, self.path, "", ""))

    def url_for(self, address: str) -> str:
        """The URL with the host replaced by a checked IP address (pinning)."""
        literal = f"[{address}]" if ":" in address else address
        return urlunsplit((self.scheme, f"{literal}:{self.port}", self.path, "", ""))

    def with_scheme(self, scheme: str, port: int) -> "TargetUrl":
        return TargetUrl(scheme, self.host, port, self.path)


def parse_target_url(raw: str, allowed_ports: frozenset[int] | set[int]) -> TargetUrl:
    """Validate a user-supplied URL (a bare host means https://host/).

    Raises ``ValueError`` with a user-safe message.
    """
    value = raw.strip()
    if not value:
        raise ValueError("Enter a URL or host name.")
    if len(value) > MAX_URL_LENGTH:
        raise ValueError(f"URLs are limited to {MAX_URL_LENGTH} characters.")
    if any(ord(c) < 0x21 or ord(c) == 0x7F for c in value):
        raise ValueError("The URL contains spaces or control characters.")
    if "://" not in value:
        value = f"https://{value}"
    parts = urlsplit(value)
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise ValueError("Only http:// and https:// URLs can be checked.")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise ValueError("URLs with embedded credentials are not allowed.")
    if not parts.hostname:
        raise ValueError("The URL has no host.")
    host = normalize_host(parts.hostname)
    try:
        port = parts.port if parts.port is not None else DEFAULT_PORTS[scheme]
    except ValueError:
        raise ValueError("The port is not a number between 1 and 65535.") from None
    if port not in allowed_ports:
        allowed = ", ".join(str(p) for p in sorted(allowed_ports))
        raise ValueError(f"Port {port} is not allowed for web checks (allowed: {allowed}).")
    path = parts.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    if parts.query:
        path = f"{path}?{parts.query}"
    return TargetUrl(scheme, host, port, path)


def resolve_redirect(
    current: TargetUrl, location: str, allowed_ports: frozenset[int] | set[int]
) -> TargetUrl:
    """Resolve a (possibly relative) Location header against the current URL and validate it."""
    location = location.strip()
    if location.startswith("//"):
        location = f"{current.scheme}:{location}"
    elif location.startswith("/"):
        location = f"{current.scheme}://{current.host_header}{location}"
    elif "://" not in location.split("?", 1)[0]:
        base = current.path.rsplit("/", 1)[0]
        location = f"{current.scheme}://{current.host_header}{base}/{location}"
    return parse_target_url(location, allowed_ports)

"""Banner handling and product identification.

Banners are attacker-controllable text: a server can claim to be anything.
So they are sanitised (non-printable bytes escaped, length capped) before
they are stored or shown, and a version read from a banner is a *claim*,
which is why every CVE match carries LOW or MEDIUM confidence, never HIGH.
"""

import re
from dataclasses import dataclass
from typing import Literal

MAX_BANNER_CHARS = 512

# Distribution package markers: distros backport security fixes without
# changing the upstream version, so "OpenSSH_7.4p1 Debian-10+deb9u7" may
# already be patched against CVEs that affect upstream 7.4.
_DISTRO_MARKERS = re.compile(
    r"ubuntu|debian|deb\d|\.el\d|centos|red ?hat|rhel|fedora|suse|alpine|freebsd", re.IGNORECASE
)


def sanitize_banner(data: bytes) -> str:
    """Printable ASCII kept; CR/LF/TAB normalised; everything else as \\xNN; capped."""
    out: list[str] = []
    length = 0
    for byte in data:
        if byte in (0x0D,):
            continue
        if byte == 0x0A:
            piece = "\n"
        elif byte == 0x09:
            piece = "\t"
        elif 0x20 <= byte <= 0x7E:
            piece = chr(byte)
        else:
            piece = f"\\x{byte:02x}"
        if length + len(piece) > MAX_BANNER_CHARS:
            out.append("…")
            break
        out.append(piece)
        length += len(piece)
    return "".join(out).strip()


@dataclass(frozen=True, slots=True)
class Product:
    name: str  # display name, e.g. "OpenSSH"
    version: str | None
    # CPE 2.3 vendor:product pairs to try, most current first.
    cpe_products: tuple[str, ...]
    confidence: Literal["LOW", "MEDIUM"]
    confidence_reason: str
    evidence: str  # the banner fragment the identification came from

    @property
    def cpe_candidates(self) -> list[str]:
        if not self.version:
            return []
        return [f"cpe:2.3:a:{vp}:{self.version}" for vp in self.cpe_products]


@dataclass(frozen=True, slots=True)
class _Rule:
    pattern: re.Pattern[str]
    name: str
    cpe_products: tuple[str, ...]


_RULES: tuple[_Rule, ...] = (
    _Rule(re.compile(r"SSH-[\d.]+-OpenSSH_(?P<v>\d+\.\d+)(?:p\d+)?", re.I), "OpenSSH",
          ("openbsd:openssh",)),
    _Rule(re.compile(r"SSH-[\d.]+-dropbear_(?P<v>\d{4}\.\d+)", re.I), "Dropbear SSH",
          ("dropbear_ssh_project:dropbear_ssh",)),
    _Rule(re.compile(r"vsFTPd (?P<v>\d+\.\d+\.\d+)", re.I), "vsftpd",
          ("vsftpd_project:vsftpd", "beasts:vsftpd")),
    _Rule(re.compile(r"ProFTPD (?P<v>\d+\.\d+\.\d+[a-z]?)", re.I), "ProFTPD", ("proftpd:proftpd",)),
    _Rule(re.compile(r"Pure-FTPd", re.I), "Pure-FTPd", ("pureftpd:pure-ftpd",)),
    _Rule(re.compile(r"Exim (?P<v>\d+\.\d+(?:\.\d+)?)", re.I), "Exim", ("exim:exim",)),
    _Rule(re.compile(r"Postfix", re.I), "Postfix", ("postfix:postfix",)),
    _Rule(re.compile(r"Server: nginx/(?P<v>\d+\.\d+\.\d+)", re.I), "nginx",
          ("f5:nginx", "nginx:nginx")),
    _Rule(re.compile(r"Server: Apache/(?P<v>\d+\.\d+\.\d+)", re.I), "Apache HTTP Server",
          ("apache:http_server",)),
    _Rule(re.compile(r"Server: Microsoft-IIS/(?P<v>\d+\.\d+)", re.I), "Microsoft IIS",
          ("microsoft:internet_information_services",)),
    _Rule(re.compile(r"Server: lighttpd/(?P<v>\d+\.\d+\.\d+)", re.I), "lighttpd",
          ("lighttpd:lighttpd",)),
    _Rule(re.compile(r"(?P<v>\d+\.\d+\.\d+)-MariaDB", re.I), "MariaDB", ("mariadb:mariadb",)),
)  # fmt: skip

_MYSQL_HANDSHAKE = re.compile(rb"^.{4}\x0a(?P<v>\d+\.\d+\.\d+)[^\x00]*\x00", re.DOTALL)


def identify(raw: bytes, banner: str) -> Product | None:
    """Best-effort product/version from a banner. None if nothing is recognised."""
    for rule in _RULES:
        match = rule.pattern.search(banner)
        if match:
            version = match.groupdict().get("v")
            return _product(rule.name, version, rule.cpe_products, banner, match.group(0))
    mysql = _MYSQL_HANDSHAKE.match(raw)
    if mysql and b"MariaDB" not in raw:
        version = mysql.group("v").decode("ascii")
        return _product("MySQL", version, ("oracle:mysql",), banner, f"MySQL {version}")
    return None


def _product(
    name: str, version: str | None, cpe_products: tuple[str, ...], banner: str, fragment: str
) -> Product:
    if not version:
        return Product(
            name,
            None,
            cpe_products,
            "LOW",
            "The banner names the product but not its version, so no CVEs can be matched.",
            fragment,
        )
    if _DISTRO_MARKERS.search(banner):
        return Product(
            name,
            version,
            cpe_products,
            "LOW",
            "The banner shows a distribution package. Distributions backport security "
            "fixes without changing the upstream version number, so these CVEs may "
            "already be patched. Check the package changelog.",
            fragment,
        )
    return Product(
        name,
        version,
        cpe_products,
        "MEDIUM",
        "Matched on the version the service announces in its banner. Banners can be "
        "changed, hidden or out of date, so treat this as a lead to verify, not proof.",
        fragment,
    )

"""Boundary validators shared by tool parameter models (04-security.md section 4).

Domains are validated structurally (RFC 1035/1123), not with one big regex,
so each rejection has a precise, user-facing reason.
"""

import ipaddress
import re
from typing import Annotated

from pydantic import AfterValidator

MAX_DOMAIN_LENGTH = 253
MAX_LABEL_LENGTH = 63
_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

# Names that only make sense inside a private network or are reserved by
# RFC 2606 / RFC 6761 / RFC 8375 / RFC 7686. Looking them up on public
# resolvers is meaningless at best, and through a container's own resolver it
# would expose internal infrastructure names.
RESERVED_SUFFIXES = (
    "localhost",
    "local",
    "localdomain",
    "internal",
    "intranet",
    "lan",
    "home",
    "corp",
    "home.arpa",
    "arpa",
    "invalid",
    "test",
    "onion",
)


def normalize_domain(value: str) -> str:
    """Lower-case, strip one trailing dot, IDNA-encode and validate a domain.

    Raises ``ValueError`` with a user-safe message on failure.
    """
    candidate = value.strip().lower().removesuffix(".")
    if not candidate:
        raise ValueError("Enter a domain name.")
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        pass
    else:
        raise ValueError("Enter a domain name, not an IP address.")
    if "://" in candidate or "/" in candidate:
        raise ValueError("Enter a bare domain name (example.com), not a URL.")
    raw_labels = candidate.split(".")
    if len(raw_labels) < 2:
        raise ValueError("Enter a fully qualified domain name, such as example.com.")
    labels: list[str] = []
    for raw_label in raw_labels:
        if not raw_label:
            raise ValueError("The domain contains an empty label (two dots in a row).")
        try:
            # IDNA 2003 via the standard library: "bücher" -> "xn--bcher-kva".
            label = raw_label.encode("idna").decode("ascii")
        except UnicodeError:
            if len(raw_label) > MAX_LABEL_LENGTH:
                raise ValueError(
                    f"Each part of a domain is at most {MAX_LABEL_LENGTH} characters."
                ) from None
            raise ValueError("The domain contains characters that cannot be encoded.") from None
        if len(label) > MAX_LABEL_LENGTH:
            raise ValueError(f"Each part of a domain is at most {MAX_LABEL_LENGTH} characters.")
        if not _LABEL_RE.fullmatch(label):
            raise ValueError(
                f'"{label}" is not a valid domain label (letters, digits and inner hyphens only).'
            )
        labels.append(label)
    ascii_name = ".".join(labels)
    if len(ascii_name) > MAX_DOMAIN_LENGTH:
        raise ValueError(f"A domain name is at most {MAX_DOMAIN_LENGTH} characters.")
    if labels[-1].isdigit():
        raise ValueError("The top-level domain cannot be numeric.")
    for suffix in RESERVED_SUFFIXES:
        if ascii_name == suffix or ascii_name.endswith(f".{suffix}"):
            raise ValueError(f'".{suffix}" names are reserved or private and cannot be looked up.')
    return ascii_name


DomainName = Annotated[str, AfterValidator(normalize_domain)]

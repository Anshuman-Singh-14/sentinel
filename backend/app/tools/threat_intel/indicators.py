"""Indicators of compromise: parse, classify and decide what may be looked up.

Supported kinds: IP addresses, domain names and file hashes (MD5, SHA-1,
SHA-256).

Privacy rule: a lookup sends the indicator to a third party. Private,
loopback, link-local and otherwise non-global addresses are never sent:
their reputation is meaningless, and they would reveal internal network
layout. Domains go through the same validator as the DNS tool, which
rejects internal and reserved names (``.internal``, ``.local``...).
"""

import ipaddress
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from app.core.security.validators import normalize_domain

MAX_INDICATORS = 20
MAX_INDICATOR_LENGTH = 253
_SPLIT = re.compile(r"[\s,;]+")
_HASH = {32: "md5", 40: "sha1", 64: "sha256"}
_HEX = re.compile(r"^[0-9a-f]+$")


class IndicatorKind(StrEnum):
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"


@dataclass(frozen=True, slots=True)
class Indicator:
    value: str
    kind: IndicatorKind
    # Set when the indicator is valid but must not be sent to providers.
    skip_reason: str | None = None

    @property
    def lookup(self) -> bool:
        return self.skip_reason is None


def split_indicators(value: Any) -> Any:
    """Accept a list (from playbooks) or one string separated by commas, spaces or newlines."""
    if isinstance(value, str):
        return [part for part in _SPLIT.split(value) if part]
    return value


def classify(raw: str) -> Indicator:
    """Validate one indicator. Raises ``ValueError`` with a user-safe message."""
    text = raw.strip()
    if not text:
        raise ValueError("Empty indicator.")
    if len(text) > MAX_INDICATOR_LENGTH:
        raise ValueError(f"Indicators are at most {MAX_INDICATOR_LENGTH} characters.")
    candidate = text.lower()
    try:
        address = ipaddress.ip_address(candidate.strip("[]"))
    except ValueError:
        pass
    else:
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        if not address.is_global:
            return Indicator(
                str(address),
                IndicatorKind.IP,
                "private or reserved address: never sent to third-party services",
            )
        return Indicator(str(address), IndicatorKind.IP)
    if len(candidate) in _HASH and _HEX.fullmatch(candidate):
        return Indicator(candidate, IndicatorKind.HASH)
    try:
        return Indicator(normalize_domain(candidate), IndicatorKind.DOMAIN)
    except ValueError as exc:
        raise ValueError(
            f"{text[:60]!r} is not an IP address, domain name or MD5/SHA-1/SHA-256 hash ({exc})"
        ) from None


def hash_type(value: str) -> str:
    return _HASH.get(len(value), "hash")

"""Identifier helpers.

UUIDv7 (RFC 9562 section 5.7) puts a millisecond Unix timestamp in the high
bits, so IDs sort by creation time. That makes them good request and run IDs:
log lines and database rows order naturally, and B-tree index inserts stay
local. Python 3.12's ``uuid`` module has no ``uuid7`` (it arrived in 3.14), and
the algorithm is small enough to own instead of adding a dependency.
"""

import re
import secrets
import time
import uuid

_TIMESTAMP_MASK = (1 << 48) - 1
_RAND_A_BITS = 12
_RAND_B_BITS = 62

# Accepted shape for caller-supplied request IDs: a UUID or a short token.
# Anything else is discarded, so a header value cannot inject newlines, ANSI
# escapes or megabytes of text into logs (log injection / log flooding).
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def uuid7() -> uuid.UUID:
    """Generate a UUIDv7: 48-bit ms timestamp, version, 74 random bits.

    IDs created within the same millisecond are unique, but their relative
    order is random. RFC 9562 allows this, and nothing here needs
    sub-millisecond ordering.
    """
    timestamp_ms = time.time_ns() // 1_000_000
    rand_a = secrets.randbits(_RAND_A_BITS)
    rand_b = secrets.randbits(_RAND_B_BITS)
    value = (
        (timestamp_ms & _TIMESTAMP_MASK) << 80
        | 0x7 << 76  # version 7
        | rand_a << 64
        | 0b10 << 62  # RFC 9562 variant
        | rand_b
    )
    return uuid.UUID(int=value)


def uuid7_timestamp_ms(value: uuid.UUID) -> int:
    """Extract the Unix timestamp (ms) embedded in a UUIDv7."""
    return value.int >> 80


def sanitize_request_id(candidate: str | None) -> str | None:
    """Return ``candidate`` if it is a safe request ID, otherwise ``None``."""
    if candidate and _REQUEST_ID_RE.fullmatch(candidate):
        return candidate
    return None


def new_request_id() -> str:
    return str(uuid7())

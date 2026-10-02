"""Opaque session tokens (ADR 0003).

Tokens are 256 bits from the OS CSPRNG, URL-safe base64 encoded. Only their
SHA-256 digest is stored. Opaque tokens were chosen over JWTs because every
request checks the session row anyway (instant revocation, last-seen
tracking), which removes the one advantage of a self-contained token and
avoids JWT pitfalls such as algorithm confusion entirely.
"""

import hashlib
import hmac
import secrets

TOKEN_BYTES = 32
# token_urlsafe(32) yields 43 characters. Anything longer is rejected before
# hashing, so oversized cookies cost nothing.
MAX_TOKEN_LENGTH = 64


def new_token() -> str:
    return secrets.token_urlsafe(TOKEN_BYTES)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def is_plausible_token(token: str | None) -> bool:
    return bool(token) and len(token or "") <= MAX_TOKEN_LENGTH


def tokens_equal(a: str, b: str) -> bool:
    """Constant-time comparison, so response timing reveals nothing about a token."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))

"""Secret redaction for logs and (from Phase 2) audit-event details.

This is a mandatory processor: every log line passes through it before it is
written (03-logging-audit.md section 4). It works in three layers:

1. **Key-based.** Values under keys that name a secret (``password``,
   ``authorization``, ``api_key``...) are replaced entirely, at any nesting depth.
2. **Pattern-based.** Known secret shapes (JWTs, bearer tokens, cloud and API
   keys, PEM private keys, ``user:password@`` in URLs) are masked inside any
   string, including exception tracebacks and free-text messages.
3. **Entropy-based, scoped.** Long random-looking tokens are masked only inside
   fields that commonly carry credentials (headers, query, payload...). Applying
   it everywhere would also destroy legitimate values such as SHA-256 digests
   in file-integrity results.

Values are then truncated to a maximum length, so raw banners or response
bodies cannot flood the logs.

Design note: redaction masks without fingerprinting. A plain hash of a short
secret can be brute-forced, so a safe fingerprint needs a keyed HMAC. That is
deferred until there is a concrete need.
"""

import math
import re
from collections import Counter
from collections.abc import Mapping
from typing import Any

from structlog.typing import EventDict, WrappedLogger

REDACTED = "[REDACTED]"
_MAX_DEPTH = 12

_SENSITIVE_KEY_RE = re.compile(
    r"password|passwd|pwd|secret|token|api[_-]?key|apikey|authorization|cookie|session"
    r"|private[_-]?key|refresh|credential|dsn|connection[_-]?string",
    re.IGNORECASE,
)
# Keys that match the pattern above but hold identifiers, not secrets.
# `session_id` is a database row ID; the bearer secret is the refresh token.
_SAFE_KEYS = frozenset({"session_id", "token_type", "token_count"})

# Fields where free text commonly carries credentials. Only these are scanned
# for high-entropy tokens.
_ENTROPY_SCOPE_KEY_RE = re.compile(
    r"header|query|param|payload|body|env|config|args|kwargs|data|extra|url",
    re.IGNORECASE,
)

_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # PEM private keys (multi-line).
    (
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
        REDACTED,
    ),
    # JSON Web Tokens: header.payload.signature, both JSON parts start with "eyJ".
    (re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"), REDACTED),
    # Authorization header schemes. The lookahead requires a digit or token
    # punctuation, so prose like "basic authentication" is left alone.
    (
        re.compile(
            r"(?i)\b(bearer|basic)\s+(?=[A-Za-z0-9._~+/=-]*[0-9._~+/=])[A-Za-z0-9._~+/=-]{8,}"
        ),
        r"\1 " + REDACTED,
    ),
    # Credentials embedded in URLs: scheme://user:password@host. This also
    # covers Sentinel's own DATABASE_URL / REDIS_URL if they reach an error.
    (
        re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)([^:/@\s]*):([^@/\s]+)@"),
        r"\1\2:" + REDACTED + "@",
    ),
    # key=value / key: value pairs in free text, query strings and serialised
    # JSON ("api_key": "..."), so a secret is masked even inside a string.
    (
        re.compile(
            r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key"
            r"|client[_-]?secret)(['\"]?\s*[=:]\s*)(['\"]?)[^\s'\"&,;]+"
        ),
        r"\1\2\3" + REDACTED,
    ),
    # Well-known credential formats.
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), REDACTED),  # AWS access key ID
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), REDACTED),  # GitHub token
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"), REDACTED),  # GitHub fine-grained PAT
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), REDACTED),  # Slack token
    (re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"), REDACTED),  # OpenAI/Anthropic-style key
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), REDACTED),  # Google API key
)

_TOKEN_RE = re.compile(r"[A-Za-z0-9+/_=-]{32,}")
# Random base64 tokens of 32+ chars score about 4.5-5.0 bits/char. Hex digests
# (SHA-256, MD5) cannot exceed 4.0, since hex has only 16 symbols, so they stay intact.
_ENTROPY_THRESHOLD = 4.2


def _shannon_entropy(text: str) -> float:
    length = len(text)
    return -sum((n / length) * math.log2(n / length) for n in Counter(text).values())


def _is_sensitive_key(key: str) -> bool:
    return key.lower() not in _SAFE_KEYS and bool(_SENSITIVE_KEY_RE.search(key))


def redact_text(text: str, *, entropy_scan: bool = False) -> str:
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    if entropy_scan:
        text = _TOKEN_RE.sub(
            lambda m: REDACTED if _shannon_entropy(m.group()) >= _ENTROPY_THRESHOLD else m.group(),
            text,
        )
    return text


def _truncate(text: str, max_length: int) -> str:
    if len(text) <= max_length:
        return text
    return f"{text[:max_length]}…[truncated {len(text) - max_length} chars]"


def redact(
    value: Any,
    *,
    max_length: int = 2048,
    entropy_scan: bool = False,
    _depth: int = 0,
) -> Any:
    """Return a redacted copy of ``value``. The input is never modified."""
    if _depth > _MAX_DEPTH:
        return "[MAX_DEPTH]"
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, str):
        return _truncate(redact_text(value, entropy_scan=entropy_scan), max_length)
    if isinstance(value, bytes | bytearray):
        text = bytes(value).decode("utf-8", errors="backslashreplace")
        return _truncate(redact_text(text, entropy_scan=entropy_scan), max_length)
    if isinstance(value, Mapping):
        result: dict[Any, Any] = {}
        for key, item in value.items():
            key_str = str(key)
            if _is_sensitive_key(key_str) and item not in (None, ""):
                result[key] = REDACTED
            else:
                result[key] = redact(
                    item,
                    max_length=max_length,
                    entropy_scan=entropy_scan or bool(_ENTROPY_SCOPE_KEY_RE.search(key_str)),
                    _depth=_depth + 1,
                )
        return result
    if isinstance(value, list | tuple | set | frozenset):
        return [
            redact(item, max_length=max_length, entropy_scan=entropy_scan, _depth=_depth + 1)
            for item in value
        ]
    # Unknown objects are converted to text and then scanned. Their str() or
    # repr() might embed a secret (e.g. a URL object or an exception).
    return _truncate(redact_text(str(value), entropy_scan=entropy_scan), max_length)


class RedactionProcessor:
    """structlog processor that applies ``redact`` to the whole event dict."""

    # A rendered traceback gets more room than ordinary fields, and is cut
    # from the *front*: the exception type and message are at the end.
    _TRACEBACK_FACTOR = 4

    def __init__(self, max_field_length: int = 2048) -> None:
        self._max_length = max_field_length

    def __call__(self, logger: WrappedLogger, method_name: str, event_dict: EventDict) -> EventDict:
        traceback = event_dict.pop("exception", None)
        redacted: EventDict = redact(event_dict, max_length=self._max_length)
        if isinstance(traceback, str):
            text = redact_text(traceback)
            limit = self._max_length * self._TRACEBACK_FACTOR
            if len(text) > limit:
                text = f"[truncated {len(text) - limit} chars]…{text[-limit:]}"
            redacted["exception"] = text
        elif traceback is not None:
            redacted["exception"] = redact(traceback, max_length=self._max_length)
        return redacted

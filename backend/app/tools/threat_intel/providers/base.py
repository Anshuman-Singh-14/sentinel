"""The provider contract and the HTTP plumbing every provider shares.

A provider turns one indicator into a ``Reputation``: a common model
(verdict, normalised 0-100 score, categories, last seen, a link to the
provider's own page) plus a small, whitelisted ``details`` dict. The full
provider response is never stored or logged: it can be large, and some
providers echo request parameters back.

``ProviderHttp`` gives every provider the same behaviour:

* a request budget per provider, shared by all workers (Redis window);
* HTTP 429/503 retried at most twice, honouring ``Retry-After``, otherwise
  exponential backoff with full jitter;
* a response size cap, no redirects, no proxy settings from the environment;
* user-safe errors. Exception text from httpx can contain the request URL,
  and Shodan's key travels in the query string, so errors carry only a fixed
  message and a code, never ``str(exc)``.
"""

import asyncio
import random
import time
from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any, ClassVar

import httpx

from app.core.external import WindowLimiter
from app.tools.threat_intel.indicators import Indicator, IndicatorKind

MAX_RESPONSE_BYTES = 1_000_000
RETRY_STATUSES = frozenset({429, 503})
MAX_ATTEMPTS = 3
BACKOFF_BASE_SECONDS = 1.0
BACKOFF_CAP_SECONDS = 8.0
MAX_RETRY_AFTER_SECONDS = 10.0
MAX_WINDOW_WAIT_SECONDS = 20.0
WINDOW_SECONDS = 60


class Verdict(StrEnum):
    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    HARMLESS = "HARMLESS"
    UNKNOWN = "UNKNOWN"  # the provider has data, but no reputation judgement (Shodan)
    NOT_FOUND = "NOT_FOUND"  # the provider has never seen the indicator


@dataclass(slots=True)
class Reputation:
    provider: str
    provider_name: str
    indicator: str
    kind: str
    verdict: Verdict
    score: int | None  # 0-100, provider-specific meaning, documented per provider
    categories: list[str] = field(default_factory=list)
    last_seen: str | None = None
    link: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["verdict"] = self.verdict.value
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Reputation":
        return cls(**{**data, "verdict": Verdict(data["verdict"])})


class ProviderError(Exception):
    """A lookup failed. ``message`` is safe to show to the user and to store."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def backoff_delay(attempt: int, retry_after: str | None) -> float:
    """Seconds to wait before retry ``attempt`` (0-based)."""
    if retry_after and retry_after.strip().isdigit():
        return min(float(retry_after.strip()), MAX_RETRY_AFTER_SECONDS)
    # Full jitter (AWS architecture blog): spreads retries from many workers.
    ceiling = min(BACKOFF_CAP_SECONDS, BACKOFF_BASE_SECONDS * 2**attempt)
    return random.uniform(0, ceiling)  # noqa: S311  (jitter, not cryptography)


class ProviderHttp:
    def __init__(
        self,
        client: httpx.AsyncClient,
        limiter: WindowLimiter,
        *,
        sleep: Any = asyncio.sleep,
    ) -> None:
        self.client = client
        self.limiter = limiter
        self.sleep = sleep
        self.requests_made = 0

    async def _wait_for_slot(self, provider: str, per_minute: int) -> None:
        deadline = time.monotonic() + MAX_WINDOW_WAIT_SECONDS
        while True:
            wait = await self.limiter.try_acquire(
                f"sentinel:intel:window:{provider}", per_minute, WINDOW_SECONDS
            )
            if wait <= 0:
                return
            if time.monotonic() + wait > deadline:
                raise ProviderError(
                    "rate_limited",
                    "Sentinel's request budget for this provider is used up; try again shortly.",
                )
            await self.sleep(wait)

    async def get_json(
        self,
        provider: "Provider",
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, str] | None = None,
    ) -> dict[str, Any] | None:
        """GET and parse JSON. ``None`` means the provider does not know the indicator (404)."""
        for attempt in range(MAX_ATTEMPTS):
            await self._wait_for_slot(provider.provider_id, provider.requests_per_minute)
            self.requests_made += 1
            try:
                response = await self.client.get(url, headers=headers, params=params)
            except httpx.TimeoutException:
                raise ProviderError("timeout", "The provider did not answer in time.") from None
            except httpx.HTTPError:
                raise ProviderError("unreachable", "The provider could not be reached.") from None
            status = response.status_code
            if status == 200:
                if len(response.content) > MAX_RESPONSE_BYTES:
                    raise ProviderError("too_large", "The provider's answer was too large.")
                try:
                    data = response.json()
                except ValueError:
                    raise ProviderError(
                        "bad_response", "The provider's answer was unreadable."
                    ) from None
                if not isinstance(data, dict):
                    raise ProviderError("bad_response", "The provider's answer was unexpected.")
                return data
            if status == 404:
                return None
            if status in (401, 403):
                raise ProviderError("auth", "The provider rejected the API key (check it).")
            if status in RETRY_STATUSES and attempt < MAX_ATTEMPTS - 1:
                await self.sleep(backoff_delay(attempt, response.headers.get("Retry-After")))
                continue
            if status in RETRY_STATUSES:
                raise ProviderError(
                    "rate_limited", "The provider is throttling requests; try again later."
                )
            raise ProviderError("http_error", f"The provider answered with HTTP {status}.")
        raise ProviderError(
            "rate_limited", "The provider kept throttling requests."
        )  # pragma: no cover


class Provider(ABC):
    provider_id: ClassVar[str]
    name: ClassVar[str]
    supports: ClassVar[frozenset[IndicatorKind]]
    # What the normalised score means for this provider (shown in findings).
    score_meaning: ClassVar[str]

    def __init__(self, api_key: str, base_url: str, requests_per_minute: int) -> None:
        self._api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.requests_per_minute = requests_per_minute

    def __repr__(self) -> str:  # never print the key
        return f"{type(self).__name__}(base_url={self.base_url!r})"

    @abstractmethod
    async def lookup(self, http: ProviderHttp, indicator: Indicator) -> Reputation: ...

    def _result(self, indicator: Indicator, **values: Any) -> Reputation:
        return Reputation(
            provider=self.provider_id,
            provider_name=self.name,
            indicator=indicator.value,
            kind=indicator.kind.value,
            **values,
        )

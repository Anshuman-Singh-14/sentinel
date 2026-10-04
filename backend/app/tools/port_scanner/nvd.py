"""NVD CVE API 2.0 client with caching and rate limiting.

* **Query:** ``virtualMatchString=cpe:2.3:a:<vendor>:<product>:<version>``
  returns CVEs whose configurations include that product version, including
  version *ranges* ("all versions before 7.7").
* **Cache:** every answer (including "no CVEs") is cached as JSON for
  ``nvd_cache_hours``, so repeated scans do not hit the NVD again. JSON only,
  never pickle (CLAUDE.md rule 1).
* **Rate limit:** the NVD allows 5 requests per rolling 30 s without a key
  and 50 with one. A Redis fixed window shared by all workers keeps Sentinel
  under it. When the window is full the client waits (bounded) rather than
  getting itself blocked.
* **Throttling and errors:** HTTP 403/429/503 are retried twice with
  backoff (honouring Retry-After, capped). Any other failure raises
  ``NvdUnavailable``; the scan then completes without CVE data and says so.

Framework-free: HTTP client, cache and limiter are injected.
"""

import asyncio
import hashlib
import json
import math
import time
from dataclasses import asdict, dataclass
from typing import Any

import httpx

from app.core.external import Cache, WindowLimiter

MAX_CVES_PER_PRODUCT = 10
MAX_DESCRIPTION_CHARS = 400
WINDOW_SECONDS = 30
RETRY_STATUSES = frozenset({403, 429, 503})
MAX_RETRY_WAIT_SECONDS = 10.0
MAX_WINDOW_WAIT_SECONDS = 31.0


class NvdUnavailable(Exception):
    """The NVD could not be queried; the message is user-safe."""


@dataclass(frozen=True, slots=True)
class CveRecord:
    cve_id: str
    score: float | None
    cvss_version: str | None
    vector: str | None
    description: str
    published: str | None

    @property
    def url(self) -> str:
        return f"https://nvd.nist.gov/vuln/detail/{self.cve_id}"


def _metric(metrics: dict[str, Any]) -> tuple[float | None, str | None, str | None]:
    for key, version in (
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    ):
        entries = metrics.get(key) or []
        # Prefer the NVD's own (Primary) assessment over a CNA's.
        entries = sorted(entries, key=lambda m: m.get("type") != "Primary")
        if entries:
            data = entries[0].get("cvssData", {})
            score = data.get("baseScore")
            if isinstance(score, (int, float)) and math.isfinite(score) and 0 <= score <= 10:
                return float(score), version, data.get("vectorString")
    return None, None, None


def parse_response(payload: dict[str, Any]) -> list[CveRecord]:
    records: list[CveRecord] = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not isinstance(cve_id, str) or not cve_id.startswith("CVE-"):
            continue
        if cve.get("vulnStatus") == "Rejected":
            continue
        description = next(
            (d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), ""
        )
        score, version, vector = _metric(cve.get("metrics", {}))
        records.append(
            CveRecord(
                cve_id=cve_id,
                score=score,
                cvss_version=version,
                vector=vector,
                description=description[:MAX_DESCRIPTION_CHARS],
                published=cve.get("published"),
            )
        )
    records.sort(key=lambda r: (r.score is None, -(r.score or 0), r.cve_id))
    return records[:MAX_CVES_PER_PRODUCT]


class NvdClient:
    def __init__(
        self,
        http: httpx.AsyncClient,
        cache: Cache,
        limiter: WindowLimiter,
        *,
        base_url: str,
        api_key: str | None,
        cache_ttl_seconds: int,
    ) -> None:
        self.http = http
        self.cache = cache
        self.limiter = limiter
        self.base_url = base_url
        self.api_key = api_key
        self.cache_ttl = cache_ttl_seconds
        self.requests_made = 0

    @property
    def window_limit(self) -> int:
        # One below the NVD's published limits (50 / 5 per rolling 30 s):
        # Sentinel's window is fixed, not rolling, so leave a margin.
        return 49 if self.api_key else 4

    async def cves_for(self, cpe_match: str) -> tuple[list[CveRecord], bool]:
        """CVEs for a ``cpe:2.3:a:vendor:product:version`` prefix. Returns (records, from_cache)."""
        key = "sentinel:nvd:v1:" + hashlib.sha256(cpe_match.encode()).hexdigest()
        cached = await self.cache.get(key)
        if cached is not None:
            return [CveRecord(**r) for r in json.loads(cached)], True
        payload = await self._fetch(cpe_match)
        records = parse_response(payload)
        await self.cache.set(key, json.dumps([asdict(r) for r in records]), self.cache_ttl)
        return records, False

    async def _wait_for_slot(self) -> None:
        deadline = time.monotonic() + MAX_WINDOW_WAIT_SECONDS
        while True:
            wait = await self.limiter.try_acquire(
                "sentinel:nvd:window", self.window_limit, WINDOW_SECONDS
            )
            if wait <= 0:
                return
            if time.monotonic() + wait > deadline:
                raise NvdUnavailable("The NVD request quota is used up; try again in a minute.")
            await asyncio.sleep(wait)

    async def _fetch(self, cpe_match: str) -> dict[str, Any]:
        headers = {"apiKey": self.api_key} if self.api_key else {}
        # Rejected CVEs are filtered in parse_response.
        params = {"virtualMatchString": cpe_match, "resultsPerPage": "100"}
        for attempt in range(3):
            await self._wait_for_slot()
            self.requests_made += 1
            try:
                response = await self.http.get(self.base_url, params=params, headers=headers)
            except httpx.HTTPError:
                raise NvdUnavailable("The NVD could not be reached.") from None
            if response.status_code == 200:
                try:
                    data = response.json()
                except ValueError:
                    raise NvdUnavailable("The NVD returned an unreadable response.") from None
                if not isinstance(data, dict):
                    raise NvdUnavailable("The NVD returned an unexpected response.")
                return data
            if response.status_code == 404:
                return {"vulnerabilities": []}  # unknown CPE: no CVEs
            if response.status_code in RETRY_STATUSES and attempt < 2:
                retry_after = response.headers.get("Retry-After", "")
                wait = float(retry_after) if retry_after.isdigit() else 2.0 * (attempt + 1)
                await asyncio.sleep(min(wait, MAX_RETRY_WAIT_SECONDS))
                continue
            raise NvdUnavailable(f"The NVD answered with HTTP {response.status_code}.")
        raise NvdUnavailable("The NVD kept throttling requests.")  # pragma: no cover

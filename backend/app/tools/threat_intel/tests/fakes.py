"""Mock provider APIs (httpx.MockTransport) and in-memory cache/limiter: no network."""

import json
import uuid
from collections.abc import Callable
from typing import Any

import httpx
import structlog

from app.engine.base_tool import ToolContext
from app.tools.threat_intel.providers.abuseipdb import AbuseIpdbProvider
from app.tools.threat_intel.providers.base import ProviderHttp
from app.tools.threat_intel.providers.shodan import ShodanProvider
from app.tools.threat_intel.providers.virustotal import VirusTotalProvider

ABUSE_KEY = "abuse-test-key-0123456789"
VT_KEY = "vt-test-key-0123456789"
SHODAN_KEY = "shodan-test-key-0123456789"
ALL_KEYS = (ABUSE_KEY, VT_KEY, SHODAN_KEY)


def abuseipdb() -> AbuseIpdbProvider:
    return AbuseIpdbProvider(ABUSE_KEY, "https://abuse.test/api/v2", 1000)


def virustotal() -> VirusTotalProvider:
    return VirusTotalProvider(VT_KEY, "https://vt.test/api/v3", 1000)


def shodan() -> ShodanProvider:
    return ShodanProvider(SHODAN_KEY, "https://shodan.test", 1000)


def abuse_payload(score: int, reports: int = 12, reporters: int = 6) -> dict[str, Any]:
    return {
        "data": {
            "ipAddress": "45.33.32.156",
            "isPublic": True,
            "abuseConfidenceScore": score,
            "countryCode": "NL",
            "usageType": "Data Center/Web Hosting/Transit",
            "isp": "Example Hosting",
            "totalReports": reports,
            "numDistinctUsers": reporters,
            "lastReportedAt": "2026-10-03T21:14:00+00:00",
            "isWhitelisted": False,
        }
    }


def vt_payload(malicious: int, suspicious: int = 0, harmless: int = 60) -> dict[str, Any]:
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": 10,
                    "timeout": 0,
                },
                "reputation": -12,
                "categories": {"Forcepoint": "malicious web sites", "Sophos": "phishing"},
                "last_analysis_date": 1790000000,
                "as_owner": "Example AS",
                "country": "NL",
                "tags": ["self-signed"],
            }
        }
    }


SHODAN_HOST = {
    "ip_str": "45.33.32.156",
    "ports": [22, 80, 443, 3306],
    "vulns": ["CVE-2023-38408", "CVE-2021-41617"],
    "hostnames": ["host.example"],
    "org": "Example Hosting",
    "os": None,
    "country_name": "Netherlands",
    "last_update": "2026-10-01T10:00:00",
    "tags": ["cloud"],
}

Handler = Callable[[httpx.Request], httpx.Response]


class Recorder:
    """Routes requests by host and records them (to prove what was, and was not, sent)."""

    def __init__(self, routes: dict[str, Handler]) -> None:
        self.routes = routes
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        handler = self.routes.get(request.url.host)
        if handler is None:
            raise AssertionError(f"unexpected request to {request.url.host}")
        return handler(request)

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self)


def json_response(payload: Any, status: int = 200, **headers: str) -> httpx.Response:
    return httpx.Response(status, content=json.dumps(payload).encode(), headers=headers)


class MemoryCache:
    def __init__(self) -> None:
        self.data: dict[str, str] = {}

    async def get(self, key: str) -> str | None:
        return self.data.get(key)

    async def set(self, key: str, value: str, ttl_seconds: int) -> None:
        self.data[key] = value


class OpenLimiter:
    async def try_acquire(self, key: str, limit: int, window_seconds: int) -> float:
        return 0.0


class FullLimiter:
    async def try_acquire(self, key: str, limit: int, window_seconds: int) -> float:
        return 60.0


async def no_sleep(_: float) -> None:
    return None


def http_for(recorder: Recorder, limiter: Any = None) -> ProviderHttp:
    client = httpx.AsyncClient(transport=recorder.transport(), timeout=5)
    return ProviderHttp(client, limiter or OpenLimiter(), sleep=no_sleep)


def context() -> ToolContext:
    return ToolContext(run_id=uuid.uuid4(), logger=structlog.get_logger())

"""Shodan host lookup (https://developer.shodan.io/api): what the internet sees.

Shodan does not judge reputation: it reports which ports and services its
crawlers found open on an address, and CVEs it associates with them. For a
defender that is an exposure view of their own public addresses, so the
verdict is UNKNOWN and the score is unused; the translator turns open ports
and listed CVEs into exposure findings.

Shodan's API takes the key as a query parameter. That is why ProviderHttp
never puts exception text or URLs into errors, and httpx's own logger is
held at WARNING (threat model T19).
"""

from typing import Any

from app.tools.threat_intel.indicators import Indicator, IndicatorKind
from app.tools.threat_intel.providers.base import Provider, ProviderHttp, Reputation, Verdict

MAX_PORTS = 50
MAX_VULNS = 20


class ShodanProvider(Provider):
    provider_id = "shodan"
    name = "Shodan"
    supports = frozenset({IndicatorKind.IP})
    score_meaning = "not scored (Shodan reports exposure, not reputation)"

    async def lookup(self, http: ProviderHttp, indicator: Indicator) -> Reputation:
        payload = await http.get_json(
            self,
            f"{self.base_url}/shodan/host/{indicator.value}",
            params={"key": self._api_key, "minify": "true"},
        )
        link = f"https://www.shodan.io/host/{indicator.value}"
        if not payload:
            return self._result(indicator, verdict=Verdict.NOT_FOUND, score=None, link=link)
        ports = sorted({p for p in payload.get("ports") or [] if isinstance(p, int)})[:MAX_PORTS]
        vulns_raw = payload.get("vulns") or []
        vulns = sorted(
            {
                v
                for v in (vulns_raw if isinstance(vulns_raw, list) else list(vulns_raw))
                if isinstance(v, str)
            }
        )[:MAX_VULNS]
        return self._result(
            indicator,
            verdict=Verdict.UNKNOWN,
            score=None,
            categories=[str(t)[:40] for t in (payload.get("tags") or [])][:10],
            last_seen=payload.get("last_update")
            if isinstance(payload.get("last_update"), str)
            else None,
            link=link,
            details={
                "open_ports": ports,
                "vulns": vulns,
                "hostnames": [str(h)[:120] for h in (payload.get("hostnames") or [])][:10],
                "org": _text(payload.get("org")),
                "os": _text(payload.get("os")),
                "country": _text(payload.get("country_name")),
            },
        )


def _text(value: Any, limit: int = 120) -> str | None:
    return value[:limit] if isinstance(value, str) else None

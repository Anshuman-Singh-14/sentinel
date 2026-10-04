"""VirusTotal API v3 (https://docs.virustotal.com/reference/overview).

IPs, domains and file hashes. Each object carries ``last_analysis_stats``:
how many of VirusTotal's security vendors flag it as malicious or
suspicious. Score: the percentage of vendors with an opinion (malicious,
suspicious, harmless or undetected) that flag it as malicious.
"""

from datetime import UTC, datetime
from typing import Any

from app.tools.threat_intel.indicators import Indicator, IndicatorKind
from app.tools.threat_intel.providers.base import Provider, ProviderHttp, Reputation, Verdict

MALICIOUS_ENGINES = 3  # at least this many vendors flagging malicious: MALICIOUS
_PATHS = {
    IndicatorKind.IP: ("ip_addresses", "ip-address"),
    IndicatorKind.DOMAIN: ("domains", "domain"),
    IndicatorKind.HASH: ("files", "file"),
}


class VirusTotalProvider(Provider):
    provider_id = "virustotal"
    name = "VirusTotal"
    supports = frozenset({IndicatorKind.IP, IndicatorKind.DOMAIN, IndicatorKind.HASH})
    score_meaning = "share of VirusTotal vendors flagging it as malicious (%)"

    async def lookup(self, http: ProviderHttp, indicator: Indicator) -> Reputation:
        api_path, gui_path = _PATHS[indicator.kind]
        payload = await http.get_json(
            self,
            f"{self.base_url}/{api_path}/{indicator.value}",
            headers={"x-apikey": self._api_key, "Accept": "application/json"},
        )
        link = f"https://www.virustotal.com/gui/{gui_path}/{indicator.value}"
        attributes: dict[str, Any] = ((payload or {}).get("data") or {}).get("attributes") or {}
        if not attributes:
            return self._result(indicator, verdict=Verdict.NOT_FOUND, score=None, link=link)
        stats = attributes.get("last_analysis_stats") or {}
        counts = {
            key: int(stats.get(key) or 0)
            for key in ("malicious", "suspicious", "harmless", "undetected")
        }
        judged = sum(counts.values())
        score = round(counts["malicious"] / judged * 100) if judged else None
        if counts["malicious"] >= MALICIOUS_ENGINES:
            verdict = Verdict.MALICIOUS
        elif counts["malicious"] or counts["suspicious"]:
            verdict = Verdict.SUSPICIOUS
        elif judged:
            verdict = Verdict.HARMLESS
        else:
            verdict = Verdict.UNKNOWN
        categories = attributes.get("categories") or {}
        last = attributes.get("last_analysis_date")
        return self._result(
            indicator,
            verdict=verdict,
            score=score,
            categories=sorted({str(c)[:60] for c in categories.values()})[:10]
            if isinstance(categories, dict)
            else [],
            last_seen=datetime.fromtimestamp(last, UTC).isoformat()
            if isinstance(last, int)
            else None,
            link=link,
            details={
                "engines": counts,
                "community_reputation": attributes.get("reputation")
                if isinstance(attributes.get("reputation"), int)
                else None,
                "tags": [str(t)[:40] for t in (attributes.get("tags") or [])][:10],
                "owner": _text(attributes.get("as_owner")),
                "country": _text(attributes.get("country")),
                "file_name": _text(attributes.get("meaningful_name")),
            },
        )


def _text(value: Any, limit: int = 120) -> str | None:
    return value[:limit] if isinstance(value, str) else None

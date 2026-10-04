"""AbuseIPDB (https://docs.abuseipdb.com/#check-endpoint): IP abuse reports.

Score: AbuseIPDB's ``abuseConfidenceScore`` (0-100), its own estimate of how
likely the address is abusive, based on recent community reports.
"""

from typing import Any

from app.tools.threat_intel.indicators import Indicator, IndicatorKind
from app.tools.threat_intel.providers.base import Provider, ProviderHttp, Reputation, Verdict

MALICIOUS_FROM = 75
SUSPICIOUS_FROM = 1


class AbuseIpdbProvider(Provider):
    provider_id = "abuseipdb"
    name = "AbuseIPDB"
    supports = frozenset({IndicatorKind.IP})
    score_meaning = "AbuseIPDB abuse confidence score (0-100)"

    async def lookup(self, http: ProviderHttp, indicator: Indicator) -> Reputation:
        payload = await http.get_json(
            self,
            f"{self.base_url}/check",
            headers={"Key": self._api_key, "Accept": "application/json"},
            params={"ipAddress": indicator.value, "maxAgeInDays": "90"},
        )
        link = f"https://www.abuseipdb.com/check/{indicator.value}"
        data: dict[str, Any] = (payload or {}).get("data") or {}
        if not data:
            return self._result(indicator, verdict=Verdict.NOT_FOUND, score=None, link=link)
        raw_score = data.get("abuseConfidenceScore")
        score = int(raw_score) if isinstance(raw_score, int | float) else 0
        score = max(0, min(100, score))
        reports = int(data.get("totalReports") or 0)
        if score >= MALICIOUS_FROM:
            verdict = Verdict.MALICIOUS
        elif score >= SUSPICIOUS_FROM:
            verdict = Verdict.SUSPICIOUS
        else:
            verdict = Verdict.HARMLESS
        return self._result(
            indicator,
            verdict=verdict,
            score=score,
            last_seen=data.get("lastReportedAt")
            if isinstance(data.get("lastReportedAt"), str)
            else None,
            link=link,
            details={
                "total_reports": reports,
                "distinct_reporters": int(data.get("numDistinctUsers") or 0),
                "country": _text(data.get("countryCode")),
                "usage_type": _text(data.get("usageType")),
                "isp": _text(data.get("isp")),
                "whitelisted": bool(data.get("isWhitelisted")),
            },
        )


def _text(value: Any, limit: int = 120) -> str | None:
    return value[:limit] if isinstance(value, str) else None

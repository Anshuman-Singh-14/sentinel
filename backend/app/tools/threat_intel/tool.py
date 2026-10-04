from typing import Any, ClassVar

import httpx

from app.config import get_settings
from app.core.errors import ProviderError as ProviderUnavailable
from app.core.external import RedisCache, RedisWindowLimiter
from app.core.tasks.queues import INTEL_QUEUE
from app.engine.base_tool import BaseTool, RawOutput, ToolAvailability, ToolContext
from app.engine.schemas import Finding, ToolCategory
from app.tools.threat_intel import providers as registry
from app.tools.threat_intel import service, translator
from app.tools.threat_intel.providers.base import ProviderHttp
from app.tools.threat_intel.schemas import ThreatIntelParams


class ThreatIntelTool(BaseTool[ThreatIntelParams]):
    """Threat Intelligence Integrator (02-modules.md, backend tool 3). Passive.

    Passive towards the target: nothing is sent to the indicators themselves,
    so no scope check applies. What does leave Sentinel is the indicator
    value, sent to the configured third-party services. Private addresses
    are never sent (see indicators.py), and the tool description says so.
    """

    tool_id = "threat_intel"
    name = "Threat Intelligence"
    description = (
        "Checks IP addresses, domains and file hashes against AbuseIPDB, VirusTotal and "
        "Shodan, and explains what their reputation data means. The indicators you enter are "
        "sent to those services; private addresses never are."
    )
    version = "1.0.0"
    category = ToolCategory.INTEL
    params_model = ThreatIntelParams
    queue = INTEL_QUEUE
    soft_time_limit = 90
    hard_time_limit = 120
    # Test seam: integration tests route provider traffic to a mock transport.
    http_transport: ClassVar[httpx.AsyncBaseTransport | None] = None

    @classmethod
    def availability(cls) -> ToolAvailability:
        settings = get_settings()
        status = registry.status(settings)
        if any(p["configured"] for p in status):
            return ToolAvailability(details={"providers": status})
        return ToolAvailability(
            available=False,
            reason=(
                "No threat-intelligence provider is configured. An administrator must set "
                "ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY or SHODAN_API_KEY."
            ),
            details={"providers": status},
        )

    async def run(self, params: ThreatIntelParams, ctx: ToolContext) -> RawOutput:
        settings = get_settings()
        providers = registry.configured(settings)
        if not providers:
            raise ProviderUnavailable("No threat-intelligence provider is configured.")
        timeout = httpx.Timeout(settings.threat_intel_timeout_seconds, connect=5.0)
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
            transport=self.http_transport,
            headers={"User-Agent": "Sentinel threat-intel (defensive lookups)"},
        ) as client:
            raw = await service.investigate(
                params.parsed(),
                providers,
                ProviderHttp(client, RedisWindowLimiter()),
                RedisCache(),
                ctx,
                timeout_seconds=settings.threat_intel_timeout_seconds,
                cache_ttl_seconds=settings.threat_intel_cache_hours * 3600,
            )
        if raw["lookups_planned"] and not raw["results"]:
            # Every lookup failed: a FAILED run, not an empty "all clear".
            raise ProviderUnavailable(
                "No provider answered. " + "; ".join(e.message for e in ctx.errors)
            )
        await ctx.report_progress(100, "Done")
        return raw

    def translate(self, raw: RawOutput, params: ThreatIntelParams) -> list[Finding]:
        return translator.translate(raw)

    def target_of(self, params: ThreatIntelParams) -> str:
        first: Any = params.indicators[0]
        more = len(params.indicators) - 1
        return f"{first} (+{more} more)" if more else str(first)

from app.config import get_settings
from app.engine.base_tool import BaseTool, RawOutput, ToolContext
from app.engine.schemas import Finding, ToolCategory
from app.tools.dns_lookup import service, translator
from app.tools.dns_lookup.schemas import DnsLookupParams


class DnsLookupTool(BaseTool[DnsLookupParams]):
    """DNS & Domain Intelligence (02-modules.md, backend tool 2).

    Passive: it only asks DNS resolvers about public records and sends nothing
    to the target's own hosts, so it needs no scope authorisation.
    """

    tool_id = "dns_lookup"
    name = "DNS & Domain Intelligence"
    description = (
        "Collects A, AAAA, CNAME, MX, NS, TXT, SOA and CAA records and checks email "
        "anti-spoofing (SPF, DMARC), certificate restrictions (CAA), dangling CNAMEs and "
        "name server redundancy."
    )
    version = "1.0.0"
    category = ToolCategory.RECON
    params_model = DnsLookupParams
    is_active = False
    soft_time_limit = 30
    hard_time_limit = 45

    async def run(self, params: DnsLookupParams, ctx: ToolContext) -> RawOutput:
        settings = get_settings()
        resolver = service.build_resolver(
            service.ResolverConfig(
                nameservers=settings.dns_nameservers,
                timeout=settings.dns_timeout_seconds,
                lifetime=settings.dns_lifetime_seconds,
            )
        )
        raw = await service.lookup(params.domain, params.include_reverse, resolver, ctx)
        raw["resolver"] = list(settings.dns_nameservers) or "system"
        return raw

    def translate(self, raw: RawOutput, params: DnsLookupParams) -> list[Finding]:
        return translator.translate(raw, params)

    def target_of(self, params: DnsLookupParams) -> str:
        return params.domain

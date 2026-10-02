import ssl
from dataclasses import asdict
from typing import Any

import httpx

from app.config import get_settings
from app.core.errors import ScopeDenied
from app.engine.base_tool import BaseTool, RawOutput, ToolContext
from app.engine.schemas import Finding, ToolCategory
from app.tools.header_tls import service, tls, translator
from app.tools.header_tls.schemas import HeaderTlsParams


def trust_context() -> ssl.SSLContext:
    """The trust store for verification (system CAs). Tests swap in a test CA."""
    return tls.verified_context()


class HeaderTlsTool(BaseTool[HeaderTlsParams]):
    """HTTP Security Header & TLS Checker (02-modules.md, backend tool 4). Active."""

    tool_id = "header_tls"
    name = "HTTP Security Header & TLS Checker"
    description = (
        "Fetches an in-scope URL (following redirects safely) and checks its security "
        "headers, cookie flags, HTTPS redirect and TLS certificate, with nginx and Apache "
        "remediation snippets."
    )
    version = "1.0.0"
    category = ToolCategory.WEB
    params_model = HeaderTlsParams
    is_active = True
    soft_time_limit = 60
    hard_time_limit = 90

    async def run(self, params: HeaderTlsParams, ctx: ToolContext) -> RawOutput:
        if not ctx.authorized_addresses:
            raise ScopeDenied("No scope-approved address for this target.")
        settings = get_settings()
        allowed_ports = frozenset(settings.web_check_allowed_ports)
        start = params.target()
        raw: dict[str, Any] = {"url": str(start), "host": start.host, "hops": []}

        await ctx.report_progress(5, f"Requesting {start}")
        fetcher = service.Fetcher(
            settings.web_check_timeout_seconds, settings.web_check_max_body_bytes, trust_context()
        )
        try:
            crawl = await service.crawl(
                start,
                ctx.authorized_addresses,
                fetcher,
                ctx,
                allowed_ports=allowed_ports,
                max_redirects=settings.web_check_max_redirects,
            )
            raw["hops"] = [asdict(h) for h in crawl.hops]
            raw["final"] = None
            if crawl.final is not None:
                raw["final"] = asdict(crawl.final)
                raw["final"]["headers"] = [list(h) for h in crawl.final.headers]
            final_target = crawl.final_target
            await ctx.report_progress(50, "Response received" if crawl.final else "No response")
            if final_target is None:
                return raw
            raw["final_host"] = final_target.host
            address = service.pick_address(crawl.final_addresses)

            if final_target.is_https:
                await ctx.raise_if_cancelled()
                await ctx.report_progress(60, "Inspecting TLS")
                info = await tls.inspect_tls(
                    address, final_target.port, final_target.host, verify_context=trust_context()
                )
                raw["tls"] = tls.tls_to_dict(info)
                if params.check_http_redirect and final_target.default_port and 80 in allowed_ports:
                    await ctx.report_progress(85, "Checking the HTTP to HTTPS redirect")
                    raw["http_probe"] = await self._http_probe(
                        fetcher, final_target.with_scheme("http", 80), address
                    )
            elif 443 in allowed_ports:
                await ctx.report_progress(70, "Checking whether HTTPS is offered")
                info = await tls.inspect_tls(address, 443, final_target.host)
                raw["https_probe"] = {"available": info.reachable}
        finally:
            await fetcher.aclose()
        await ctx.report_progress(100, "Done")
        return raw

    @staticmethod
    async def _http_probe(fetcher: service.Fetcher, target: Any, address: str) -> dict[str, Any]:
        try:
            response, _, _ = await fetcher.get(target, address)
        except httpx.HTTPError as exc:
            # Port 80 closed is fine: nothing is served over clear text.
            return {"url": str(target), "status": None, "error": type(exc).__name__}
        location = response.headers.get("location", "")
        return {
            "url": str(target),
            "status": response.status_code,
            "location": location[:500],
            "redirects_to_https": response.status_code in service.REDIRECT_STATUSES
            and location.lower().startswith(f"https://{target.host}"),
        }

    def translate(self, raw: RawOutput, params: HeaderTlsParams) -> list[Finding]:
        return translator.translate(raw, params)

    def target_of(self, params: HeaderTlsParams) -> str:
        return params.url

    def scope_host(self, params: HeaderTlsParams) -> str:
        return params.target().host

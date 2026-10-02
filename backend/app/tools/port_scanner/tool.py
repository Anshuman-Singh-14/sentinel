import ipaddress
from dataclasses import asdict
from typing import Any

import httpx

from app.config import get_settings
from app.core.errors import ScopeDenied
from app.core.runs.events import get_redis
from app.engine.base_tool import BaseTool, RawOutput, ToolContext
from app.engine.schemas import Finding, ToolCategory
from app.tools.port_scanner import service, translator
from app.tools.port_scanner.nvd import NvdClient, NvdUnavailable
from app.tools.port_scanner.schemas import PortScanParams


class RedisCache:
    async def get(self, key: str) -> str | None:
        value = await get_redis().get(key)
        return str(value) if value is not None else None

    async def set(self, key: str, value: str, ttl_seconds: int) -> None:
        await get_redis().set(key, value, ex=ttl_seconds)


class RedisWindowLimiter:
    """Fixed window shared by every worker process.

    A request that does not fit is handed back (DECR), so waiting callers do
    not use up the next window's quota just by asking.
    """

    async def try_acquire(self, key: str, limit: int, window_seconds: int) -> float:
        redis = get_redis()
        async with redis.pipeline(transaction=True) as pipe:
            pipe.incr(key)
            pipe.expire(key, window_seconds, nx=True)
            pipe.ttl(key)
            count, _, ttl = await pipe.execute()
        if int(count) <= limit:
            return 0.0
        await redis.decr(key)
        return float(ttl if isinstance(ttl, int) and ttl > 0 else window_seconds)


def pick_address(addresses: tuple[str, ...]) -> str:
    """Scan one address: the first IPv4 if there is one (lab networks are IPv4)."""
    for address in addresses:
        if ipaddress.ip_address(address).version == 4:
            return address
    return addresses[0]


class PortScannerTool(BaseTool[PortScanParams]):
    """Port Scanner & Banner Grabber (02-modules.md, backend tool 1). Active."""

    tool_id = "port_scanner"
    name = "Port Scanner & Banner Grabber"
    description = (
        "TCP connect scan of an in-scope host: finds open ports, explains what each exposed "
        "service means, reads service banners and matches identified versions against known "
        "CVEs in the NVD."
    )
    version = "1.0.0"
    category = ToolCategory.RECON
    params_model = PortScanParams
    is_active = True
    queue = "scans"
    soft_time_limit = 300
    hard_time_limit = 360

    async def run(self, params: PortScanParams, ctx: ToolContext) -> RawOutput:
        if not ctx.authorized_addresses:
            # Defence in depth: the framework must have run the scope check.
            raise ScopeDenied("No scope-approved address for this target.")
        settings = get_settings()
        address = pick_address(ctx.authorized_addresses)
        config = service.ScanConfig(
            concurrency=settings.port_scan_concurrency,
            connect_timeout=settings.port_scan_connect_timeout_seconds,
            banner_timeout=settings.port_scan_banner_timeout_seconds,
            grab_banners=params.grab_banners,
        )
        await ctx.report_progress(1, f"Scanning {address}")
        raw = await service.scan(address, params.port_list(), config, ctx)
        raw["target"] = params.target
        raw["resolved_addresses"] = list(ctx.authorized_addresses)
        raw["cve_lookup"] = {"enabled": params.cve_lookup, "queried": [], "errors": []}
        raw["cves"] = {}
        if params.cve_lookup:
            await self._enrich(raw, ctx)
        await ctx.report_progress(100, "Done")
        return raw

    async def _enrich(self, raw: dict[str, Any], ctx: ToolContext) -> None:
        settings = get_settings()
        products = {
            tuple(p["product"]["cpe_candidates"])
            for p in raw["open"]
            if p.get("product") and p["product"]["cpe_candidates"]
        }
        if not products:
            return
        await ctx.report_progress(88, f"Looking up CVEs for {len(products)} product(s)")
        timeout = httpx.Timeout(settings.nvd_timeout_seconds)
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as http:
            client = NvdClient(
                http,
                RedisCache(),
                RedisWindowLimiter(),
                base_url=settings.nvd_base_url,
                api_key=settings.nvd_api_key.get_secret_value() if settings.nvd_api_key else None,
                cache_ttl_seconds=settings.nvd_cache_hours * 3600,
            )
            for candidates in sorted(products):
                await ctx.raise_if_cancelled()
                for cpe in candidates:
                    try:
                        records, cached = await client.cves_for(cpe)
                    except NvdUnavailable as exc:
                        raw["cve_lookup"]["errors"].append(str(exc))
                        ctx.add_error("cve_lookup_unavailable", f"CVE lookup skipped: {exc}")
                        return
                    raw["cve_lookup"]["queried"].append({"cpe": cpe, "cached": cached})
                    if records:
                        raw["cves"][cpe] = [asdict(r) | {"url": r.url} for r in records]
                        break

    def translate(self, raw: RawOutput, params: PortScanParams) -> list[Finding]:
        return translator.translate(raw, params)

    def target_of(self, params: PortScanParams) -> str:
        return params.target

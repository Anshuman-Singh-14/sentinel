"""Look indicators up across providers: concurrently, cached, partial on failure.

Every (indicator, provider) pair the provider supports becomes one lookup.
Lookups run concurrently (bounded), each under its own timeout, so one slow
or failing provider never blocks or fails the others: its failure is recorded
as a run error and the run completes with partial results (02-modules.md).

Results, including "not found", are cached per provider and indicator, so a
playbook re-run does not spend the provider quota again. Errors are not cached.
"""

import asyncio
import hashlib
import json
from typing import Any

from app.core.external import Cache
from app.engine.base_tool import ToolContext
from app.tools.threat_intel.indicators import Indicator
from app.tools.threat_intel.providers.base import Provider, ProviderError, ProviderHttp, Reputation

MAX_CONCURRENT_LOOKUPS = 4


def cache_key(provider: Provider, indicator: Indicator) -> str:
    digest = hashlib.sha256(f"{indicator.kind}:{indicator.value}".encode()).hexdigest()
    return f"sentinel:intel:v1:{provider.provider_id}:{digest}"


async def investigate(
    indicators: list[Indicator],
    providers: list[Provider],
    http: ProviderHttp,
    cache: Cache,
    ctx: ToolContext,
    *,
    timeout_seconds: float,
    cache_ttl_seconds: int,
) -> dict[str, Any]:
    pairs = [
        (indicator, provider)
        for indicator in indicators
        if indicator.lookup
        for provider in providers
        if indicator.kind in provider.supports
    ]
    results: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    cache_hits = 0
    done = 0
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_LOOKUPS)

    async def one(indicator: Indicator, provider: Provider) -> None:
        nonlocal cache_hits, done
        key = cache_key(provider, indicator)
        async with semaphore:
            await ctx.raise_if_cancelled()
            cached = await cache.get(key)
            if cached is not None:
                results.append(json.loads(cached))
                cache_hits += 1
            else:
                try:
                    reputation: Reputation = await asyncio.wait_for(
                        provider.lookup(http, indicator), timeout=timeout_seconds
                    )
                except TimeoutError:
                    failures.append(_failure(provider, indicator, "timeout", "No answer in time."))
                except ProviderError as exc:
                    failures.append(_failure(provider, indicator, exc.code, exc.message))
                else:
                    data = reputation.to_dict()
                    results.append(data)
                    await cache.set(key, json.dumps(data), cache_ttl_seconds)
        done += 1
        await ctx.report_progress(
            5 + round(done / max(len(pairs), 1) * 90), f"{done}/{len(pairs)} lookups done"
        )

    await ctx.report_progress(2, f"Looking up {len(pairs)} indicator/provider pair(s)")
    await asyncio.gather(*(one(indicator, provider) for indicator, provider in pairs))

    # One run error per provider, not per lookup: "VirusTotal: rate limited (3 lookups)".
    by_provider: dict[str, list[dict[str, str]]] = {}
    for failure in failures:
        by_provider.setdefault(failure["provider_name"], []).append(failure)
    for name, items in by_provider.items():
        ctx.add_error(
            f"provider_{items[0]['code']}",
            f"{name}: {items[0]['message']} ({len(items)} lookup(s) without an answer)",
        )

    order = {(i.value, p.provider_id): n for n, (i, p) in enumerate(pairs)}
    results.sort(key=lambda r: order.get((r["indicator"], r["provider"]), 0))
    return {
        "indicators": [
            {
                "value": i.value,
                "kind": i.kind.value,
                "lookup": i.lookup,
                "skip_reason": i.skip_reason,
            }
            for i in indicators
        ],
        "providers": [{"id": p.provider_id, "name": p.name} for p in providers],
        "lookups_planned": len(pairs),
        "cache_hits": cache_hits,
        "requests_made": http.requests_made,
        "results": results,
        "failures": failures,
    }


def _failure(provider: Provider, indicator: Indicator, code: str, message: str) -> dict[str, str]:
    return {
        "provider": provider.provider_id,
        "provider_name": provider.name,
        "indicator": indicator.value,
        "code": code,
        "message": message,
    }

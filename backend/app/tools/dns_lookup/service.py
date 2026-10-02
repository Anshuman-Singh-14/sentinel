"""DNS resolution for the dns_lookup tool. Pure async I/O, no framework imports.

Every query has a per-attempt timeout and an overall lifetime (CLAUDE.md
rule 7). Failures of individual record types are recorded and reported as
partial results; only a total failure to reach any resolver fails the run.
"""

import asyncio
import ipaddress
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.name
import dns.rdatatype
import dns.resolver
import dns.reversename

from app.core.errors import ProviderError
from app.engine.base_tool import RawOutput, ToolContext

RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA")
MAX_PTR_LOOKUPS = 10
MAX_RECORDS_PER_TYPE = 50
MAX_TXT_LENGTH = 4096
QUERY_CONCURRENCY = 5


@dataclass(frozen=True, slots=True)
class ResolverConfig:
    nameservers: Sequence[str]  # empty: use the system resolver
    timeout: float
    lifetime: float


def build_resolver(config: ResolverConfig) -> dns.asyncresolver.Resolver:
    resolver = dns.asyncresolver.Resolver(configure=not config.nameservers)
    if config.nameservers:
        resolver.nameservers = list(config.nameservers)
    resolver.timeout = config.timeout
    resolver.lifetime = config.lifetime
    return resolver


def _rdata_to_value(rtype: str, rdata: Any) -> Any:
    if rtype == "MX":
        return {"preference": int(rdata.preference), "exchange": rdata.exchange.to_text(True)}
    if rtype == "SOA":
        return {
            "mname": rdata.mname.to_text(True),
            "rname": rdata.rname.to_text(True),
            "serial": int(rdata.serial),
            "refresh": int(rdata.refresh),
            "retry": int(rdata.retry),
            "expire": int(rdata.expire),
            "minimum": int(rdata.minimum),
        }
    if rtype == "CAA":
        return {
            "flags": int(rdata.flags),
            "tag": rdata.tag.decode("ascii", "replace"),
            "value": rdata.value.decode("utf-8", "replace"),
        }
    if rtype == "TXT":
        return b"".join(rdata.strings).decode("utf-8", "replace")[:MAX_TXT_LENGTH]
    if rtype in ("NS", "CNAME", "PTR"):
        return rdata.target.to_text(True)
    return rdata.to_text()


@dataclass(slots=True)
class QueryOutcome:
    values: list[Any]
    error: str | None = None  # "nxdomain" | "timeout" | "no_nameservers" | "error"


async def query(resolver: dns.asyncresolver.Resolver, name: str, rtype: str) -> QueryOutcome:
    try:
        answer = await resolver.resolve(name, rtype, raise_on_no_answer=False)
    except dns.resolver.NXDOMAIN:
        return QueryOutcome([], "nxdomain")
    except dns.resolver.LifetimeTimeout:
        return QueryOutcome([], "timeout")
    except dns.resolver.NoNameservers:
        return QueryOutcome([], "no_nameservers")
    except dns.exception.DNSException:
        return QueryOutcome([], "error")
    if answer.rrset is None:
        return QueryOutcome([])
    values = [_rdata_to_value(rtype, rdata) for rdata in list(answer.rrset)[:MAX_RECORDS_PER_TYPE]]
    return QueryOutcome(values)


def _is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


async def lookup(
    domain: str,
    include_reverse: bool,
    resolver: dns.asyncresolver.Resolver,
    ctx: ToolContext,
) -> RawOutput:
    semaphore = asyncio.Semaphore(QUERY_CONCURRENCY)

    async def bounded(name: str, rtype: str) -> QueryOutcome:
        async with semaphore:
            return await query(resolver, name, rtype)

    await ctx.report_progress(5, f"Querying {len(RECORD_TYPES)} record types")
    outcomes = await asyncio.gather(
        *(bounded(domain, rtype) for rtype in RECORD_TYPES),
        bounded(f"_dmarc.{domain}", "TXT"),
        bounded(f"www.{domain}", "CNAME"),
    )
    by_type = dict(zip(RECORD_TYPES, outcomes[: len(RECORD_TYPES)], strict=True))
    dmarc, www_cname = outcomes[len(RECORD_TYPES)], outcomes[len(RECORD_TYPES) + 1]
    await ctx.raise_if_cancelled()
    await ctx.report_progress(55, "Records collected")

    errors = {rtype: o.error for rtype, o in by_type.items() if o.error}
    unreachable = {"timeout", "no_nameservers"}
    if (
        errors
        and all(error in unreachable for error in errors.values())
        and len(errors) == len(RECORD_TYPES)
    ):
        raise ProviderError("No DNS resolver answered. Check the worker's network access.")
    nxdomain = all(o.error == "nxdomain" for o in by_type.values())

    raw: dict[str, Any] = {
        "domain": domain,
        "nxdomain": nxdomain,
        "records": {rtype: o.values for rtype, o in by_type.items()},
        "record_errors": {rtype: error for rtype, error in errors.items() if error != "nxdomain"},
        "dmarc": dmarc.values,
        "resolved_ips": [],
        "ptr": {},
        "cname_checks": [],
    }
    for rtype, error in raw["record_errors"].items():
        ctx.add_error(f"dns_{error}", f"The {rtype} lookup did not complete ({error}).")
    if nxdomain:
        await ctx.report_progress(100, "Domain does not exist")
        return raw

    ips = [*by_type["A"].values, *by_type["AAAA"].values]
    raw["resolved_ips"] = ips

    # Dangling CNAMEs: a CNAME whose target no longer exists can be claimed by
    # whoever registers that target (subdomain takeover).
    checks = [(domain, by_type["CNAME"].values), (f"www.{domain}", www_cname.values)]
    for name, targets in checks:
        for target in targets[:3]:
            target_a = await bounded(target, "A")
            target_aaaa = await bounded(target, "AAAA")
            raw["cname_checks"].append(
                {
                    "name": name,
                    "target": target,
                    "dangling": target_a.error == "nxdomain" and target_aaaa.error == "nxdomain",
                    "resolves": bool(target_a.values or target_aaaa.values),
                }
            )
    await ctx.raise_if_cancelled()
    await ctx.report_progress(75, "CNAME targets checked")

    if include_reverse:
        public = [ip for ip in ips if _is_public(ip)][:MAX_PTR_LOOKUPS]
        for ip in ips:
            if not _is_public(ip):
                raw["ptr"][ip] = {"skipped": "not a public address"}
        ptr_outcomes = await asyncio.gather(
            *(bounded(dns.reversename.from_address(ip).to_text(), "PTR") for ip in public)
        )
        for ip, outcome in zip(public, ptr_outcomes, strict=True):
            raw["ptr"][ip] = {"names": outcome.values, "error": outcome.error}
        await ctx.report_progress(95, "Reverse lookups done")

    return raw

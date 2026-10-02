"""DNS service against a fake resolver: no network in unit tests."""

import asyncio
import uuid
from types import SimpleNamespace
from typing import Any

import dns.name
import dns.resolver
import pytest
import structlog

from app.core.errors import ProviderError
from app.engine.base_tool import RunCancelled, ToolContext
from app.tools.dns_lookup import service

Zone = dict[tuple[str, str], Any]


def _rdata(rtype: str, value: Any) -> Any:
    if rtype in ("NS", "CNAME", "PTR"):
        return SimpleNamespace(target=dns.name.from_text(value))
    if rtype == "MX":
        return SimpleNamespace(preference=value[0], exchange=dns.name.from_text(value[1]))
    if rtype == "TXT":
        return SimpleNamespace(strings=[value.encode()])
    if rtype == "CAA":
        return SimpleNamespace(flags=0, tag=b"issue", value=value.encode())
    return SimpleNamespace(to_text=lambda: value)


class FakeResolver:
    """Answers from a dict; values may be lists or an exception class to raise."""

    def __init__(self, zone: Zone, default: Any = ()) -> None:
        self.zone = zone
        self.default = default
        self.queries: list[tuple[str, str]] = []

    async def resolve(self, name: str, rtype: str, raise_on_no_answer: bool = True) -> Any:
        self.queries.append((name, rtype))
        await asyncio.sleep(0)
        value = self.zone.get((name, rtype), self.default)
        if isinstance(value, type) and issubclass(value, BaseException):
            raise value()
        if not value:
            return SimpleNamespace(rrset=None)
        return SimpleNamespace(rrset=[_rdata(rtype, v) for v in value])


def ctx(cancelled: bool = False, progress: list[int] | None = None) -> ToolContext:
    progress = progress if progress is not None else []

    async def on_progress(pct: int, message: str) -> None:
        progress.append(pct)

    async def cancel() -> bool:
        return cancelled

    return ToolContext(
        run_id=uuid.uuid4(),
        logger=structlog.get_logger(),
        progress_callback=on_progress,
        cancel_check=cancel,
    )


ZONE: Zone = {
    ("example.com", "A"): ["93.184.216.34", "10.0.0.1"],
    ("example.com", "MX"): [(10, "mx.example.com.")],
    ("example.com", "NS"): ["a.iana-servers.net.", "b.iana-servers.net."],
    ("example.com", "TXT"): ["v=spf1 -all"],
    ("example.com", "CAA"): ["letsencrypt.org"],
    ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject"],
    ("www.example.com", "CNAME"): ["gone.herokuapp.com."],
    ("gone.herokuapp.com", "A"): dns.resolver.NXDOMAIN,
    ("gone.herokuapp.com", "AAAA"): dns.resolver.NXDOMAIN,
    ("34.216.184.93.in-addr.arpa.", "PTR"): ["host.example.net."],
}


async def test_collects_records_dmarc_ptr_and_dangling_cname() -> None:
    resolver = FakeResolver(ZONE)
    progress: list[int] = []
    raw = await service.lookup("example.com", True, resolver, ctx(progress=progress))  # type: ignore[arg-type]

    assert raw["records"]["A"] == ["93.184.216.34", "10.0.0.1"]
    assert raw["records"]["MX"] == [{"preference": 10, "exchange": "mx.example.com"}]
    assert raw["records"]["NS"] == ["a.iana-servers.net", "b.iana-servers.net"]
    assert raw["records"]["CAA"] == [{"flags": 0, "tag": "issue", "value": "letsencrypt.org"}]
    assert raw["dmarc"] == ["v=DMARC1; p=reject"]
    assert raw["resolved_ips"] == ["93.184.216.34", "10.0.0.1"]
    assert raw["cname_checks"] == [
        {
            "name": "www.example.com",
            "target": "gone.herokuapp.com",
            "dangling": True,
            "resolves": False,
        }
    ]
    assert raw["ptr"]["93.184.216.34"] == {"names": ["host.example.net"], "error": None}
    # Private addresses are never sent to public resolvers for PTR.
    assert raw["ptr"]["10.0.0.1"] == {"skipped": "not a public address"}
    assert ("1.0.0.10.in-addr.arpa.", "PTR") not in resolver.queries
    assert progress[0] == 5 and progress[-1] == 95


async def test_reverse_lookups_can_be_disabled() -> None:
    resolver = FakeResolver(ZONE)
    raw = await service.lookup("example.com", False, resolver, ctx())  # type: ignore[arg-type]
    assert raw["ptr"] == {}
    assert not any(rtype == "PTR" for _, rtype in resolver.queries)


async def test_nxdomain() -> None:
    resolver = FakeResolver({}, default=dns.resolver.NXDOMAIN)
    raw = await service.lookup("nope.example", True, resolver, ctx())  # type: ignore[arg-type]
    assert raw["nxdomain"] is True
    assert raw["record_errors"] == {}


async def test_partial_failures_become_errors_not_crashes() -> None:
    zone = dict(ZONE)
    zone[("example.com", "CAA")] = dns.resolver.LifetimeTimeout
    context = ctx()
    raw = await service.lookup("example.com", False, FakeResolver(zone), context)  # type: ignore[arg-type]
    assert raw["record_errors"] == {"CAA": "timeout"}
    assert [e.code for e in context.errors] == ["dns_timeout"]


async def test_no_resolver_reachable_fails_the_run() -> None:
    resolver = FakeResolver({}, default=dns.resolver.LifetimeTimeout)
    with pytest.raises(ProviderError, match="No DNS resolver answered"):
        await service.lookup("example.com", True, resolver, ctx())  # type: ignore[arg-type]


async def test_cancellation_is_checked_between_stages() -> None:
    with pytest.raises(RunCancelled):
        await service.lookup("example.com", True, FakeResolver(ZONE), ctx(cancelled=True))  # type: ignore[arg-type]


def test_build_resolver_uses_explicit_nameservers() -> None:
    resolver = service.build_resolver(
        service.ResolverConfig(nameservers=["1.1.1.1"], timeout=2, lifetime=4)
    )
    assert resolver.nameservers == ["1.1.1.1"]
    assert resolver.timeout == 2
    assert resolver.lifetime == 4


async def test_long_txt_records_are_capped() -> None:
    zone = {("example.com", "TXT"): ["x" * 10_000]}
    raw = await service.lookup("example.com", False, FakeResolver(zone), ctx())  # type: ignore[arg-type]
    assert len(raw["records"]["TXT"][0]) == service.MAX_TXT_LENGTH

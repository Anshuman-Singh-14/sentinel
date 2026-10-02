"""Scope policy for active tools (04-security.md section 2, threat model T10).

Decision procedure for a target (host name or IP literal):

1. Resolve it to IP addresses (an IP literal resolves to itself).
2. **Hard denylist first.** If *any* resolved address is in Sentinel's own
   infrastructure subnets or a never-scannable range (cloud metadata,
   link-local, multicast, unspecified, broadcast), the target is denied. No
   policy entry can override this, so a mistaken or malicious admin entry
   like 0.0.0.0/0 still cannot point a scan at Postgres or Redis.
3. **Allow** if the host name matches an allowed domain suffix (and every
   non-public address is also covered by a CIDR rule), or if
   *every* resolved address is inside an allowed CIDR. "Every", not "any":
   a name that resolves to one lab IP and one third-party IP is ambiguous,
   and ambiguity is denied.
4. Otherwise deny.

The tool then connects only to the addresses checked here (``ScopeDecision.
addresses``), never re-resolving the name. That closes the DNS-rebinding gap
between "checked" and "connected".

Pure logic plus an injectable resolver, so every rule is unit-testable.
"""

import asyncio
import ipaddress
import socket
from collections.abc import Awaitable, Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Literal

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

# Always denied, whatever the configuration says.
NEVER_SCANNABLE: tuple[str, ...] = (
    "0.0.0.0/8",  # "this network" / unspecified
    "169.254.0.0/16",  # link-local, incl. cloud metadata 169.254.169.254
    "224.0.0.0/4",  # multicast
    "240.0.0.0/4",  # reserved, incl. broadcast 255.255.255.255
    "100.100.100.200/32",  # Alibaba Cloud metadata
    "::/128",  # unspecified
    "fe80::/10",  # IPv6 link-local
    "ff00::/8",  # IPv6 multicast
    "fd00:ec2::254/128",  # AWS IMDS over IPv6
)

RESOLVE_TIMEOUT_SECONDS = 3.0
MAX_ADDRESSES = 16

Resolver = Callable[[str], Awaitable[list[str]]]


def parse_networks(values: Iterable[str]) -> tuple[IPNetwork, ...]:
    return tuple(ipaddress.ip_network(v.strip(), strict=False) for v in values if v.strip())


def normalize_domain_suffix(value: str) -> str:
    """Lower-case, drop leading '*.' / '.' and a trailing dot. Validation is the caller's."""
    v = value.strip().lower().removesuffix(".")
    v = v.removeprefix("*.").removeprefix(".")
    return v


def matches_suffix(host: str, suffix: str) -> bool:
    """Label-aware: 'lab.example.com' matches 'example.com'; 'badexample.com' does not."""
    host = host.lower().removesuffix(".")
    return host == suffix or host.endswith("." + suffix)


@dataclass(frozen=True, slots=True)
class PolicyRule:
    kind: Literal["cidr", "domain"]
    value: str
    source: Literal["builtin", "admin"]
    description: str = ""


@dataclass(frozen=True, slots=True)
class ScopePolicy:
    hard_deny: tuple[IPNetwork, ...]
    allow_networks: tuple[tuple[IPNetwork, PolicyRule], ...] = ()
    allow_domains: tuple[tuple[str, PolicyRule], ...] = ()

    @classmethod
    def build(cls, infra_subnets: Sequence[str], rules: Sequence[PolicyRule]) -> "ScopePolicy":
        nets: list[tuple[IPNetwork, PolicyRule]] = []
        domains: list[tuple[str, PolicyRule]] = []
        for rule in rules:
            if rule.kind == "cidr":
                nets.append((ipaddress.ip_network(rule.value, strict=False), rule))
            else:
                domains.append((normalize_domain_suffix(rule.value), rule))
        return cls(
            hard_deny=parse_networks([*NEVER_SCANNABLE, *infra_subnets]),
            allow_networks=tuple(nets),
            allow_domains=tuple(domains),
        )

    def hard_denied(self, address: IPAddress) -> IPNetwork | None:
        for net in self.hard_deny:
            if address.version == net.version and address in net:
                return net
        # IPv4-mapped IPv6 (::ffff:10.231.0.2) must not sneak past IPv4 rules.
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            return self.hard_denied(address.ipv4_mapped)
        return None

    def allowing_network(self, address: IPAddress) -> PolicyRule | None:
        candidate: IPAddress = (
            address.ipv4_mapped
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped
            else address
        )
        for net, rule in self.allow_networks:
            if candidate.version == net.version and candidate in net:
                return rule
        return None

    def allowing_domain(self, host: str) -> PolicyRule | None:
        for suffix, rule in self.allow_domains:
            if matches_suffix(host, suffix):
                return rule
        return None


@dataclass(frozen=True, slots=True)
class ScopeDecision:
    allowed: bool
    target: str
    addresses: tuple[str, ...] = ()
    reason: str = ""
    # Machine-readable reason for audit details.
    code: str = ""
    matched_rule: PolicyRule | None = None
    denied_by: list[str] = field(default_factory=list)


def is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


async def system_resolve(host: str) -> list[str]:
    """Resolve with the OS resolver (Docker's DNS in compose, which knows lab names)."""
    loop = asyncio.get_running_loop()
    infos = await asyncio.wait_for(
        loop.getaddrinfo(host, None, type=socket.SOCK_STREAM), RESOLVE_TIMEOUT_SECONDS
    )
    seen: list[str] = []
    for info in infos:
        address = str(info[4][0]).split("%")[0]  # drop IPv6 zone ids
        if address not in seen:
            seen.append(address)
    return seen[:MAX_ADDRESSES]


async def evaluate(
    target: str, policy: ScopePolicy, resolve: Resolver = system_resolve
) -> ScopeDecision:
    host = target.strip().lower().removesuffix(".")
    if is_ip_literal(host):
        addresses = [str(ipaddress.ip_address(host))]
    else:
        try:
            addresses = await resolve(host)
        except (OSError, TimeoutError, UnicodeError):
            addresses = []
        if not addresses:
            return ScopeDecision(
                False, host, reason=f"{host} could not be resolved.", code="unresolvable"
            )

    parsed = [ipaddress.ip_address(a) for a in addresses]
    denied = [(a, net) for a in parsed if (net := policy.hard_denied(a)) is not None]
    if denied:
        return ScopeDecision(
            False,
            host,
            tuple(addresses),
            reason=(
                f"{host} resolves to {denied[0][0]}, inside a protected range "
                f"({denied[0][1]}) that Sentinel never scans."
            ),
            code="hard_denied",
            denied_by=[str(net) for _, net in denied],
        )

    if not is_ip_literal(host):
        rule = policy.allowing_domain(host)
        if rule is not None:
            # A domain rule vouches for public addresses only. Whoever controls
            # the domain's DNS could otherwise point it at 10.x or 127.0.0.1 and
            # turn an allowed name into a probe of internal networks (SSRF).
            # Internal addresses need an explicit CIDR rule as well.
            internal = [
                str(a) for a in parsed if not a.is_global and policy.allowing_network(a) is None
            ]
            if internal:
                return ScopeDecision(
                    False,
                    host,
                    tuple(addresses),
                    reason=(
                        f"{host} is allowed by name but resolves to a non-public address "
                        f"({', '.join(internal)}). Internal addresses must be allowed explicitly "
                        "by an IP/CIDR rule."
                    ),
                    code="internal_via_domain",
                )
            return ScopeDecision(True, host, tuple(addresses), code="domain", matched_rule=rule)

    rules = [policy.allowing_network(a) for a in parsed]
    if all(rule is not None for rule in rules):
        return ScopeDecision(True, host, tuple(addresses), code="cidr", matched_rule=rules[0])

    outside = [str(a) for a, r in zip(parsed, rules, strict=True) if r is None]
    return ScopeDecision(
        False,
        host,
        tuple(addresses),
        reason=(
            f"{host} ({', '.join(outside)}) is not in the scan scope. An admin must add it "
            "to the scope policy, and only for systems you own or may test."
        ),
        code="out_of_scope",
    )

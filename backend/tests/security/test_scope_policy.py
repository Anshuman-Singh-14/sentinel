"""Scope policy decisions, including bypass attempts (04-security.md section 11)."""

import pytest

from app.core.security.scope import PolicyRule, ScopePolicy, evaluate, matches_suffix

INFRA = ["10.231.0.0/24", "10.231.1.0/24", "10.231.2.0/24"]
LAB = PolicyRule("cidr", "10.231.10.0/24", "builtin")
LOOPBACK = PolicyRule("cidr", "127.0.0.0/8", "builtin")
OWNED = PolicyRule("domain", "example.org", "admin")


def policy(*rules: PolicyRule) -> ScopePolicy:
    return ScopePolicy.build(INFRA, rules or (LAB, LOOPBACK))


def resolver(table: dict[str, list[str]]):  # type: ignore[no-untyped-def]
    async def resolve(host: str) -> list[str]:
        return table.get(host, [])

    return resolve


async def test_lab_ip_and_name_are_allowed() -> None:
    decision = await evaluate("10.231.10.11", policy())
    assert decision.allowed and decision.code == "cidr" and decision.matched_rule == LAB
    decision = await evaluate("lab-banners", policy(), resolver({"lab-banners": ["10.231.10.11"]}))
    assert decision.allowed and decision.addresses == ("10.231.10.11",)


async def test_out_of_scope_is_denied_with_reason() -> None:
    decision = await evaluate("8.8.8.8", policy())
    assert not decision.allowed
    assert decision.code == "out_of_scope"
    assert "not in the scan scope" in decision.reason


@pytest.mark.parametrize(
    "target",
    [
        "10.231.0.2",  # postgres on the internal network
        "10.231.1.5",  # edge network
        "10.231.2.9",  # egress network
        "169.254.169.254",  # cloud metadata
        "0.0.0.0",  # noqa: S104  (a target string, not a bind address)
        "224.0.0.1",
        "255.255.255.255",
        "fe80::1",
        "fd00:ec2::254",
        "::ffff:10.231.0.2",  # IPv4-mapped IPv6 of postgres
    ],
)
async def test_hard_denylist_beats_any_allow_rule(target: str) -> None:
    everything = ScopePolicy.build(
        INFRA,
        [PolicyRule("cidr", "0.0.0.0/0", "admin"), PolicyRule("cidr", "::/0", "admin")],
    )
    decision = await evaluate(target, everything)
    assert not decision.allowed
    assert decision.code == "hard_denied"


async def test_infra_service_names_are_denied_after_resolution() -> None:
    decision = await evaluate("postgres", policy(), resolver({"postgres": ["10.231.0.2"]}))
    assert not decision.allowed and decision.code == "hard_denied"


async def test_allowed_domain_cannot_point_at_infrastructure() -> None:
    # DNS for an owned domain is changed to point at Sentinel's database.
    decision = await evaluate(
        "db.example.org", policy(OWNED), resolver({"db.example.org": ["10.231.0.2"]})
    )
    assert not decision.allowed and decision.code == "hard_denied"


async def test_domain_suffix_allows_public_addresses() -> None:
    decision = await evaluate(
        "www.example.org", policy(OWNED), resolver({"www.example.org": ["93.184.216.34"]})
    )
    assert decision.allowed and decision.code == "domain"


async def test_every_address_must_be_in_scope() -> None:
    mixed = resolver({"split.test": ["10.231.10.11", "93.184.216.34"]})
    decision = await evaluate("split.test", policy(), mixed)
    assert not decision.allowed
    assert "93.184.216.34" in decision.reason


async def test_any_infra_address_denies_even_if_others_allowed() -> None:
    mixed = resolver({"sneaky": ["10.231.10.11", "10.231.0.3"]})
    decision = await evaluate("sneaky", policy(), mixed)
    assert decision.code == "hard_denied"


async def test_unresolvable_names_are_denied() -> None:
    decision = await evaluate("nowhere", policy(), resolver({}))
    assert not decision.allowed and decision.code == "unresolvable"


async def test_resolver_errors_are_denials_not_crashes() -> None:
    async def broken(host: str) -> list[str]:
        raise OSError("resolver down")

    decision = await evaluate("lab-web", policy(), broken)
    assert decision.code == "unresolvable"


@pytest.mark.parametrize(
    ("host", "suffix", "expected"),
    [
        ("example.org", "example.org", True),
        ("a.b.example.org", "example.org", True),
        ("badexample.org", "example.org", False),
        ("example.org.evil.com", "example.org", False),
        ("EXAMPLE.ORG.", "example.org", True),
    ],
)
def test_suffix_matching_is_label_aware(host: str, suffix: str, expected: bool) -> None:
    assert matches_suffix(host, suffix) is expected


async def test_loopback_default() -> None:
    assert (await evaluate("127.0.0.1", policy())).allowed

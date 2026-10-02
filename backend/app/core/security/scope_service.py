"""Scope policy persistence, validation, acknowledgement and audit.

The pure decision logic lives in ``scope.py``; this module connects it to the
database, settings and the audit log.
"""

import hashlib
import ipaddress
import uuid
from dataclasses import dataclass
from typing import Literal

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.core.audit import Actor, AuditAction, AuditService, Outcome
from app.core.errors import ValidationFailed
from app.core.security.scope import (
    NEVER_SCANNABLE,
    PolicyRule,
    ScopeDecision,
    ScopePolicy,
    evaluate,
    is_ip_literal,
    parse_networks,
    system_resolve,
)
from app.core.security.validators import normalize_domain
from app.db.models import AuthorizationAcknowledgement, ScopeEntry

# Shown to the user before their first active run. Changing the text means
# bumping AUTHORIZATION_STATEMENT_VERSION so everyone accepts the new wording.
AUTHORIZATION_STATEMENT = (
    "I will only scan or test systems that I own or for which I have explicit, written "
    "permission from the owner. I understand that every run is recorded under my name in a "
    "tamper-evident audit log, and that unauthorised scanning may be illegal (for example "
    "under the Computer Misuse Act 1990 (UK), the Computer Fraud and Abuse Act (US), or the "
    "Information Technology Act 2000 (India))."
)

# Prefixes broader than these are refused: allowing a /4 is never a scope,
# it is switching the control off.
MIN_IPV4_PREFIX = 8
MIN_IPV6_PREFIX = 32


def statement_sha256() -> str:
    return hashlib.sha256(AUTHORIZATION_STATEMENT.encode()).hexdigest()


def hard_deny_list(settings: Settings) -> list[str]:
    return [*NEVER_SCANNABLE, *settings.scope_infra_subnets]


def builtin_rules(settings: Settings) -> list[PolicyRule]:
    return [
        PolicyRule("cidr", str(ipaddress.ip_network(v, strict=False)), "builtin", "Default scope")
        for v in settings.scope_default_allow
    ]


async def load_policy(db: AsyncSession, settings: Settings) -> ScopePolicy:
    rows = await db.scalars(select(ScopeEntry).where(ScopeEntry.enabled.is_(True)))
    admin_rules = [
        PolicyRule(row.kind, row.value, "admin", row.description)  # type: ignore[arg-type]
        for row in rows
    ]
    return ScopePolicy.build(settings.scope_infra_subnets, [*builtin_rules(settings), *admin_rules])


def normalize_entry(kind: Literal["cidr", "domain"], value: str, settings: Settings) -> str:
    """Validate an admin-supplied entry and return its canonical form."""
    if kind == "domain":
        try:
            return normalize_domain(value.strip().removeprefix("*."))
        except ValueError as exc:
            raise ValidationFailed(str(exc)) from None
    try:
        network = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        raise ValidationFailed("Enter a valid IP address or CIDR, such as 192.0.2.0/24.") from None
    minimum = MIN_IPV4_PREFIX if network.version == 4 else MIN_IPV6_PREFIX
    if network.prefixlen < minimum:
        raise ValidationFailed(
            f"/{network.prefixlen} is too broad for a scope entry (minimum /{minimum})."
        )
    for denied in parse_networks(hard_deny_list(settings)):
        if network.version == denied.version and network.overlaps(denied):
            raise ValidationFailed(
                f"{network} overlaps {denied}, which Sentinel never scans "
                "(its own infrastructure or a reserved range)."
            )
    return str(network)


async def precheck(target: str, policy: ScopePolicy) -> ScopeDecision | None:
    """The API's early check. Returns None when the API cannot decide.

    The API container is not on the lab network, so lab host names do not
    resolve here. Those runs are queued, and the worker, which can resolve
    them, makes the authoritative decision before any traffic is sent.
    """
    if is_ip_literal(target):
        return await evaluate(target, policy)
    decision = await evaluate(target, policy, system_resolve)
    if decision.code == "unresolvable":
        return None
    return decision


async def evaluate_target(db: AsyncSession, target: str, settings: Settings) -> ScopeDecision:
    """Authoritative check with the current policy and the system resolver."""
    return await evaluate(target, await load_policy(db, settings), system_resolve)


async def record_denial(
    audit: AuditService,
    actor: Actor,
    *,
    tool_id: str,
    decision: ScopeDecision,
    stage: str,
    run_id: uuid.UUID | None = None,
    session: AsyncSession | None = None,
) -> None:
    await audit.record(
        AuditAction.TOOL_RUN_DENIED_SCOPE,
        actor=actor,
        outcome=Outcome.DENIED,
        resource_type="tool_run" if run_id else "tool",
        resource_id=str(run_id) if run_id else tool_id,
        target=decision.target,
        reason=decision.code or "out_of_scope",
        details={
            "tool_id": tool_id,
            "stage": stage,
            "addresses": list(decision.addresses),
            "denied_by": decision.denied_by,
        },
        security_event=True,
        session=session,
    )


@dataclass(frozen=True, slots=True)
class AcknowledgementStatus:
    acknowledged: bool
    version: int
    statement: str
    acknowledged_at: str | None


async def acknowledgement_status(
    db: AsyncSession, user_id: uuid.UUID, settings: Settings
) -> AcknowledgementStatus:
    row = await db.scalar(
        select(AuthorizationAcknowledgement).where(
            AuthorizationAcknowledgement.user_id == user_id,
            AuthorizationAcknowledgement.statement_version
            == settings.authorization_statement_version,
        )
    )
    return AcknowledgementStatus(
        acknowledged=row is not None,
        version=settings.authorization_statement_version,
        statement=AUTHORIZATION_STATEMENT,
        acknowledged_at=row.acknowledged_at.isoformat() if row else None,
    )

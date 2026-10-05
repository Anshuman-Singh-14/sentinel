"""Scheduled integrity checks (ADR 0015, section 7).

Celery beat sends ``sentinel.fim.dispatch_scheduled`` every minute. This
module finds baselines whose interval has elapsed and starts a normal
``fim_check`` run for each, attributed to the baseline's creator, through
``RunService.create`` (same validation and audit trail as a manual run).

* **Claimed with a compare-and-set** on ``last_scheduled_at``: a duplicate
  beat message, or two workers running this task at once, cannot start two
  checks for the same interval.
* **A disabled or demoted creator** (below analyst) gets their schedule
  cleared instead of a run in their name.
* **Bounded**: at most ``MAX_PER_TICK`` baselines per minute; the rest wait
  for the next tick.
"""

import uuid
from datetime import datetime

from sqlalchemy import ColumnElement, and_, func, or_, select, update

from app.config import get_settings
from app.core.audit import Actor, ActorType, build_audit_service
from app.core.auth.dependencies import Principal
from app.core.auth.roles import Role, role_allows
from app.core.errors import SentinelError
from app.core.logging import get_logger
from app.core.ratelimit import MemoryRateLimiter
from app.core.runs.dispatch import Dispatcher, get_dispatcher
from app.core.runs.service import RunService
from app.db.models import FimBaseline, User
from app.db.models._types import utcnow
from app.db.session import get_sessionmaker
from app.engine.registry import registry

logger = get_logger("sentinel.fim.schedule")

DISPATCH_TASK = "sentinel.fim.dispatch_scheduled"
CHECK_TOOL_ID = "fim_check"
MAX_PER_TICK = 50


def _due(now: datetime) -> ColumnElement[bool]:
    return and_(
        FimBaseline.schedule_minutes.is_not(None),
        FimBaseline.deleted_at.is_(None),
        or_(
            FimBaseline.last_scheduled_at.is_(None),
            FimBaseline.last_scheduled_at
            <= now - func.make_interval(0, 0, 0, 0, 0, FimBaseline.schedule_minutes),
        ),
    )


def _principal(user: User) -> Principal:
    actor = Actor(
        actor_type=ActorType.USER, user_id=user.id, username=user.username, role=user.role
    )
    # No interactive session exists for a scheduled run; the id only has to be unique.
    return Principal(
        user_id=user.id,
        username=user.username,
        role=Role(user.role),
        session_id=uuid.uuid4(),
        actor=actor,
    )


async def dispatch_due(
    now: datetime | None = None, *, dispatcher: Dispatcher | None = None
) -> list[uuid.UUID]:
    """Start the checks that are due. Returns the ids of the runs created."""
    now = now or utcnow()
    settings = get_settings()
    sessionmaker = get_sessionmaker()
    started: list[uuid.UUID] = []

    async with sessionmaker() as db:
        due = list(
            await db.scalars(
                select(FimBaseline.id).where(_due(now)).order_by(FimBaseline.id).limit(MAX_PER_TICK)
            )
        )

    for baseline_id in due:
        async with sessionmaker() as db:
            claimed = await db.execute(
                update(FimBaseline)
                .where(FimBaseline.id == baseline_id, _due(now))
                .values(last_scheduled_at=now)
                .returning(FimBaseline.created_by)
            )
            row = claimed.first()
            if row is None:  # someone else claimed it, or it was changed meanwhile
                await db.rollback()
                continue
            await db.commit()

            user = await db.get(User, row.created_by)
            if user is None or not user.is_active or not role_allows(Role(user.role), Role.ANALYST):
                await db.execute(
                    update(FimBaseline)
                    .where(FimBaseline.id == baseline_id)
                    .values(schedule_minutes=None)
                )
                await db.commit()
                logger.warning("fim.schedule.cleared", baseline_id=str(baseline_id))
                continue

            service = RunService(
                db,
                build_audit_service("worker"),
                MemoryRateLimiter(),
                dispatcher or get_dispatcher(),
                settings,
            )
            try:
                run = await service.create(
                    registry.get(CHECK_TOOL_ID),
                    {"baseline_id": str(baseline_id)},
                    _principal(user),
                    scheduled=True,
                )
            except SentinelError as exc:
                await db.rollback()
                logger.warning(
                    "fim.schedule.not_started", baseline_id=str(baseline_id), error_code=exc.code
                )
                continue
            started.append(run.id)
            logger.info("fim.schedule.started", baseline_id=str(baseline_id), run_id=str(run.id))
    return started

"""SQL implementation of the FIM tools' ``BaselineStore`` (ADR 0015, section 2).

Runs inside the worker. Each method uses its own short session and
transaction. A baseline's rows and its ``fim.baseline.created`` audit event
commit together, so there is never a baseline without an audit record (or the
reverse).
"""

import uuid
from collections.abc import Mapping
from itertools import batched

from sqlalchemy import insert, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import Actor, ActorType, AuditAction, Outcome, build_audit_service
from app.core.errors import NotFound
from app.db.models import FimBaseline, FimBaselineEntry, ToolRun, User
from app.db.models._types import utcnow
from app.db.session import get_sessionmaker
from app.tools.fim.scanner import Entry
from app.tools.fim.store import BaselineNotFound, BaselineSpec, SavedBaseline, StoredBaseline

INSERT_BATCH = 1000


def location(root: str, path: str) -> str:
    return f"{root}:/{path}"


async def _run_actor(db: AsyncSession, run_id: uuid.UUID) -> tuple[ToolRun, Actor]:
    run = await db.get(ToolRun, run_id)
    if run is None:
        raise NotFound("The run creating this baseline no longer exists.")
    user = await db.get(User, run.user_id)
    return run, Actor(
        actor_type=ActorType.USER,
        user_id=run.user_id,
        username=run.username,
        role=user.role if user else None,
    )


class SqlBaselineStore:
    async def save(
        self, run_id: uuid.UUID, spec: BaselineSpec, entries: Mapping[str, Entry]
    ) -> SavedBaseline:
        async with get_sessionmaker()() as db:
            run, actor = await _run_actor(db, run_id)
            kinds = [e.kind for e in entries.values()]
            baseline = FimBaseline(
                name=spec.name,
                root=spec.root,
                path=spec.path,
                excludes=list(spec.excludes),
                file_count=kinds.count("file"),
                dir_count=kinds.count("dir"),
                other_count=len(kinds) - kinds.count("file") - kinds.count("dir"),
                total_bytes=sum(e.size for e in entries.values() if e.sha256),
                # Attribution comes from the run row, never from parameters.
                created_by=run.user_id,
                created_by_username=run.username,
                created_run_id=run.id,
                created_at=utcnow(),
            )
            db.add(baseline)
            await db.flush()
            for chunk in batched(entries.items(), INSERT_BATCH):
                await db.execute(
                    insert(FimBaselineEntry),
                    [
                        {
                            "baseline_id": baseline.id,
                            "path": path,
                            "kind": e.kind,
                            "size": e.size,
                            "mtime_ns": e.mtime_ns,
                            "mode": e.mode,
                            "uid": e.uid,
                            "gid": e.gid,
                            "sha256": e.sha256,
                            "link_target": e.link_target,
                            "note": e.note,
                        }
                        for path, e in chunk
                    ],
                )
            await build_audit_service("worker").record(
                AuditAction.FIM_BASELINE_CREATED,
                actor=actor,
                outcome=Outcome.SUCCESS,
                resource_type="fim_baseline",
                resource_id=str(baseline.id),
                target=location(spec.root, spec.path),
                details={
                    "name": spec.name,
                    "run_id": str(run.id),
                    "entries": len(entries),
                    "files": baseline.file_count,
                    "excludes": list(spec.excludes),
                },
                session=db,
            )
            await db.commit()
            return SavedBaseline(baseline.id, baseline.created_at, run.username)

    async def load(self, baseline_id: uuid.UUID) -> StoredBaseline:
        async with get_sessionmaker()() as db:
            baseline = await db.scalar(
                select(FimBaseline).where(
                    FimBaseline.id == baseline_id, FimBaseline.deleted_at.is_(None)
                )
            )
            if baseline is None:
                raise BaselineNotFound(str(baseline_id))
            rows = await db.scalars(
                select(FimBaselineEntry).where(FimBaselineEntry.baseline_id == baseline_id)
            )
            entries = {
                row.path: Entry(
                    kind=row.kind,
                    size=row.size,
                    mtime_ns=row.mtime_ns,
                    mode=row.mode,
                    uid=row.uid,
                    gid=row.gid,
                    sha256=row.sha256,
                    link_target=row.link_target,
                    note=row.note,
                )
                for row in rows
            }
            return StoredBaseline(
                baseline_id=baseline.id,
                spec=BaselineSpec(
                    name=baseline.name,
                    root=baseline.root,
                    path=baseline.path,
                    excludes=tuple(baseline.excludes),
                ),
                created_at=baseline.created_at,
                created_by=baseline.created_by_username,
                entries=entries,
            )

    async def record_check(
        self, run_id: uuid.UUID, baseline_id: uuid.UUID, counts: Mapping[str, int]
    ) -> None:
        async with get_sessionmaker()() as db:
            run, actor = await _run_actor(db, run_id)
            total = sum(counts.values())
            baseline = await db.scalar(
                update(FimBaseline)
                .where(FimBaseline.id == baseline_id)
                .values(
                    last_checked_at=utcnow(),
                    last_check_run_id=run_id,
                    last_check_changes=total,
                )
                .returning(FimBaseline)
            )
            await build_audit_service("worker").record(
                AuditAction.FIM_CHECK_COMPLETED,
                actor=actor,
                outcome=Outcome.SUCCESS,
                resource_type="fim_baseline",
                resource_id=str(baseline_id),
                target=location(baseline.root, baseline.path) if baseline else None,
                details={"run_id": str(run.id), "changes": total, "by_type": dict(counts)},
                session=db,
            )
            await db.commit()

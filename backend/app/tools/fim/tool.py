"""The two FIM tools (02-modules.md, backend tool 6; ADR 0015).

Both are local (no network traffic) and read only the configured, read-only
FIM roots. Their only state goes through ``BaselineStore``.
"""

from collections.abc import Callable
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import PurePosixPath
from typing import Any

from pydantic import BaseModel

from app.config import get_settings
from app.core.errors import NotFound
from app.engine.base_tool import BaseTool, RawOutput, ToolAvailability, ToolContext
from app.engine.schemas import Finding, ToolCategory
from app.tools.fim import service, translator
from app.tools.fim.compare import compare, special_bits, world_writable
from app.tools.fim.scanner import Entry
from app.tools.fim.schemas import FimBaselineParams, FimCheckParams
from app.tools.fim.store import BaselineNotFound, BaselineSpec, BaselineStore

MAX_STORED_CHANGES = 500
MAX_OBSERVATIONS = 50


def _default_store() -> BaselineStore:
    from app.fim.store import SqlBaselineStore  # imported late: keeps the tool DB-free in tests

    return SqlBaselineStore()


# Replaced by an in-memory fake in unit tests.
store_factory: Callable[[], BaselineStore] = _default_store


def _availability() -> ToolAvailability:
    roots = sorted(get_settings().fim_roots)
    if not roots:
        return ToolAvailability(
            available=False, reason="No FIM roots are configured (set FIM_ROOTS on the server)."
        )
    return ToolAvailability(details={"roots": roots})


def entry_dict(entry: Entry) -> dict[str, Any]:
    data = {k: v for k, v in asdict(entry).items() if v is not None}
    data["mode"] = entry.mode
    data["mode_text"] = f"{entry.mode:04o}"
    data["mtime"] = datetime.fromtimestamp(entry.mtime_ns / 1e9, UTC).isoformat()
    return data


def _escapes_root(link_target: str | None, path: str) -> bool:
    if not link_target:
        return False
    if link_target.startswith("/"):
        return True
    depth = len(PurePosixPath(path).parent.parts)
    for part in PurePosixPath(link_target).parts:
        depth += -1 if part == ".." else (0 if part == "." else 1)
        if depth < 0:
            return True
    return False


class _FimTool[P: BaseModel](BaseTool[P]):
    """Shared settings of both FIM tools (abstract: not registered itself)."""

    category = ToolCategory.FORENSIC
    soft_time_limit = 300
    hard_time_limit = 330

    @classmethod
    def availability(cls) -> ToolAvailability:
        return _availability()


class FimBaselineTool(_FimTool[FimBaselineParams]):
    tool_id = "fim_baseline"
    name = "FIM: Create Baseline"
    description = (
        "Records the SHA-256 hash, size, permissions and owner of every file in a monitored "
        "directory. Run a File Integrity Check later to see what was modified, added, "
        "removed or had its permissions changed."
    )
    version = "1.0.0"
    params_model = FimBaselineParams

    async def run(self, params: FimBaselineParams, ctx: ToolContext) -> RawOutput:
        settings = get_settings()
        result = await service.scan_directory(
            root=service.root_path(settings, params.root),
            path=params.path,
            excludes=params.excludes,
            limits=service.limits_from(settings),
            ctx=ctx,
            fail_on_limit=True,
            label="Recording",
        )
        await ctx.raise_if_cancelled()
        await ctx.report_progress(95, "Saving the baseline")
        spec = BaselineSpec(
            name=params.name, root=params.root, path=params.path, excludes=params.excludes
        )
        saved = await store_factory().save(ctx.run_id, spec, result.entries)
        return {
            "baseline": {
                "id": str(saved.baseline_id),
                "name": spec.name,
                "root": spec.root,
                "path": spec.path,
                "excludes": list(spec.excludes),
                "created_at": saved.created_at.isoformat(),
                "created_by": saved.created_by,
            },
            "stats": self._stats(result.entries),
            "observations": self._observations(result.entries),
        }

    @staticmethod
    def _stats(entries: dict[str, Entry]) -> dict[str, Any]:
        kinds = {"file": 0, "dir": 0, "symlink": 0, "other": 0}
        notes: dict[str, int] = {}
        hashed = 0
        for entry in entries.values():
            kinds[entry.kind] += 1
            if entry.note:
                notes[entry.note] = notes.get(entry.note, 0) + 1
            if entry.sha256:
                hashed += entry.size
        return {
            "entries": len(entries),
            "files": kinds["file"],
            "dirs": kinds["dir"],
            "symlinks": kinds["symlink"],
            "other": kinds["other"],
            "bytes_hashed": hashed,
            "not_hashed": notes,
        }

    @staticmethod
    def _observations(entries: dict[str, Entry]) -> dict[str, Any]:
        groups: dict[str, list[str]] = {
            "world_writable": [p for p, e in entries.items() if world_writable(e)],
            "setuid": [p for p, e in entries.items() if special_bits(e)],
            "external_symlinks": [
                p
                for p, e in entries.items()
                if e.kind == "symlink" and _escapes_root(e.link_target, p)
            ],
            "not_hashed": [p for p, e in entries.items() if e.note],
        }
        out: dict[str, Any] = {}
        for key, paths in groups.items():
            out[key] = paths[:MAX_OBSERVATIONS]
            out[f"{key}_count"] = len(paths)
        return out

    def translate(self, raw: RawOutput, params: FimBaselineParams) -> list[Finding]:
        return translator.translate_baseline(raw)

    def target_of(self, params: FimBaselineParams) -> str:
        return f"{params.root}:/{params.path}"


class FimCheckTool(_FimTool[FimCheckParams]):
    tool_id = "fim_check"
    name = "File Integrity Check"
    description = (
        "Compares a monitored directory with a baseline and explains every change: modified, "
        "added and removed files, and permission or owner changes, rated by how sensitive "
        "the path is. Can run on a schedule."
    )
    version = "1.0.0"
    params_model = FimCheckParams

    async def run(self, params: FimCheckParams, ctx: ToolContext) -> RawOutput:
        settings = get_settings()
        store = store_factory()
        try:
            baseline = await store.load(params.baseline_id)
        except BaselineNotFound:
            raise NotFound("That baseline does not exist or was deleted.") from None
        await ctx.report_progress(5, f"Loaded baseline '{baseline.spec.name}'")
        limits = service.limits_from(settings)
        result = await service.scan_directory(
            root=service.root_path(settings, baseline.spec.root),
            path=baseline.spec.path,
            excludes=baseline.spec.excludes,
            limits=limits,
            ctx=ctx,
            fail_on_limit=False,
            label="Checking",
        )
        await ctx.raise_if_cancelled()
        changes, stats = compare(
            baseline.entries, result.entries, report_removed=not result.truncated
        )
        counts = {str(k): v for k, v in stats.by_type.items()}
        await store.record_check(ctx.run_id, baseline.baseline_id, counts)
        return {
            "baseline": {
                "id": str(baseline.baseline_id),
                "name": baseline.spec.name,
                "root": baseline.spec.root,
                "path": baseline.spec.path,
                "excludes": list(baseline.spec.excludes),
                "created_at": baseline.created_at.isoformat(),
                "created_by": baseline.created_by,
            },
            "stats": {
                "baseline_entries": stats.baseline_entries,
                "current_entries": stats.current_entries,
                "unchanged": stats.unchanged,
                "touched": stats.touched,
                "by_type": counts,
            },
            "truncated": result.truncated,
            "limit": limits.max_entries,
            "changes_total": len(changes),
            "changes": [
                {
                    "path": c.path,
                    "type": str(c.type),
                    "severity": c.severity.value,
                    "sensitivity": {
                        "level": c.sensitivity.level.value,
                        "pattern": c.sensitivity.pattern,
                        "reason": c.sensitivity.reason,
                    },
                    "details": list(c.details),
                    "escalations": [str(e) for e in c.escalations],
                    "hashed": c.hashed,
                    "before": entry_dict(c.before) if c.before else None,
                    "after": entry_dict(c.after) if c.after else None,
                }
                for c in changes[:MAX_STORED_CHANGES]
            ],
        }

    def translate(self, raw: RawOutput, params: FimCheckParams) -> list[Finding]:
        return translator.translate_check(raw)

    def target_of(self, params: FimCheckParams) -> str:
        return f"baseline {params.baseline_id}"

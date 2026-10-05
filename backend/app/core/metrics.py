"""Prometheus metrics for the optional observability profile (ADR 0016).

Two sources:

* **HTTP metrics**, recorded by the access-log middleware: a request counter
  and a latency histogram by method, route *template* and status class.
  Templates keep label cardinality bounded and identifiers out of labels.
  Production runs several uvicorn workers, so values are kept in the
  client's multiprocess files and summed at scrape time.
* **Business metrics**, read from Postgres and Redis at scrape time: runs by
  tool and status, durations, queue depth, alerts. Workers keep no metric
  state, so a restart loses nothing and the numbers match the UI.

Everything is inert until ``init()`` runs with a ``METRICS_TOKEN`` set.
``prometheus_client`` is imported only then, because its multiprocess mode is
chosen from an environment variable at import time.
"""

import os
from collections.abc import Iterable, Sequence
from datetime import timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.core.logging import get_logger
from app.core.tasks.queues import QUEUES
from app.db.models import AuditEvent, PlaybookRun, Report, SecurityAlert, ToolRun
from app.db.models._types import utcnow

logger = get_logger("sentinel.metrics")

LATENCY_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)
METRICS_ROUTE = "/metrics"

_requests: Any = None
_latency: Any = None


def enabled() -> bool:
    return _requests is not None


def init(settings: Settings) -> None:
    """Create the HTTP metrics once per process (idempotent). No token: stay off."""
    global _requests, _latency
    if settings.metrics_token is None or _requests is not None:
        return
    directory = settings.metrics_multiproc_dir
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Must be set before prometheus_client is first imported (see module docstring).
    os.environ.setdefault("PROMETHEUS_MULTIPROC_DIR", str(directory))
    from prometheus_client import Counter, Histogram

    _requests = Counter(
        "sentinel_http_requests",
        "HTTP requests handled by the API.",
        ["method", "route", "status"],
    )
    _latency = Histogram(
        "sentinel_http_request_duration_seconds",
        "API request latency.",
        ["method", "route"],
        buckets=LATENCY_BUCKETS,
    )
    logger.info("metrics.enabled")


def observe_request(method: str | None, route: str, status: int, seconds: float) -> None:
    if _requests is None or route == METRICS_ROUTE:
        return
    status_class = f"{status // 100}xx"
    _requests.labels(method or "?", route, status_class).inc()
    _latency.labels(method or "?", route).observe(seconds)


# --- business metrics ---------------------------------------------------------------


def _gauge(name: str, doc: str, labels: Sequence[str], rows: Iterable[tuple[Any, ...]]) -> Any:
    from prometheus_client.core import GaugeMetricFamily

    family = GaugeMetricFamily(name, doc, labels=list(labels))
    for *values, value in rows:
        family.add_metric([str(v) for v in values], float(value or 0))
    return family


async def business_metrics(db: AsyncSession, redis: Any) -> list[Any]:
    """Aggregates over the run, report, alert and audit tables plus queue lengths.

    A failing dependency is reported as ``sentinel_dependency_up{component}=0``
    rather than failing the scrape, so the dashboard shows what is down.
    """
    families: list[Any] = []
    up: list[tuple[str, int]] = []

    try:
        runs = (
            await db.execute(
                select(
                    ToolRun.tool_id,
                    ToolRun.status,
                    func.count(),
                    func.coalesce(func.sum(ToolRun.duration_ms), 0),
                    func.count(ToolRun.duration_ms),
                ).group_by(ToolRun.tool_id, ToolRun.status)
            )
        ).all()
        since = utcnow() - timedelta(hours=1)
        p95 = (
            await db.execute(
                select(
                    ToolRun.tool_id,
                    func.percentile_cont(0.95).within_group(ToolRun.duration_ms),
                )
                .where(ToolRun.completed_at >= since, ToolRun.duration_ms.is_not(None))
                .group_by(ToolRun.tool_id)
            )
        ).all()
        playbooks = (
            await db.execute(select(PlaybookRun.status, func.count()).group_by(PlaybookRun.status))
        ).all()
        reports = (
            await db.execute(select(Report.status, func.count()).group_by(Report.status))
        ).all()
        open_alert = SecurityAlert.acknowledged_at.is_(None)
        alerts = (await db.execute(select(open_alert, func.count()).group_by(open_alert))).all()
        audit_last = await db.scalar(select(func.max(AuditEvent.id)))
    except Exception:  # noqa: BLE001  (a scrape must not 500 because the DB is down)
        logger.warning("metrics.database_unavailable")
        await db.rollback()
        up.append(("postgres", 0))
    else:
        up.append(("postgres", 1))
        families.append(
            _gauge(
                "sentinel_tool_runs",
                "Tool runs by current status. Terminal statuses only grow: runs are never deleted.",
                ["tool_id", "status"],
                ((r[0], r[1], r[2]) for r in runs),
            )
        )
        durations: dict[str, list[float]] = {}
        for tool_id, _status, _count, total_ms, timed in runs:
            entry = durations.setdefault(tool_id, [0.0, 0.0])
            entry[0] += float(total_ms or 0) / 1000
            entry[1] += float(timed)
        families.append(
            _gauge(
                "sentinel_tool_run_duration_seconds_sum",
                "Total run time of finished tool runs, per tool.",
                ["tool_id"],
                ((t, v[0]) for t, v in durations.items()),
            )
        )
        families.append(
            _gauge(
                "sentinel_tool_run_duration_seconds_count",
                "Finished tool runs with a recorded duration, per tool.",
                ["tool_id"],
                ((t, v[1]) for t, v in durations.items()),
            )
        )
        families.append(
            _gauge(
                "sentinel_tool_run_duration_p95_seconds",
                "95th percentile run time over the last hour, per tool.",
                ["tool_id"],
                ((t, float(ms) / 1000) for t, ms in p95),
            )
        )
        families.append(
            _gauge("sentinel_playbook_runs", "Playbook runs by status.", ["status"], playbooks)
        )
        families.append(_gauge("sentinel_reports", "Reports by status.", ["status"], reports))
        families.append(
            _gauge(
                "sentinel_security_alerts",
                "Security alerts by state.",
                ["state"],
                (("open" if is_open else "acknowledged", n) for is_open, n in alerts),
            )
        )
        families.append(
            _gauge(
                "sentinel_audit_events",
                "Sequence number of the newest audit event (audit events are append-only).",
                [],
                [(audit_last or 0,)],
            )
        )

    try:
        depths = [(queue, await redis.llen(queue)) for queue in QUEUES]
    except Exception:  # noqa: BLE001  (same reason as above)
        logger.warning("metrics.redis_unavailable")
        up.append(("redis", 0))
    else:
        up.append(("redis", 1))
        families.append(
            _gauge("sentinel_queue_depth", "Tasks waiting in each Celery queue.", ["queue"], depths)
        )

    families.append(
        _gauge(
            "sentinel_dependency_up",
            "Whether the metrics scrape could reach each dependency.",
            ["component"],
            up,
        )
    )
    return families


def render(families: list[Any]) -> tuple[bytes, str]:
    """Exposition text: summed HTTP metrics from every API process, plus the business metrics."""
    from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, generate_latest
    from prometheus_client.multiprocess import MultiProcessCollector

    class _Snapshot:
        def collect(self) -> list[Any]:
            return families

    registry = CollectorRegistry()
    MultiProcessCollector(registry)  # type: ignore[no-untyped-call]
    registry.register(_Snapshot())
    return generate_latest(registry), CONTENT_TYPE_LATEST

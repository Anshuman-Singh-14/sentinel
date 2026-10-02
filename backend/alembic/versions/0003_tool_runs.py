"""Tool runs and findings.

Grants, written out like 0002:

* ``tool_runs``: SELECT, INSERT, UPDATE. No DELETE: run history is evidence
  of what was done and is removed only by a future retention job.
* ``findings``: SELECT, INSERT. Findings are written once, when a run
  completes, and never edited.

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-02
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APP_ROLE = "sentinel_app"

RUN_STATUSES = "'QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED', 'TIMED_OUT'"
SEVERITIES = "'INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'"
FINDING_STATUSES = (
    "'PASS', 'FAIL', 'MISSING', 'WEAK', 'DETECTED', 'CHANGED', 'ADDED', 'REMOVED', 'ERROR', 'INFO'"
)
CONFIDENCES = "'LOW', 'MEDIUM', 'HIGH'"


def upgrade() -> None:
    op.create_table(
        "tool_runs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tool_id", sa.String(length=64), nullable=False),
        sa.Column("tool_name", sa.String(length=128), nullable=False),
        sa.Column("tool_version", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("params", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("target", sa.String(length=512), nullable=True),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("username", sa.String(length=64), nullable=False),
        sa.Column("request_id", sa.String(length=64), nullable=True),
        sa.Column("celery_task_id", sa.String(length=64), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("cancel_requested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("progress_pct", sa.SmallInteger(), server_default="0", nullable=False),
        sa.Column("progress_message", sa.String(length=256), nullable=True),
        sa.Column("finding_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("max_severity", sa.String(length=16), nullable=True),
        sa.Column(
            "errors", postgresql.JSONB(astext_type=sa.Text()), server_default="[]", nullable=False
        ),
        sa.Column(
            "raw_data", postgresql.JSONB(astext_type=sa.Text()), server_default="{}", nullable=False
        ),
        sa.CheckConstraint(f"status IN ({RUN_STATUSES})", name=op.f("ck_tool_runs_status_valid")),
        sa.CheckConstraint(
            "progress_pct BETWEEN 0 AND 100", name=op.f("ck_tool_runs_progress_pct_range")
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name=op.f("fk_tool_runs_user_id_users"), ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_tool_runs")),
    )
    op.create_index(op.f("ix_tool_runs_created_at"), "tool_runs", ["created_at"])
    op.create_index("ix_tool_runs_user_id_created_at", "tool_runs", ["user_id", "created_at"])
    op.create_index("ix_tool_runs_tool_id_created_at", "tool_runs", ["tool_id", "created_at"])
    op.create_index(
        "ix_tool_runs_active_by_user",
        "tool_runs",
        ["user_id"],
        postgresql_where=sa.text("status IN ('QUEUED', 'RUNNING')"),
    )

    op.create_table(
        "findings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("item", sa.String(length=300), nullable=False),
        sa.Column("category", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("severity_rationale", sa.Text(), nullable=False),
        sa.Column("confidence", sa.String(length=8), nullable=False),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("remediation", sa.Text(), nullable=False),
        sa.Column(
            "evidence", postgresql.JSONB(astext_type=sa.Text()), server_default="{}", nullable=False
        ),
        sa.Column(
            "references",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="[]",
            nullable=False,
        ),
        sa.Column(
            "raw_data", postgresql.JSONB(astext_type=sa.Text()), server_default="{}", nullable=False
        ),
        sa.CheckConstraint(f"severity IN ({SEVERITIES})", name=op.f("ck_findings_severity_valid")),
        sa.CheckConstraint(
            f"status IN ({FINDING_STATUSES})", name=op.f("ck_findings_status_valid")
        ),
        sa.CheckConstraint(
            f"confidence IN ({CONFIDENCES})", name=op.f("ck_findings_confidence_valid")
        ),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["tool_runs.id"],
            name=op.f("fk_findings_run_id_tool_runs"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_findings")),
    )
    op.create_index(op.f("ix_findings_run_id"), "findings", ["run_id"])
    op.create_index(op.f("ix_findings_severity"), "findings", ["severity"])

    op.execute(
        f"""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN
                REVOKE ALL ON tool_runs, findings FROM {APP_ROLE};
                GRANT SELECT, INSERT, UPDATE ON tool_runs TO {APP_ROLE};
                GRANT SELECT, INSERT ON findings TO {APP_ROLE};
            END IF;
        END
        $$
        """  # noqa: S608  (APP_ROLE is a module constant, never input)
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_findings_severity"), table_name="findings")
    op.drop_index(op.f("ix_findings_run_id"), table_name="findings")
    op.drop_table("findings")
    op.drop_index("ix_tool_runs_active_by_user", table_name="tool_runs")
    op.drop_index("ix_tool_runs_tool_id_created_at", table_name="tool_runs")
    op.drop_index("ix_tool_runs_user_id_created_at", table_name="tool_runs")
    op.drop_index(op.f("ix_tool_runs_created_at"), table_name="tool_runs")
    op.drop_table("tool_runs")

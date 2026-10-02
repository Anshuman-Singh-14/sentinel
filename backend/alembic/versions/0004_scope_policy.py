"""Scope policy entries and authorization acknowledgements.

Grants, written out like 0002/0003:

* ``scope_entries``: SELECT, INSERT, UPDATE, DELETE. Admins manage the
  policy; every change is audited (``scope.policy.changed``).
* ``authorization_acknowledgements``: SELECT, INSERT only. An acceptance is
  evidence and is never edited or removed by the application.

The hard infrastructure denylist is deliberately *not* stored in the database
(it comes from settings), so no database write can lift it.

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-02
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APP_ROLE = "sentinel_app"


def upgrade() -> None:
    op.create_table(
        "authorization_acknowledgements",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("statement_version", sa.Integer(), nullable=False),
        sa.Column("statement_sha256", sa.String(length=64), nullable=False),
        sa.Column(
            "acknowledged_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("source_ip", sa.String(length=64), nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_authorization_acknowledgements_user_id_users"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_authorization_acknowledgements")),
        sa.UniqueConstraint(
            "user_id",
            "statement_version",
            name=op.f("uq_authorization_acknowledgements_user_id"),
        ),
    )
    op.create_index(
        op.f("ix_authorization_acknowledgements_user_id"),
        "authorization_acknowledgements",
        ["user_id"],
    )
    op.create_table(
        "scope_entries",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("kind", sa.String(length=8), nullable=False),
        sa.Column("value", sa.String(length=253), nullable=False),
        sa.Column("description", sa.String(length=256), server_default="", nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("kind IN ('cidr', 'domain')", name=op.f("ck_scope_entries_kind_valid")),
        sa.ForeignKeyConstraint(
            ["created_by"],
            ["users.id"],
            name=op.f("fk_scope_entries_created_by_users"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scope_entries")),
        sa.UniqueConstraint("kind", "value", name=op.f("uq_scope_entries_kind")),
    )

    op.execute(
        f"""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN
                REVOKE ALL ON scope_entries, authorization_acknowledgements FROM {APP_ROLE};
                GRANT SELECT, INSERT, UPDATE, DELETE ON scope_entries TO {APP_ROLE};
                GRANT SELECT, INSERT ON authorization_acknowledgements TO {APP_ROLE};
            END IF;
        END
        $$
        """  # noqa: S608  (APP_ROLE is a module constant, never input)
    )


def downgrade() -> None:
    op.drop_table("scope_entries")
    op.drop_index(
        op.f("ix_authorization_acknowledgements_user_id"),
        table_name="authorization_acknowledgements",
    )
    op.drop_table("authorization_acknowledgements")

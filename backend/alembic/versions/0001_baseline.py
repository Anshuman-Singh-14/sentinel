"""Baseline: empty schema.

Establishes the migration history so every later schema change is a reviewed,
reversible revision (CLAUDE.md rule 10). The first tables arrive in Phase 2.

Revision ID: 0001
Revises:
Create Date: 2026-10-01
"""

from collections.abc import Sequence

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass

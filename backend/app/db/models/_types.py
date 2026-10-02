"""Column helpers shared by the models."""

from datetime import UTC, datetime


def utcnow() -> datetime:
    """Timezone-aware UTC now. Naive datetimes are never stored."""
    return datetime.now(UTC)

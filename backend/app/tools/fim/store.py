"""The FIM tools' only door to durable state (ADR 0015, section 2).

Tools never touch the database. Like ``Cache`` and ``WindowLimiter`` in
``app.core.external``, the tools depend on this small protocol; the SQL
implementation lives in ``app.fim.store`` and tests use an in-memory fake.
"""

import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from app.tools.fim.scanner import Entry


@dataclass(frozen=True, slots=True)
class BaselineSpec:
    name: str
    root: str  # root name from FIM_ROOTS
    path: str  # root-relative directory, "" for the whole root
    excludes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SavedBaseline:
    baseline_id: uuid.UUID
    created_at: datetime
    created_by: str


@dataclass(frozen=True, slots=True)
class StoredBaseline:
    baseline_id: uuid.UUID
    spec: BaselineSpec
    created_at: datetime
    created_by: str
    entries: Mapping[str, Entry]


class BaselineNotFound(LookupError):
    """No such baseline, or it was deleted."""


class BaselineStore(Protocol):
    async def save(
        self, run_id: uuid.UUID, spec: BaselineSpec, entries: Mapping[str, Entry]
    ) -> SavedBaseline:
        """Store a new baseline, attributed to the user who started ``run_id``."""
        ...

    async def load(self, baseline_id: uuid.UUID) -> StoredBaseline:
        """The baseline and all its entries. Raises ``BaselineNotFound``."""
        ...

    async def record_check(
        self, run_id: uuid.UUID, baseline_id: uuid.UUID, counts: Mapping[str, int]
    ) -> None:
        """Note the check on the baseline and audit ``fim.check.completed``."""
        ...

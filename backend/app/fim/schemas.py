"""Baseline management API shapes (ADR 0015, section 8)."""

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict

from app.db.models import FimBaseline

ScheduleMinutes = Literal[15, 60, 360, 1440]


class BaselineOut(BaseModel):
    id: uuid.UUID
    name: str
    root: str
    path: str
    excludes: list[str]
    file_count: int
    dir_count: int
    other_count: int
    total_bytes: int
    created_by: uuid.UUID
    created_by_username: str
    created_run_id: uuid.UUID | None
    created_at: datetime
    schedule_minutes: int | None
    last_scheduled_at: datetime | None
    last_checked_at: datetime | None
    last_check_run_id: uuid.UUID | None
    last_check_changes: int | None

    @classmethod
    def from_row(cls, row: FimBaseline) -> "BaselineOut":
        return cls.model_validate(row, from_attributes=True)


class BaselineList(BaseModel):
    baselines: list[BaselineOut]
    schedule_choices: list[int]


class BaselineUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # null switches scheduled checks off.
    schedule_minutes: ScheduleMinutes | None

"""FIM parameters, validated at the API boundary (CLAUDE.md rule 3).

The root is chosen by *name*. Names come from ``FIM_ROOTS`` and are added to
the JSON Schema as an ``enum`` when the catalogue is generated, so the form
shows a drop-down and server paths never reach the browser. The worker
repeats every check against the filesystem (``scanner.resolve_base``).
"""

import uuid
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.config import get_settings
from app.core.security.paths import PathRejected, check_relative_path

MAX_EXCLUDES = 32
MAX_EXCLUDE_LENGTH = 200


def _root_enum(schema: dict[str, Any]) -> None:
    # Called each time the schema is generated: reflects the current settings.
    schema["enum"] = sorted(get_settings().fim_roots)


def parse_excludes(value: str) -> tuple[str, ...]:
    patterns = tuple(p.strip() for p in value.split(",") if p.strip())
    if len(patterns) > MAX_EXCLUDES:
        raise ValueError(f"Give at most {MAX_EXCLUDES} exclude patterns.")
    for pattern in patterns:
        if len(pattern) > MAX_EXCLUDE_LENGTH:
            raise ValueError(f"Exclude patterns may be at most {MAX_EXCLUDE_LENGTH} characters.")
        if any(ord(ch) < 32 for ch in pattern) or "\\" in pattern:
            raise ValueError("Exclude patterns may not contain control characters or backslashes.")
    return patterns


class FimBaselineParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(
        min_length=1,
        max_length=80,
        pattern=r"^[^\x00-\x1f\x7f]+$",
        title="Baseline name",
        description="A label for this baseline, e.g. 'web server config before release'.",
        examples=["demo before changes"],
    )
    root: str = Field(
        max_length=32,
        title="FIM root",
        description="One of the directories the server allows FIM to read (FIM_ROOTS).",
        json_schema_extra=_root_enum,
    )
    path: str = Field(
        default="",
        max_length=255,
        title="Subdirectory",
        description="Optional directory inside the root, e.g. etc. Empty means the whole root.",
        examples=["etc"],
    )
    exclude: str = Field(
        default="",
        max_length=2000,
        title="Exclude patterns",
        description=(
            "Optional, comma-separated globs matched against the path or the file name, "
            "e.g. *.log, cache. '*' also matches '/'."
        ),
        examples=["*.log, *.tmp"],
    )

    @field_validator("name")
    @classmethod
    def _trim(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Give the baseline a name.")
        return value

    @field_validator("root")
    @classmethod
    def _known_root(cls, value: str) -> str:
        if value not in get_settings().fim_roots:
            raise ValueError("Unknown FIM root. Choose one of the roots the server offers.")
        return value

    @field_validator("path")
    @classmethod
    def _safe_relative_path(cls, value: str) -> str:
        if not value:
            return value
        try:
            return check_relative_path(value.strip("/"))
        except PathRejected as exc:
            raise ValueError(exc.message) from None

    @field_validator("exclude")
    @classmethod
    def _valid_excludes(cls, value: str) -> str:
        return ", ".join(parse_excludes(value))

    @property
    def excludes(self) -> tuple[str, ...]:
        return parse_excludes(self.exclude)


class FimCheckParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    baseline_id: uuid.UUID = Field(
        title="Baseline",
        description="The baseline to compare against. Pick one from the list below.",
    )

"""Path sensitivity rules (``sensitivity.yaml``): which paths matter most.

Loaded with ``yaml.safe_load``, size-capped and validated with Pydantic, like
the log analyzer's rules. An invalid file fails at first use with a clear
error instead of silently rating everything LOW.
"""

from dataclasses import dataclass
from fnmatch import fnmatchcase
from functools import lru_cache
from pathlib import Path, PurePosixPath
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

from app.engine.schemas import Severity

RULES_FILE = Path(__file__).resolve().parent / "sensitivity.yaml"
MAX_FILE_BYTES = 100_000

Level = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class SensitivityRule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    pattern: str = Field(min_length=1, max_length=200, pattern=r"^[^\x00-\x1f\\]+$")
    level: Level
    reason: str = Field(min_length=1, max_length=200)

    def matches(self, path: str) -> bool:
        if fnmatchcase(path, self.pattern):
            return True
        # A pattern without a slash ("*.conf") also matches the bare name.
        return "/" not in self.pattern and fnmatchcase(PurePosixPath(path).name, self.pattern)


class SensitivityFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: int = Field(ge=1, le=1)
    version: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    rules: list[SensitivityRule] = Field(max_length=200)


@dataclass(frozen=True, slots=True)
class Sensitivity:
    level: Severity
    pattern: str | None
    reason: str


DEFAULT = Sensitivity(Severity.LOW, None, "no sensitivity rule matches this path")


def load_rules(path: Path = RULES_FILE) -> SensitivityFile:
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError(f"{path.name} exceeds {MAX_FILE_BYTES} bytes")
    return SensitivityFile.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))


@lru_cache
def get_rules() -> SensitivityFile:
    return load_rules()


def classify(path: str, rules: SensitivityFile | None = None) -> Sensitivity:
    """First matching rule wins; unmatched paths are LOW."""
    for rule in (rules or get_rules()).rules:
        if rule.matches(path):
            return Sensitivity(Severity(rule.level), rule.pattern, rule.reason)
    return DEFAULT

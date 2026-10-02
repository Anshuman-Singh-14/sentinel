"""Knowledge base: explanation and remediation text kept in versioned YAML.

Educational text lives in one reviewable place instead of being scattered
across tool code (01-architecture.md). Files are parsed with ``yaml.safe_load``
only (never ``yaml.load``, which can construct arbitrary Python objects) and
validated with Pydantic. An invalid file stops startup instead of producing
half-explained findings at run time.
"""

from functools import lru_cache
from pathlib import Path
from string import Template
from typing import Annotated

import yaml
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError

from app.engine.schemas import Severity

KNOWLEDGE_DIR = Path(__file__).resolve().parent
_MAX_FILE_BYTES = 1_000_000

EntryKey = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$")]


class KnowledgeError(Exception):
    """A knowledge file is missing, malformed or inconsistent."""


class KnowledgeEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    title: str = Field(min_length=1)
    explanation: str = Field(min_length=1)
    remediation: str = Field(min_length=1)
    severity: Severity
    severity_rationale: str = Field(min_length=1)
    references: tuple[str, ...] = ()

    def render(self, field: str, **values: object) -> str:
        """Fill ``$placeholders`` in a text field.

        ``string.Template`` substitutes plain names only. Unlike ``str.format``,
        it cannot reach object attributes (``{x.__class__}``), so even a
        careless template cannot leak internals.
        """
        text: str = getattr(self, field)
        return Template(text).safe_substitute({k: str(v) for k, v in values.items()})


class KnowledgeFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: int = Field(ge=1, le=1)
    namespace: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    version: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    entries: dict[EntryKey, KnowledgeEntry]


class KnowledgeBase:
    def __init__(self, entries: dict[str, KnowledgeEntry], versions: dict[str, str]) -> None:
        self._entries = entries
        self.versions = versions  # namespace -> knowledge file version

    def get(self, key: str) -> KnowledgeEntry:
        try:
            return self._entries[key]
        except KeyError:
            raise KnowledgeError(f"Unknown knowledge entry: {key!r}") from None

    def __contains__(self, key: object) -> bool:
        return key in self._entries

    def __len__(self) -> int:
        return len(self._entries)


def load_knowledge(directory: Path = KNOWLEDGE_DIR) -> KnowledgeBase:
    entries: dict[str, KnowledgeEntry] = {}
    versions: dict[str, str] = {}
    for path in sorted(directory.glob("*.yaml")):
        if path.stat().st_size > _MAX_FILE_BYTES:
            raise KnowledgeError(f"{path.name}: file exceeds {_MAX_FILE_BYTES} bytes")
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
            parsed = KnowledgeFile.model_validate(raw)
        except (yaml.YAMLError, ValidationError) as exc:
            raise KnowledgeError(f"{path.name}: invalid knowledge file: {exc}") from exc
        if parsed.namespace in versions:
            raise KnowledgeError(f"{path.name}: duplicate namespace {parsed.namespace!r}")
        versions[parsed.namespace] = parsed.version
        for key, entry in parsed.entries.items():
            if not key.startswith(f"{parsed.namespace}."):
                raise KnowledgeError(
                    f"{path.name}: key {key!r} must start with {parsed.namespace + '.'!r}"
                )
            entries[key] = entry
    return KnowledgeBase(entries, versions)


@lru_cache
def get_knowledge_base() -> KnowledgeBase:
    return load_knowledge()

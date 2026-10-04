"""The exporter plugin contract and its registry.

An exporter turns a ``ReportDocument`` into bytes. Adding a format means one
new module with one ``@register`` class, plus one import line in
``exporters/__init__.py`` (CLAUDE.md rule 9). The API, the worker and the
frontend's export buttons all read the registry, so nothing else changes.

Exporters are pure and synchronous: no I/O, no network, no database. The
worker runs them in a thread with a timeout.
"""

import re
from abc import ABC, abstractmethod
from typing import ClassVar

from app.reports.document import ReportDocument
from app.reports.sanitize import clean_text

__all__ = ["Exporter", "clean_text", "exporters", "get_exporter", "register"]

FORMAT_PATTERN = re.compile(r"^[a-z][a-z0-9]{1,7}$")


class Exporter(ABC):
    format: ClassVar[str]
    label: ClassVar[str]
    media_type: ClassVar[str]
    extension: ClassVar[str]

    @abstractmethod
    def render(self, doc: ReportDocument) -> bytes: ...


_registry: dict[str, type[Exporter]] = {}


def register[E: type[Exporter]](cls: E) -> E:
    """Class decorator: validate the metadata and add the exporter to the registry."""
    if not FORMAT_PATTERN.match(cls.format):
        raise ValueError(f"invalid exporter format {cls.format!r}")
    if cls.format in _registry:
        raise ValueError(f"duplicate exporter format {cls.format!r}")
    if not FORMAT_PATTERN.match(cls.extension):
        raise ValueError(f"invalid exporter extension {cls.extension!r}")
    _registry[cls.format] = cls
    return cls


def get_exporter(fmt: str) -> Exporter:
    try:
        return _registry[fmt]()
    except KeyError:
        raise LookupError(f"no exporter for format {fmt!r}") from None


def exporters() -> list[type[Exporter]]:
    return list(_registry.values())

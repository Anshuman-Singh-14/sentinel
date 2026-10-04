"""Rule definitions (rules.yaml) and the five detectors that evaluate them.

Every detector is streaming and bounded:

* state is kept per source IP, and at most ``MAX_KEYS`` IPs are tracked per
  rule (a log from a large botnet degrades to "partial", it does not exhaust
  memory);
* per-IP windows keep at most a fixed number of timestamps;
* evidence samples are capped and truncated.

So memory depends on the number of distinct attackers (capped), never on the
number of lines.
"""

from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any, Literal, Self
from urllib.parse import unquote

import yaml
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from app.tools.log_analyzer.parsers import PARSER_NAMES, LogEvent

RULES_FILE = Path(__file__).resolve().parent / "rules.yaml"
MAX_RULES_FILE_BYTES = 200_000
MAX_KEYS = 50_000
MAX_SAMPLES = 3
MAX_SAMPLE_CHARS = 200
MAX_VALUES_KEPT = 20
MAX_SPIKES = 50

RuleId = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{1,63}$")]
Detector = Literal["burst", "distinct", "sequence", "match", "spike"]
StatusClass = Literal["1xx", "2xx", "3xx", "4xx", "5xx"]


class RuleError(Exception):
    """rules.yaml is missing, malformed or inconsistent (stops startup)."""


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: RuleId
    title: str = Field(min_length=1, max_length=120)
    parser: str
    detector: Detector
    events: tuple[str, ...] = Field(min_length=1)
    threshold: int = Field(ge=1, le=1_000_000)
    window_seconds: int | None = Field(default=None, ge=1, le=86_400 * 7)
    category: str = Field(pattern=r"^[A-Z][A-Z0-9_]*$", max_length=64)
    knowledge: str = Field(pattern=r"^log_analyzer\.[a-z0-9_]+$")
    enabled: bool = True
    # detector-specific
    field: str | None = Field(default=None, max_length=32)
    then: str | None = None
    equals: tuple[str, ...] = ()
    contains_any: tuple[str, ...] = ()
    builtin: Literal["path_traversal"] | None = None
    statuses: tuple[StatusClass, ...] = ()
    bucket_seconds: int | None = Field(default=None, ge=10, le=3600)

    @model_validator(mode="after")
    def _detector_requirements(self) -> Self:
        if self.parser not in PARSER_NAMES:
            raise ValueError(f"unknown parser {self.parser!r}")
        need: dict[str, bool] = {
            "burst": self.window_seconds is not None,
            "distinct": self.field is not None,
            "sequence": self.then is not None,
            "match": (self.field is not None and bool(self.equals or self.contains_any))
            or self.builtin is not None,
            "spike": bool(self.statuses) and self.bucket_seconds is not None,
        }
        if not need[self.detector]:
            raise ValueError(f"rule {self.id!r}: missing settings for detector {self.detector!r}")
        return self


class RuleFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: int = Field(ge=1, le=1)
    version: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    rules: tuple[Rule, ...]

    @model_validator(mode="after")
    def _unique_ids(self) -> Self:
        ids = [rule.id for rule in self.rules]
        if len(ids) != len(set(ids)):
            raise ValueError("rule ids must be unique")
        return self


def load_rules(path: Path = RULES_FILE) -> RuleFile:
    """Parse with ``yaml.safe_load`` only (never ``yaml.load``) and validate."""
    try:
        if path.stat().st_size > MAX_RULES_FILE_BYTES:
            raise RuleError(f"{path.name} exceeds {MAX_RULES_FILE_BYTES} bytes")
        return RuleFile.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
    except (OSError, yaml.YAMLError, ValueError) as exc:
        raise RuleError(f"{path.name}: {exc}") from exc


@lru_cache
def get_rules() -> RuleFile:
    return load_rules()


# --- helpers -------------------------------------------------------------------

_CONTROL = dict.fromkeys(range(32), "?") | {127: "?"}


def sample_text(text: str) -> str:
    """Make attacker-controlled log text safe to show: no control characters, short."""
    cleaned = text.translate(_CONTROL)
    return cleaned if len(cleaned) <= MAX_SAMPLE_CHARS else cleaned[:MAX_SAMPLE_CHARS] + "…"


TRAVERSAL_MARKERS = ("../", "..\\", "..;/", "\x00")
# Encodings that a single URL-decode does not turn into "../": overlong UTF-8
# and IIS %u escapes, recognised in their raw form.
RAW_TRAVERSAL_MARKERS = ("%c0%ae", "%e0%80%ae", "%c0%af", "%c1%9c", "%u002e", "%uff0e")
SENSITIVE_TARGETS = ("/etc/passwd", "/etc/shadow", "/proc/self/environ", "win.ini", "boot.ini")


def looks_like_traversal(target: str) -> str | None:
    """Name the traversal technique in a request target, or None.

    Decodes up to three times, so double- and triple-encoded variants
    (``%252e%252e%252f``) are seen as what they become on a naive server.
    """
    lowered = target.lower()
    for marker in RAW_TRAVERSAL_MARKERS:
        if marker in lowered:
            return f"overlong or %u-encoded dot ({marker})"
    # Traversal in any decoding round wins over the weaker "sensitive file
    # name" signal, so the reported technique is the most specific one.
    rounds = [lowered]
    for _ in range(3):
        decoded = unquote(rounds[-1])
        if decoded == rounds[-1]:
            break
        rounds.append(decoded)
    for round_no, text in enumerate(rounds):
        if "\x00" in text:
            return "null byte injection"
        if any(marker in text for marker in TRAVERSAL_MARKERS):
            return "'..' sequence" + ("" if round_no == 0 else f" after {round_no} decode(s)")
    for name in SENSITIVE_TARGETS:
        if name in rounds[-1]:
            return f"request for a sensitive system file ({name})"
    return None


def status_class(status: str) -> str:
    return f"{status[:1]}xx" if status[:1].isdigit() else "?"


# --- detections ------------------------------------------------------------------


@dataclass(slots=True)
class Detection:
    """One rule firing for one key (usually a source IP)."""

    rule: Rule
    key: str
    count: int
    first_seen: datetime | None
    last_seen: datetime | None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class _KeyState:
    count: int = 0
    first: datetime | None = None
    last: datetime | None = None
    window: deque[datetime] = field(default_factory=deque)
    peak: int = 0
    triggered: bool = False
    values: set[str] = field(default_factory=set)
    distinct: int = 0
    samples: list[str] = field(default_factory=list)
    lines: list[int] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    def touch(self, event: LogEvent) -> None:
        self.count += 1
        ts = event.timestamp
        if ts is not None:
            if self.first is None or ts < self.first:
                self.first = ts
            if self.last is None or ts > self.last:
                self.last = ts

    def sample(self, text: str, line_no: int) -> None:
        if len(self.samples) < MAX_SAMPLES:
            self.samples.append(sample_text(text))
            self.lines.append(line_no)


class BaseDetector:
    def __init__(self, rule: Rule) -> None:
        self.rule = rule
        self.events = frozenset(rule.events)
        self.keys: dict[str, _KeyState] = {}
        self.overflow = False  # MAX_KEYS reached: results are partial

    def wants(self, event: LogEvent) -> bool:
        return event.kind in self.events or event.kind == self.rule.then

    def state(self, key: str) -> _KeyState | None:
        found = self.keys.get(key)
        if found is None:
            if len(self.keys) >= MAX_KEYS:
                self.overflow = True
                return None
            found = self.keys[key] = _KeyState()
        return found

    def feed(self, event: LogEvent) -> None:
        raise NotImplementedError

    def results(self) -> list[Detection]:
        return [
            Detection(self.rule, key, s.count, s.first, s.last, self.details(s))
            for key, s in self.keys.items()
            if s.triggered
        ]

    def details(self, state: _KeyState) -> dict[str, Any]:
        return {"samples": state.samples, "lines": state.lines}


class BurstDetector(BaseDetector):
    """``threshold`` events from one IP within ``window_seconds``."""

    def __init__(self, rule: Rule) -> None:
        super().__init__(rule)
        assert rule.window_seconds is not None  # noqa: S101  (guaranteed by the Rule validator)
        self.window = timedelta(seconds=rule.window_seconds)
        self.keep = rule.threshold * 4  # enough to report a peak well above the threshold

    def feed(self, event: LogEvent) -> None:
        if event.ip is None or event.timestamp is None:
            return
        state = self.state(event.ip)
        if state is None:
            return
        state.touch(event)
        window = state.window
        while window and event.timestamp - window[0] > self.window:
            window.popleft()
        if len(window) < self.keep:
            window.append(event.timestamp)
        state.peak = max(state.peak, len(window))
        if len(window) >= self.rule.threshold:
            state.triggered = True
        if self.rule.parser == "auth_log":
            state.values.add(event.fields.get("user", ""))
        elif len(state.samples) < MAX_SAMPLES:
            state.sample(event.fields.get("request", ""), event.line_no)

    def details(self, state: _KeyState) -> dict[str, Any]:
        peak = f"{state.peak}+" if state.peak >= self.keep else str(state.peak)
        users = sorted(state.values - {""})[:MAX_VALUES_KEPT]
        return {
            "peak_in_window": peak,
            **({"users": [sample_text(u) for u in users]} if users else {}),
            **({"samples": state.samples} if state.samples else {}),
        }


class DistinctDetector(BaseDetector):
    """``threshold`` different values of a field (e.g. user names) from one IP."""

    def feed(self, event: LogEvent) -> None:
        if event.ip is None:
            return
        state = self.state(event.ip)
        if state is None:
            return
        state.touch(event)
        value = event.fields.get(self.rule.field or "", "")
        if value not in state.values and len(state.values) < MAX_VALUES_KEPT * 5:
            state.values.add(value)
        state.distinct = len(state.values)
        if state.distinct >= self.rule.threshold:
            state.triggered = True

    def details(self, state: _KeyState) -> dict[str, Any]:
        values = sorted(state.values)[:MAX_VALUES_KEPT]
        return {
            "distinct_values": state.distinct,
            "values": [sample_text(v) for v in values],
        }


class SequenceDetector(BaseDetector):
    """A ``then`` event from an IP after ``threshold`` earlier ``events``."""

    def __init__(self, rule: Rule) -> None:
        super().__init__(rule)
        self.window = timedelta(seconds=rule.window_seconds) if rule.window_seconds else None

    def feed(self, event: LogEvent) -> None:
        if event.ip is None:
            return
        state = self.state(event.ip)
        if state is None:
            return
        failures = state.extra.setdefault("failures", 0)
        if event.kind in self.events:
            state.extra["failures"] = failures + 1
            state.extra["last_failure"] = event.timestamp
            return
        # The `then` event (a successful login).
        last = state.extra.get("last_failure")
        recent = (
            self.window is None
            or last is None
            or event.timestamp is None
            or event.timestamp - last <= self.window
        )
        if failures >= self.rule.threshold and recent:
            state.triggered = True
            state.touch(event)
            successes: list[dict[str, Any]] = state.extra.setdefault("successes", [])
            if len(successes) < MAX_SAMPLES:
                successes.append(
                    {
                        "user": sample_text(event.fields.get("user", "")),
                        "method": event.fields.get("method", ""),
                        "failures_before": failures,
                        "at": event.timestamp.isoformat() if event.timestamp else None,
                        "line": event.line_no,
                    }
                )
        state.extra["failures"] = 0  # a success resets the streak

    def details(self, state: _KeyState) -> dict[str, Any]:
        return {"successes": state.extra.get("successes", [])}


class MatchDetector(BaseDetector):
    """Events whose field equals or contains a listed value, or a built-in matcher."""

    def __init__(self, rule: Rule) -> None:
        super().__init__(rule)
        self.equals = frozenset(rule.equals)
        self.contains = tuple(value.lower() for value in rule.contains_any)

    def _matches(self, event: LogEvent) -> str | None:
        if self.rule.builtin == "path_traversal":
            return looks_like_traversal(event.fields.get("target", ""))
        value = event.fields.get(self.rule.field or "", "")
        if value in self.equals:
            return value
        lowered = value.lower()
        return next((needle for needle in self.contains if needle in lowered), None)

    def feed(self, event: LogEvent) -> None:
        if event.ip is None:
            return
        reason = self._matches(event)
        if reason is None:
            return
        state = self.state(event.ip)
        if state is None:
            return
        state.touch(event)
        if state.count >= self.rule.threshold:
            state.triggered = True
        if len(state.values) < MAX_VALUES_KEPT:
            state.values.add(reason)
        kinds: dict[str, int] = state.extra.setdefault("by_kind", {})
        kinds[event.kind] = kinds.get(event.kind, 0) + 1
        status = event.fields.get("status")
        if status and status_class(status) == "2xx":
            state.extra["successful_responses"] = state.extra.get("successful_responses", 0) + 1
        text = event.fields.get("request") or event.fields.get("user_agent") or ""
        if event.kind.startswith("ssh_"):
            text = f"{event.kind} user={event.fields.get('user', '')}"
        elif self.rule.field == "user_agent":
            text = event.fields.get("user_agent", "")
        state.sample(text, event.line_no)

    def details(self, state: _KeyState) -> dict[str, Any]:
        return {
            "matched": sorted(sample_text(v) for v in state.values),
            "by_event": state.extra.get("by_kind", {}),
            "successful_responses": state.extra.get("successful_responses", 0),
            "samples": state.samples,
            "lines": state.lines,
        }


class SpikeDetector(BaseDetector):
    """``threshold`` responses of the listed status classes in one time bucket."""

    def __init__(self, rule: Rule) -> None:
        super().__init__(rule)
        assert rule.bucket_seconds is not None  # noqa: S101  (guaranteed by the Rule validator)
        self.bucket = rule.bucket_seconds
        self.classes = frozenset(rule.statuses)
        self.buckets: dict[int, dict[str, int]] = {}
        self.spikes: list[Detection] = []
        self.latest = 0

    def feed(self, event: LogEvent) -> None:
        if event.timestamp is None:
            return
        slot = int(event.timestamp.timestamp()) // self.bucket
        counts = self.buckets.setdefault(slot, {"total": 0})
        counts["total"] += 1
        cls = status_class(event.fields.get("status", ""))
        counts[cls] = counts.get(cls, 0) + 1
        if slot > self.latest:
            self.latest = slot
            self._flush(older_than=slot - 5)  # logs are near-chronological

    def _flush(self, older_than: int | None = None) -> None:
        for slot in sorted(self.buckets):
            if older_than is not None and slot >= older_than:
                break
            counts = self.buckets.pop(slot)
            errors = sum(counts.get(cls, 0) for cls in self.classes)
            if errors >= self.rule.threshold and len(self.spikes) < MAX_SPIKES:
                start = datetime.fromtimestamp(slot * self.bucket, tz=UTC)
                self.spikes.append(
                    Detection(
                        self.rule,
                        start.isoformat(),
                        errors,
                        start,
                        start + timedelta(seconds=self.bucket),
                        {
                            "bucket_seconds": self.bucket,
                            "total_requests": counts["total"],
                            "by_status_class": {
                                k: v for k, v in sorted(counts.items()) if k != "total"
                            },
                        },
                    )
                )

    def results(self) -> list[Detection]:
        self._flush()
        return list(self.spikes)


DETECTORS: dict[str, type[BaseDetector]] = {
    "burst": BurstDetector,
    "distinct": DistinctDetector,
    "sequence": SequenceDetector,
    "match": MatchDetector,
    "spike": SpikeDetector,
}


def detectors_for(parser: str, rules: RuleFile) -> list[BaseDetector]:
    return [
        DETECTORS[rule.detector](rule)
        for rule in rules.rules
        if rule.enabled and rule.parser == parser
    ]

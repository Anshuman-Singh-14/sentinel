"""Playbook definitions (YAML, validated) and the API shapes for playbook runs."""

import re
import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.core.runs.schemas import RunSummary
from app.engine.schemas import Finding, Severity
from app.playbooks.templating import references_in

_ID = r"^[a-z][a-z0-9_]{1,63}$"

InputKind = Literal["host", "domain", "url", "string"]


class InputSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: InputKind = "string"
    title: str = Field(min_length=1, max_length=80)
    description: str = Field(default="", max_length=300)
    required: bool = True
    # May reference earlier inputs, e.g. "https://{{ inputs.target }}/".
    default: str | None = Field(default=None, max_length=500)
    example: str | None = Field(default=None, max_length=200)


class StepSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=_ID)
    name: str = Field(min_length=1, max_length=128)
    tool_id: str = Field(pattern=_ID)
    params: dict[str, Any] = Field(default_factory=dict)
    on_failure: Literal["stop", "continue"] = "stop"
    # Optional steps are skipped (not failed) when their tool is not installed,
    # e.g. a step for a tool from a later phase. They activate automatically
    # once the tool is registered.
    optional: bool = False
    description: str = Field(default="", max_length=300)


class PlaybookDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    id: str = Field(pattern=_ID)
    name: str = Field(min_length=1, max_length=128)
    version: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    description: str = Field(min_length=1, max_length=1000)
    inputs: dict[str, InputSpec] = Field(min_length=1, max_length=10)
    # The input that names what the playbook is about (shown and scope-prechecked).
    target_input: str
    steps: list[StepSpec] = Field(min_length=1, max_length=20)

    @field_validator("inputs")
    @classmethod
    def _input_names(cls, value: dict[str, InputSpec]) -> dict[str, InputSpec]:
        for name in value:
            if not re.fullmatch(_ID, name):
                raise ValueError(f"input name {name!r} must match {_ID}")
        return value

    @model_validator(mode="after")
    def _references_are_backwards_only(self) -> "PlaybookDefinition":
        """Every reference must point at an input or an *earlier* step.

        Checked once, when the definition loads, so a typo or a forward
        reference fails at startup instead of halfway through a run.
        """
        if self.target_input not in self.inputs:
            raise ValueError(f"target_input {self.target_input!r} is not an input")
        input_names = list(self.inputs)
        for position, (name, spec) in enumerate(self.inputs.items()):
            for root, path in references_in(spec.default or ""):
                if root != "inputs" or not path or path[0] not in input_names[:position]:
                    raise ValueError(f"default of input {name!r} may only use earlier inputs")
        seen: list[str] = []
        for step in self.steps:
            if step.id in seen:
                raise ValueError(f"duplicate step id {step.id!r}")
            for root, path in references_in(step.params):
                first = path[0] if path else None
                if root == "inputs" and first not in self.inputs:
                    raise ValueError(f"step {step.id!r} uses unknown input {first!r}")
                if root == "steps" and first not in seen:
                    raise ValueError(
                        f"step {step.id!r} references {first!r}, which is not an earlier step"
                    )
            seen.append(step.id)
        return self


# --- API shapes -------------------------------------------------------------------------------


class StepInfo(BaseModel):
    id: str
    name: str
    tool_id: str
    tool_name: str | None
    available: bool
    optional: bool
    on_failure: str
    is_active: bool
    description: str


class PlaybookInfo(BaseModel):
    id: str
    name: str
    version: str
    description: str
    available: bool
    unavailable_reason: str | None
    requires_authorization: bool
    required_role: str
    # JSON Schema for the inputs, so the frontend's schema form can render it.
    inputs_schema: dict[str, Any]
    steps: list[StepInfo]


class PlaybookRunCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    inputs: dict[str, str] = Field(default_factory=dict)


class StepOut(BaseModel):
    position: int
    step_id: str
    name: str
    tool_id: str
    on_failure: str
    status: str
    run: RunSummary | None
    resolved_params: dict[str, Any] | None
    error: dict[str, Any] | None
    started_at: datetime | None
    completed_at: datetime | None


class AggregatedFinding(Finding):
    """A finding plus where it came from in the playbook."""

    step_id: str
    tool_id: str
    run_id: uuid.UUID
    also_reported_by: list[str] = Field(default_factory=list)


class RiskSummary(BaseModel):
    total: int
    by_severity: dict[Severity, int]
    highest: Severity | None
    headline: str


class PlaybookRunSummary(BaseModel):
    playbook_run_id: uuid.UUID
    playbook_id: str
    playbook_name: str
    target: str | None
    status: str
    initiated_by: str
    created_at: datetime
    completed_at: datetime | None
    duration_ms: int | None
    finding_count: int
    max_severity: Severity | None


class PlaybookRunDetail(PlaybookRunSummary):
    playbook_version: str
    inputs: dict[str, Any]
    user_id: uuid.UUID
    started_at: datetime | None
    progress_pct: int
    current_step: str | None
    cancel_requested: bool
    error: dict[str, Any] | None
    steps: list[StepOut]
    risk: RiskSummary
    findings: list[AggregatedFinding]


class PlaybookRunPage(BaseModel):
    runs: list[PlaybookRunSummary]
    next_before: uuid.UUID | None

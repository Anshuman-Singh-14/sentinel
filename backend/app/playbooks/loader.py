"""Load and validate playbook definitions; validate a run's inputs.

Definitions are YAML (``yaml.safe_load`` only, size-capped) validated by the
Pydantic schema. A broken definition fails at startup, never mid-run.
Availability is computed against the tool registry: a required step whose
tool is missing makes the playbook unavailable; an optional one is skipped.
"""

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from app.config import get_settings
from app.core.auth.roles import ROLE_RANK, Role
from app.core.errors import NotFound, ValidationFailed
from app.core.security.ssrf import parse_target_url
from app.core.security.validators import normalize_domain, normalize_host
from app.engine.registry import registry
from app.playbooks.schemas import InputSpec, PlaybookDefinition, PlaybookInfo, StepInfo
from app.playbooks.templating import TemplateReferenceError, render

DEFINITIONS_DIR = Path(__file__).resolve().parent / "definitions"
MAX_DEFINITION_BYTES = 200_000
MAX_INPUT_LENGTH = 2048


class PlaybookDefinitionError(Exception):
    pass


def load_definitions(directory: Path = DEFINITIONS_DIR) -> dict[str, PlaybookDefinition]:
    found: dict[str, PlaybookDefinition] = {}
    for path in sorted(directory.glob("*.yaml")):
        if path.stat().st_size > MAX_DEFINITION_BYTES:
            raise PlaybookDefinitionError(f"{path.name}: larger than {MAX_DEFINITION_BYTES} bytes")
        try:
            definition = PlaybookDefinition.model_validate(yaml.safe_load(path.read_text("utf-8")))
        except (yaml.YAMLError, ValidationError) as exc:
            raise PlaybookDefinitionError(f"{path.name}: {exc}") from exc
        if definition.id in found:
            raise PlaybookDefinitionError(f"{path.name}: duplicate playbook id {definition.id!r}")
        found[definition.id] = definition
    return found


@lru_cache
def definitions() -> dict[str, PlaybookDefinition]:
    return load_definitions()


def get_definition(playbook_id: str) -> PlaybookDefinition:
    try:
        return definitions()[playbook_id]
    except KeyError:
        raise NotFound("Playbook not found.") from None


def required_role(definition: PlaybookDefinition) -> Role:
    roles = [
        registry.get(s.tool_id).required_role for s in definition.steps if s.tool_id in registry
    ]
    return max(roles or [Role.ANALYST], key=lambda r: ROLE_RANK[r])


def describe(definition: PlaybookDefinition) -> PlaybookInfo:
    steps: list[StepInfo] = []
    missing_required: list[str] = []
    active = False
    for step in definition.steps:
        tool = registry.get(step.tool_id) if step.tool_id in registry else None
        availability = tool.availability() if tool else None
        usable = bool(availability and availability.available)
        if not usable and not step.optional:
            missing_required.append(step.tool_id)
        active = active or bool(tool and tool.is_active)
        steps.append(
            StepInfo(
                id=step.id,
                name=step.name,
                tool_id=step.tool_id,
                tool_name=tool.name if tool else None,
                available=usable,
                unavailable_reason=(
                    None
                    if usable
                    else (availability.reason if availability else "Not installed yet.")
                ),
                optional=step.optional,
                on_failure=step.on_failure,
                is_active=bool(tool and tool.is_active),
                description=step.description,
            )
        )
    return PlaybookInfo(
        id=definition.id,
        name=definition.name,
        version=definition.version,
        description=definition.description,
        available=not missing_required,
        unavailable_reason=(
            f"Required tool(s) not installed or not configured: {', '.join(missing_required)}"
            if missing_required
            else None
        ),
        requires_authorization=active,
        required_role=required_role(definition).value,
        inputs_schema=inputs_schema(definition),
        steps=steps,
    )


def inputs_schema(definition: PlaybookDefinition) -> dict[str, Any]:
    properties: dict[str, Any] = {}
    for name, spec in definition.inputs.items():
        prop: dict[str, Any] = {
            "type": "string",
            "title": spec.title,
            "maxLength": MAX_INPUT_LENGTH,
        }
        if spec.description:
            prop["description"] = spec.description
        if spec.example:
            prop["examples"] = [spec.example]
        properties[name] = prop
    return {
        "type": "object",
        "required": [n for n, s in definition.inputs.items() if s.required],
        "properties": properties,
    }


def _validate_input(name: str, spec: InputSpec, value: str) -> str:
    if spec.kind == "host":
        return normalize_host(value)
    if spec.kind == "domain":
        return normalize_domain(value)
    if spec.kind == "url":
        return str(parse_target_url(value, frozenset(get_settings().web_check_allowed_ports)))
    cleaned = value.strip()
    if len(cleaned) > MAX_INPUT_LENGTH:
        raise ValueError(f"at most {MAX_INPUT_LENGTH} characters")
    return cleaned


def validate_inputs(definition: PlaybookDefinition, raw: dict[str, str]) -> dict[str, str]:
    """Validate inputs in declaration order; defaults may use earlier inputs."""
    unknown = set(raw) - set(definition.inputs)
    errors: list[dict[str, Any]] = [
        {"loc": ["inputs", name], "msg": "Unknown input.", "type": "extra_forbidden"}
        for name in sorted(unknown)
    ]
    values: dict[str, str] = {}
    for name, spec in definition.inputs.items():
        value = (raw.get(name) or "").strip()
        if not value and spec.default is not None:
            try:
                value = str(render(spec.default, {"inputs": values}))
            except TemplateReferenceError:
                value = ""
        if not value:
            if spec.required:
                errors.append({"loc": ["inputs", name], "msg": "Required.", "type": "missing"})
            continue
        if len(value) > MAX_INPUT_LENGTH:
            errors.append({"loc": ["inputs", name], "msg": "Too long.", "type": "too_long"})
            continue
        try:
            values[name] = _validate_input(name, spec, value)
        except ValueError as exc:
            errors.append({"loc": ["inputs", name], "msg": str(exc), "type": "value_error"})
    if errors:
        raise ValidationFailed("The playbook inputs are invalid.", details={"errors": errors})
    return values

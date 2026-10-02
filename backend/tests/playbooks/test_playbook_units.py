"""Playbook building blocks: the safe resolver, definition validation, aggregation."""

import uuid
from typing import Any

import pytest
from pydantic import ValidationError

from app.core.errors import ValidationFailed
from app.engine.schemas import Finding, FindingStatus, Severity
from app.playbooks.aggregate import StepFindings, merge, risk_summary
from app.playbooks.loader import definitions, load_definitions, validate_inputs
from app.playbooks.schemas import PlaybookDefinition
from app.playbooks.templating import TemplateReferenceError, parse_reference, render

CTX: dict[str, Any] = {
    "inputs": {"target": "lab-https", "port": "8443"},
    "steps": {"dns": {"resolved_ips": ["10.0.0.1", "10.0.0.2"], "nested": {"a": [{"b": 7}]}}},
}

# --- the safe resolver -----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("template", "expected"),
    [
        ("{{ inputs.target }}", "lab-https"),
        ("{{steps.dns.resolved_ips}}", ["10.0.0.1", "10.0.0.2"]),  # keeps the list type
        ("{{ steps.dns.resolved_ips[1] }}", "10.0.0.2"),
        ("{{ steps.dns.nested.a[0].b }}", 7),
        ("https://{{ inputs.target }}:{{ inputs.port }}/", "https://lab-https:8443/"),
        ("no placeholders", "no placeholders"),
        (42, 42),
        (["{{ inputs.target }}", {"k": "{{ inputs.port }}"}], ["lab-https", {"k": "8443"}]),
    ],
)
def test_render(template: Any, expected: Any) -> None:
    assert render(template, CTX) == expected


@pytest.mark.parametrize(
    ("template", "message"),
    [
        # Attempts to reach outside plain JSON data or run code.
        ("{{ __import__('os').system('id') }}", "not a valid reference"),
        ("{{ inputs.target.__class__ }}", "has no field '__class__'"),
        ("{{ inputs.__dict__ }}", "has no field '__dict__'"),
        ("{{ config.secret }}", "not a valid reference"),
        ("{{ inputs['target'] }}", "not a valid reference"),
        ("{{ inputs.target | upper }}", "not a valid reference"),
        ("{{ 1 + 1 }}", "not a valid reference"),
        ("{{ steps.dns.resolved_ips[-1] }}", "not a valid reference"),
        # Missing data.
        ("{{ steps.nope.x }}", "has no field 'nope'"),
        ("{{ steps.dns.resolved_ips[5] }}", r"has no item \[5\]"),
        # A list cannot be pasted into text.
        ("ip={{ steps.dns.resolved_ips }}", "not a single value"),
    ],
)
def test_render_refuses(template: str, message: str) -> None:
    with pytest.raises(TemplateReferenceError, match=message):
        render(template, CTX)


def test_rendered_text_is_capped() -> None:
    big = {"inputs": {"x": "a" * 3000}, "steps": {}}
    with pytest.raises(TemplateReferenceError, match="too long"):
        render("{{ inputs.x }}{{ inputs.x }}", big)


def test_parse_reference() -> None:
    assert parse_reference("steps.dns.resolved_ips[0]") == ("steps", ["dns", "resolved_ips", 0])


# --- definitions ------------------------------------------------------------------------------


def base_definition(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "id": "test_pb",
        "name": "Test",
        "version": "1.0.0",
        "description": "d",
        "target_input": "target",
        "inputs": {"target": {"kind": "host", "title": "Target"}},
        "steps": [
            {
                "id": "one",
                "name": "One",
                "tool_id": "echo",
                "params": {"message": "{{ inputs.target }}"},
            },
            {
                "id": "two",
                "name": "Two",
                "tool_id": "echo",
                "params": {"message": "{{ steps.one.echoes[0] }}"},
            },
        ],
    }
    data.update(overrides)
    return data


def test_valid_definition() -> None:
    assert PlaybookDefinition.model_validate(base_definition()).steps[1].id == "two"


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (
            {
                "steps": [
                    {
                        "id": "one",
                        "name": "x",
                        "tool_id": "echo",
                        "params": {"m": "{{ steps.two.x }}"},
                    },
                    {"id": "two", "name": "y", "tool_id": "echo"},
                ]
            },
            "not an earlier step",
        ),
        (
            {
                "steps": [
                    {
                        "id": "one",
                        "name": "x",
                        "tool_id": "echo",
                        "params": {"m": "{{ steps.one.x }}"},
                    }
                ]
            },
            "not an earlier step",
        ),
        (
            {
                "steps": [
                    {
                        "id": "one",
                        "name": "x",
                        "tool_id": "echo",
                        "params": {"m": "{{ inputs.nope }}"},
                    }
                ]
            },
            "unknown input",
        ),
        (
            {
                "steps": [
                    {"id": "dup", "name": "x", "tool_id": "echo"},
                    {"id": "dup", "name": "y", "tool_id": "echo"},
                ]
            },
            "duplicate step id",
        ),
        ({"target_input": "missing"}, "target_input"),
        ({"steps": []}, "at least 1"),
        ({"steps": [{"id": "one", "name": "x", "tool_id": "echo", "on_failure": "retry"}]}, "stop"),
        ({"steps": [{"id": "one", "name": "x", "tool_id": "echo", "evil": True}]}, "Extra inputs"),
        (
            {
                "inputs": {
                    "target": {"kind": "host", "title": "t", "default": "{{ inputs.later }}"},
                    "later": {"kind": "string", "title": "l"},
                }
            },
            "earlier inputs",
        ),
    ],
)
def test_invalid_definitions(change: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        PlaybookDefinition.model_validate(base_definition(**change))


def test_shipped_definitions_load() -> None:
    loaded = load_definitions()
    audit = loaded["web_defensive_audit"]
    assert [s.tool_id for s in audit.steps] == [
        "dns_lookup",
        "port_scanner",
        "header_tls",
        "threat_intel",
    ]
    intel = audit.steps[-1]
    assert intel.optional and intel.on_failure == "continue"
    assert "{{ steps.dns.resolved_ips }}" in str(intel.params)


def test_inputs_validation_and_defaults() -> None:
    audit = definitions()["web_defensive_audit"]
    assert validate_inputs(audit, {"target": "Lab-HTTPS"}) == {
        "target": "lab-https",
        "web_url": "https://lab-https/",
    }
    with pytest.raises(ValidationFailed) as exc:
        validate_inputs(audit, {"target": "", "web_url": "gopher://x", "extra": "1"})
    locs = {tuple(e["loc"]) for e in exc.value.details["errors"]}
    assert locs == {("inputs", "extra"), ("inputs", "target"), ("inputs", "web_url")}


# --- aggregation ---------------------------------------------------------------------------------


def finding(item: str, severity: Severity, category: str = "TEST") -> Finding:
    return Finding(
        item=item,
        category=category,
        status=FindingStatus.DETECTED,
        severity=severity,
        severity_rationale="r",
        explanation="e",
        remediation="f",
    )


def test_merge_dedupes_and_ranks() -> None:
    a, b = uuid.uuid4(), uuid.uuid4()
    merged = merge(
        [
            StepFindings(
                "ports",
                "port_scanner",
                a,
                [finding("Telnet open", Severity.HIGH), finding("Same thing", Severity.LOW)],
            ),
            StepFindings(
                "web",
                "header_tls",
                b,
                [
                    finding("same THING ", Severity.LOW),
                    finding("Expired cert", Severity.CRITICAL),
                    finding("Same thing", Severity.MEDIUM),
                ],
            ),
        ]
    )
    assert [(f.item, f.severity) for f in merged] == [
        ("Expired cert", Severity.CRITICAL),
        ("Telnet open", Severity.HIGH),
        ("Same thing", Severity.MEDIUM),  # different severity: kept separately
        ("Same thing", Severity.LOW),
    ]
    low = merged[-1]
    assert low.step_id == "ports" and low.also_reported_by == ["web"] and low.run_id == a


def test_risk_summary() -> None:
    merged = merge(
        [
            StepFindings(
                "s", "t", uuid.uuid4(), [finding("x", Severity.HIGH), finding("y", Severity.INFO)]
            )
        ]
    )
    risk = risk_summary(merged, completed_steps=2, failed_steps=1)
    assert risk.highest is Severity.HIGH and risk.total == 2
    assert risk.headline.startswith("Highest severity HIGH: 1 high, 1 info")
    assert "coverage is partial" in risk.headline
    empty = risk_summary([], completed_steps=3, failed_steps=0)
    assert empty.highest is None and empty.headline == "No findings from 3 completed step(s)."

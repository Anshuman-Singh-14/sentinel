"""Phase 1 acceptance: the registry lists the echo tool."""

from typing import Any

import pytest
from pydantic import BaseModel, ConfigDict

from app.core.errors import ToolNotFound
from app.engine.base_tool import BaseTool, RawOutput, ToolContext
from app.engine.registry import DuplicateToolError, ToolRegistry, registry
from app.engine.schemas import Finding, ToolCategory
from app.tools.echo.tool import EchoTool


class Params(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LooseParams(BaseModel):
    pass


OMIT = object()


def make_tool_class(**attrs: Any) -> type[BaseTool[Any]]:
    """Build a concrete tool class. Metadata is validated on class creation."""

    async def run(self: Any, params: Any, ctx: ToolContext) -> RawOutput:
        return {}

    def translate(self: Any, raw: RawOutput, params: Any) -> list[Finding]:
        return []

    namespace: dict[str, Any] = {
        "tool_id": "sample_tool",
        "name": "Sample",
        "description": "A sample tool.",
        "version": "1.0.0",
        "category": ToolCategory.DIAGNOSTIC,
        "params_model": Params,
        "run": run,
        "translate": translate,
    }
    namespace.update(attrs)
    namespace = {k: v for k, v in namespace.items() if v is not OMIT}
    return type("SampleTool", (BaseTool,), namespace)


def test_discovery_registers_echo() -> None:
    registry.discover()

    assert "echo" in registry
    assert registry.get("echo") is EchoTool


def test_catalogue_describes_echo_with_json_schema() -> None:
    registry.discover()
    (echo,) = [entry for entry in registry.catalogue() if entry.tool_id == "echo"]

    assert echo.name == "Echo (diagnostic)"
    assert echo.version == "1.0.0"
    assert echo.is_active is False
    assert echo.params_schema["additionalProperties"] is False
    assert set(echo.params_schema["properties"]) == {"message", "repeat"}
    assert echo.params_schema["required"] == ["message"]


def test_duplicate_tool_id_rejected() -> None:
    local = ToolRegistry()
    local.register(make_tool_class())

    with pytest.raises(DuplicateToolError):
        local.register(make_tool_class())


def test_reregistering_same_class_is_idempotent() -> None:
    local = ToolRegistry()
    tool = make_tool_class()
    local.register(tool)
    local.register(tool)
    assert len(local) == 1


def test_unknown_tool_raises_structured_error() -> None:
    with pytest.raises(ToolNotFound):
        ToolRegistry().get("nope")


def test_catalogue_is_sorted() -> None:
    local = ToolRegistry()
    local.register(make_tool_class(tool_id="zeta"))
    local.register(make_tool_class(tool_id="alpha"))
    assert [t.tool_id for t in local.catalogue()] == ["alpha", "zeta"]


@pytest.mark.parametrize(
    ("attrs", "message"),
    [
        ({"tool_id": "Bad-ID"}, "tool_id"),
        ({"tool_id": "x"}, "tool_id"),
        ({"version": "1.0"}, "semver"),
        ({"params_model": LooseParams}, "extra='forbid'"),
        ({"queue": "nonexistent"}, "queue"),
        ({"soft_time_limit": 60, "hard_time_limit": 30}, "soft_time_limit"),
        ({"soft_time_limit": 0}, "soft_time_limit"),
    ],
)
def test_invalid_tool_metadata_fails_at_definition(attrs: dict[str, Any], message: str) -> None:
    with pytest.raises(TypeError, match=message):
        make_tool_class(**attrs)


def test_missing_metadata_fails_at_definition() -> None:
    with pytest.raises(TypeError, match="description"):
        make_tool_class(description=OMIT)

"""Tool registry and discovery.

Adding a tool means creating a package under ``app/tools/`` whose
``__init__.py`` contains one line, ``registry.register(MyTool)``. Discovery
imports every package there at startup. No core code changes (CLAUDE.md rule 9).
"""

import importlib
import pkgutil
import re
from typing import Any

from pydantic import BaseModel

from app.core.auth.roles import Role
from app.core.errors import ToolNotFound
from app.engine.base_tool import BaseTool
from app.engine.schemas import ToolCategory

AnyTool = type[BaseTool[Any]]

_PACKAGE_NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")


class DuplicateToolError(Exception):
    pass


class ToolDescriptor(BaseModel):
    """Public catalogue entry. The frontend renders forms from ``params_schema``."""

    tool_id: str
    name: str
    description: str
    version: str
    category: ToolCategory
    is_active: bool
    required_role: Role
    params_schema: dict[str, Any]


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, AnyTool] = {}

    def register(self, tool_cls: AnyTool) -> AnyTool:
        existing = self._tools.get(tool_cls.tool_id)
        if existing is not None and existing is not tool_cls:
            raise DuplicateToolError(
                f"tool_id {tool_cls.tool_id!r} already registered by {existing.__qualname__}"
            )
        self._tools[tool_cls.tool_id] = tool_cls
        return tool_cls

    def get(self, tool_id: str) -> AnyTool:
        try:
            return self._tools[tool_id]
        except KeyError:
            raise ToolNotFound() from None

    def create(self, tool_id: str) -> BaseTool[Any]:
        return self.get(tool_id)()

    def all(self) -> list[AnyTool]:
        return [self._tools[key] for key in sorted(self._tools)]

    def catalogue(self) -> list[ToolDescriptor]:
        return [
            ToolDescriptor(
                tool_id=tool.tool_id,
                name=tool.name,
                description=tool.description,
                version=tool.version,
                category=tool.category,
                is_active=tool.is_active,
                required_role=tool.required_role,
                params_schema=tool.params_model.model_json_schema(),
            )
            for tool in self.all()
        ]

    def discover(self, package: str = "app.tools") -> None:
        """Import every tool package so its registration line runs.

        Only simple lowercase package names are imported. Import errors are
        not swallowed: a broken tool must stop startup, not silently vanish.
        """
        root = importlib.import_module(package)
        for module in pkgutil.iter_modules(root.__path__):
            if module.ispkg and _PACKAGE_NAME_RE.fullmatch(module.name):
                importlib.import_module(f"{package}.{module.name}")

    def __contains__(self, tool_id: object) -> bool:
        return tool_id in self._tools

    def __len__(self) -> int:
        return len(self._tools)


# The process-wide registry used by tool packages and the API.
registry = ToolRegistry()

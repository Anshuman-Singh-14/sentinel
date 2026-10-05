"""File Integrity Monitor (Phase 11, ADR 0015): two tools sharing one scanner."""

from app.engine.registry import registry
from app.tools.fim.tool import FimBaselineTool, FimCheckTool

registry.register(FimBaselineTool)
registry.register(FimCheckTool)

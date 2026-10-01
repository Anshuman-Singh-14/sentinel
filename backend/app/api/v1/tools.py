"""Tool catalogue. Run endpoints arrive in Phase 5 and authentication in Phase 2."""

from fastapi import APIRouter

from app.engine.registry import ToolDescriptor, registry

router = APIRouter(prefix="/tools", tags=["tools"])


@router.get("", response_model=list[ToolDescriptor])
async def list_tools() -> list[ToolDescriptor]:
    return registry.catalogue()

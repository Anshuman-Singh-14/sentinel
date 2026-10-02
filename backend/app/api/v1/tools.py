"""Tool catalogue. Run endpoints arrive in Phase 5.

Reading the catalogue requires any authenticated role (viewer and up).
"""

from fastapi import APIRouter, Depends

from app.core.auth.dependencies import require_viewer
from app.engine.registry import ToolDescriptor, registry

router = APIRouter(prefix="/tools", tags=["tools"], dependencies=[Depends(require_viewer)])


@router.get("", response_model=list[ToolDescriptor])
async def list_tools() -> list[ToolDescriptor]:
    return registry.catalogue()

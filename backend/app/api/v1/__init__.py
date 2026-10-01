"""Version 1 of the public API. Routers stay thin and delegate to services."""

from fastapi import APIRouter

from app.api.v1.tools import router as tools_router

router = APIRouter(prefix="/api/v1")
router.include_router(tools_router)

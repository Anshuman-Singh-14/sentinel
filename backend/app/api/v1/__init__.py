"""Version 1 of the public API. Routers stay thin and delegate to services."""

from fastapi import APIRouter

from app.api.v1.admin import router as admin_router
from app.api.v1.auth import router as auth_router
from app.api.v1.fim import router as fim_router
from app.api.v1.playbooks import router as playbooks_router
from app.api.v1.reports import router as reports_router
from app.api.v1.runs import router as runs_router
from app.api.v1.scope import router as scope_router
from app.api.v1.tools import router as tools_router

router = APIRouter(prefix="/api/v1")
router.include_router(auth_router)
router.include_router(admin_router)
router.include_router(tools_router)
router.include_router(runs_router)
router.include_router(scope_router)
router.include_router(playbooks_router)
router.include_router(reports_router)
router.include_router(fim_router)

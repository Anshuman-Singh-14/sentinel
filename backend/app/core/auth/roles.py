"""RBAC roles (03-logging-audit.md section 1). Enforcement arrives in Phase 2."""

from enum import StrEnum


class Role(StrEnum):
    ADMIN = "admin"  # users, scope policy, provider config, audit viewer
    ANALYST = "analyst"  # run tools and playbooks, export reports
    VIEWER = "viewer"  # read results only

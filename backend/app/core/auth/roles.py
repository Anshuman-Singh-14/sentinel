"""RBAC roles (03-logging-audit.md section 1).

Roles are strictly hierarchical: each role can do everything the roles below
it can. A hierarchy is enough for three roles and keeps every authorization
check a single comparison, which is easy to review and to test exhaustively.
"""

from enum import StrEnum


class Role(StrEnum):
    ADMIN = "admin"  # users, scope policy, provider config, audit viewer
    ANALYST = "analyst"  # run tools and playbooks, export reports
    VIEWER = "viewer"  # read results only


ROLE_RANK: dict[Role, int] = {Role.VIEWER: 1, Role.ANALYST: 2, Role.ADMIN: 3}


def role_allows(actual: Role, required: Role) -> bool:
    return ROLE_RANK[actual] >= ROLE_RANK[required]

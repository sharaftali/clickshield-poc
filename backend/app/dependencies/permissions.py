"""
Role-based access control (spec §62, task 030). The whole matrix lives here.

    OWNER  ⊃  ADMIN  ⊃  MEMBER

Every mutating endpoint depends on `require_permission(...)`; a test walks the
routes and fails if one doesn't (tests/test_rbac_routes.py). Platform staff
(`is_platform_admin`, task 027) is separate from organization roles.
"""
from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, status

from app.dependencies.auth import CurrentUser
from app.models import User, UserRole

ROLE_RANK = {UserRole.MEMBER: 1, UserRole.ADMIN: 2, UserRole.OWNER: 3}

# permission → minimum role
PERMISSIONS: dict[str, UserRole] = {
    # read-only and feedback: everyone in the organization
    "dashboard:view": UserRole.MEMBER,
    "sessions:feedback": UserRole.MEMBER,
    # configuration
    "websites:manage": UserRole.ADMIN,
    "google:manage": UserRole.ADMIN,          # connect, select customer, sync
    "protection:manage": UserRole.ADMIN,      # campaign toggles, protection mode, rule overrides
    "exclusions:manage": UserRole.ADMIN,      # retry / remove exclusions
    "alerts:manage": UserRole.ADMIN,          # acknowledge / resolve
    "settings:manage": UserRole.ADMIN,        # reporting timezone, retention overrides
    # organization ownership
    "users:manage": UserRole.OWNER,           # invite, change roles, deactivate
    "privacy:erase": UserRole.OWNER,          # visitor data erasure (task 029)
    "organization:delete": UserRole.OWNER,
    "billing:manage": UserRole.OWNER,
}


def has_permission(user: User, permission: str) -> bool:
    required = PERMISSIONS[permission]
    return ROLE_RANK.get(user.role, 0) >= ROLE_RANK[required]


def require_permission(permission: str):
    if permission not in PERMISSIONS:
        raise KeyError(f"Unknown permission {permission!r}")

    async def dependency(current_user: CurrentUser) -> User:
        if not has_permission(current_user, permission):
            required = PERMISSIONS[permission].value
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Your role ({current_user.role.value}) can't do this; it needs {required} or higher.",
            )
        return current_user

    dependency.permission = permission  # read by the route audit test
    return dependency


def Permission(permission: str):  # noqa: N802 - reads like a type in signatures
    return Annotated[User, Depends(require_permission(permission))]


async def require_platform_admin(current_user: CurrentUser) -> User:
    if not current_user.is_platform_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Platform administrators only.")
    return current_user


require_platform_admin.permission = "platform:admin"
PlatformAdmin = Annotated[User, Depends(require_platform_admin)]

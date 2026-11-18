"""Backend-enforced Role-Based Access Control policy.

The policy is *default deny*: a permission must be granted explicitly to a role.
Administrators are not special-cased in code; every privilege they hold is
listed in ``ROLE_PERMISSIONS`` so the matrix is auditable and testable.

The corresponding human-readable matrix lives in ``docs/rbac.md``.
"""

from __future__ import annotations

import enum

from core.models.user import UserRole


class Permission(str, enum.Enum):
    """Fine-grained capabilities used by routes and UI affordances."""

    DASHBOARD_VIEW = "dashboard:view"
    AUDIT_VIEW = "audit:view"
    AUDIT_VERIFY = "audit:verify"
    USERS_VIEW = "users:view"
    USERS_MANAGE = "users:manage"
    MODELS_MANAGE = "models:manage"
    SELF_MANAGE = "self:manage"


ROLE_PERMISSIONS: dict[UserRole, frozenset[Permission]] = {
    UserRole.ADMIN: frozenset(
        {
            Permission.DASHBOARD_VIEW,
            Permission.AUDIT_VIEW,
            Permission.AUDIT_VERIFY,
            Permission.USERS_VIEW,
            Permission.USERS_MANAGE,
            Permission.MODELS_MANAGE,
            Permission.SELF_MANAGE,
        }
    ),
    UserRole.ANALYST: frozenset(
        {
            Permission.DASHBOARD_VIEW,
            Permission.AUDIT_VIEW,
            Permission.AUDIT_VERIFY,
            Permission.SELF_MANAGE,
        }
    ),
    UserRole.VIEWER: frozenset(
        {
            Permission.DASHBOARD_VIEW,
            Permission.AUDIT_VIEW,
            Permission.SELF_MANAGE,
        }
    ),
}


def has_permission(role: UserRole | str | None, permission: Permission | str) -> bool:
    """Return True only when the role is explicitly granted the permission."""
    if role is None:
        return False
    try:
        role_enum = role if isinstance(role, UserRole) else UserRole(str(role))
    except ValueError:
        return False
    try:
        perm_enum = (
            permission
            if isinstance(permission, Permission)
            else Permission(str(permission))
        )
    except ValueError:
        return False
    return perm_enum in ROLE_PERMISSIONS.get(role_enum, frozenset())


def permissions_for(role: UserRole | str | None) -> frozenset[Permission]:
    """Return the immutable permission set for a role."""
    if role is None:
        return frozenset()
    try:
        role_enum = role if isinstance(role, UserRole) else UserRole(str(role))
    except ValueError:
        return frozenset()
    return ROLE_PERMISSIONS.get(role_enum, frozenset())

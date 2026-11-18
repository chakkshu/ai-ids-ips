"""Pydantic request validation schemas.

Routes validate form/JSON input through these models instead of binding request
data directly onto ORM entities. ``extra="forbid"`` prevents mass-assignment of
fields such as ``is_active`` or ``must_change_password``.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from core.models.user import UserRole

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class StrictModel(BaseModel):
    """Base model that rejects unknown fields and strips string whitespace."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class UserCreate(StrictModel):
    """Validated payload for provisioning a console user."""

    username: str = Field(min_length=3, max_length=32)
    email: str = Field(min_length=5, max_length=128)
    role: UserRole = UserRole.VIEWER
    password: str = Field(min_length=12, max_length=256)

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        if not USERNAME_PATTERN.fullmatch(value):
            raise ValueError(
                "Username must be 3-32 characters and contain only letters, "
                "numbers, dots, underscores, or hyphens."
            )
        return value

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        if not EMAIL_PATTERN.fullmatch(value):
            raise ValueError("A valid email address is required.")
        return value.lower()


class RoleUpdate(StrictModel):
    """Validated payload for changing a user's security role."""

    role: UserRole


class PasswordChange(StrictModel):
    """Validated payload for a self-service password change."""

    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=12, max_length=256)
    confirm_password: str = Field(min_length=12, max_length=256)

    @field_validator("confirm_password")
    @classmethod
    def passwords_match(cls, value: str, info) -> str:
        new_password = info.data.get("new_password")
        if new_password is not None and value != new_password:
            raise ValueError("New password and confirmation do not match.")
        return value


class RecoveryCodeSubmission(StrictModel):
    """Recovery-code payload accepted by the second-factor challenge."""

    recovery_code: str = Field(min_length=8, max_length=64)

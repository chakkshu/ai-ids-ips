"""User, Role, and Authentication Models.

Implements role-based access control (Admin, Analyst, Viewer), Argon2id hash
storage, password history, encrypted TOTP 2FA secrets, one-time recovery codes,
server-side session tracking, and API tokens.
"""

from __future__ import annotations

import enum
from datetime import UTC, datetime

from flask_login import UserMixin
from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from core.db import Base


class UserRole(str, enum.Enum):
    """Hierarchical Role-Based Access Control definitions."""

    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


def _enum_values(enum_cls: type[enum.Enum]) -> list[str]:
    """Persist enum *values* (lowercase), matching the Alembic schema."""
    return [member.value for member in enum_cls]


class User(Base, UserMixin):
    """User account entity storing credentials, role, 2FA status, and lockout counters."""

    __tablename__ = "users"

    def get_id(self) -> str:
        """Return the user ID string for Flask-Login session management."""
        return str(self.id)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(
        String(64), unique=True, nullable=False, index=True
    )
    email: Mapped[str] = mapped_column(
        String(128), unique=True, nullable=False, index=True
    )
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole, name="user_role_enum", values_callable=_enum_values),
        default=UserRole.VIEWER,
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    must_change_password: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )

    # Two-Factor Authentication (TOTP) - secret is always an AES-256-GCM envelope
    totp_secret: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_totp_enabled: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    totp_last_step: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Account Lockout & Security Counters
    failed_login_attempts: Mapped[int] = mapped_column(
        Integer, default=0, nullable=False
    )
    locked_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_login_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    last_password_change_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        nullable=False,
    )

    # Relationships
    sessions: Mapped[list[UserSession]] = relationship(
        "UserSession", back_populates="user", cascade="all, delete-orphan"
    )
    api_keys: Mapped[list[APIKey]] = relationship(
        "APIKey", back_populates="user", cascade="all, delete-orphan"
    )
    password_history: Mapped[list[PasswordHistory]] = relationship(
        "PasswordHistory",
        back_populates="user",
        cascade="all, delete-orphan",
        order_by="PasswordHistory.created_at.desc()",
    )
    recovery_codes: Mapped[list[RecoveryCode]] = relationship(
        "RecoveryCode", back_populates="user", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return (
            f"<User id={self.id} username='{self.username}' "
            f"role='{self.role.value}' active={self.is_active}>"
        )


class PasswordHistory(Base):
    """Hashed history of previously used passwords, used to block reuse."""

    __tablename__ = "password_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )

    user: Mapped[User] = relationship("User", back_populates="password_history")


class RecoveryCode(Base):
    """One-time, Argon2id-hashed TOTP recovery code."""

    __tablename__ = "recovery_codes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    code_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    used_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)

    user: Mapped[User] = relationship("User", back_populates="recovery_codes")


class UserSession(Base):
    """Server-side session record enabling revocation and timeout enforcement.

    ``session_token`` stores a SHA-256 digest of the random token placed in the
    signed session cookie. A database leak therefore cannot be replayed directly
    against the application.
    """

    __tablename__ = "user_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_token: Mapped[str] = mapped_column(
        String(128), unique=True, nullable=False, index=True
    )
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    is_revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    revoke_reason: Mapped[str | None] = mapped_column(String(64), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    last_activity_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )

    user: Mapped[User] = relationship("User", back_populates="sessions")


class APIKey(Base):
    """Scoped API key allowing programmatic integration (SIEM, automation agents)."""

    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    key_prefix: Mapped[str] = mapped_column(
        String(16), nullable=False, index=True
    )  # Public identifier
    key_hash: Mapped[str] = mapped_column(
        String(128), unique=True, nullable=False
    )  # Argon2 / SHA-256 hash
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    scopes: Mapped[str] = mapped_column(
        String(255), default="read", nullable=False
    )  # Comma-separated: read, write, admin
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    user: Mapped[User] = relationship("User", back_populates="api_keys")

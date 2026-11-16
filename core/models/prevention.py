"""Prevention Models.

Stores active and historical firewall blocking rules, automated escalation levels,
manual approvals, and protected CIDR allowlists.
"""

from __future__ import annotations

import enum
from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from core.db import Base


class BlockStatus(str, enum.Enum):
    """Lifecycle state of an IP containment block."""
    PENDING_APPROVAL = "pending_approval"
    ACTIVE = "active"
    EXPIRED = "expired"
    RELEASED = "released"


class BlockedIP(Base):
    """Enforced or simulated firewall block rule against a malicious IP."""

    __tablename__ = "blocked_ips"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    reason: Mapped[str] = mapped_column(String(255), nullable=False)
    
    status: Mapped[BlockStatus] = mapped_column(
        Enum(BlockStatus, name="block_status_enum"),
        default=BlockStatus.ACTIVE,
        nullable=False,
        index=True,
    )
    
    # Escalation & Expiration Tracking
    escalation_level: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    blocked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    
    # Execution Metadata
    is_dry_run: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    firewall_rule_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    
    # Approval / Release Workflow
    created_by_user_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    approved_by_user_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    released_by_user_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    release_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)

    __table_args__ = (
        Index("ix_blocks_ip_status", "ip_address", "status"),
        Index("ix_blocks_status_expires", "status", "expires_at"),
    )

    def __repr__(self) -> str:
        return f"<BlockedIP id={self.id} ip='{self.ip_address}' status='{self.status.value}' dry_run={self.is_dry_run}>"


class Whitelist(Base):
    """Protected IP or CIDR network range immune to automated prevention blocking."""

    __tablename__ = "whitelist"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    cidr: Mapped[str] = mapped_column(String(45), unique=True, nullable=False, index=True)
    description: Mapped[str] = mapped_column(String(255), nullable=False)
    is_immutable: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)  # True for server IP, gateway, loopback
    
    created_by_user_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<Whitelist id={self.id} cidr='{self.cidr}' immutable={self.is_immutable}>"

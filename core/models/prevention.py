"""Prevention Models.

Stores active and historical firewall blocking rules, automated escalation levels,
manual approvals, and protected CIDR allowlists.
"""

from __future__ import annotations

import enum
from datetime import UTC, datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from core.db import Base


class BlockStatus(str, enum.Enum):
    """Lifecycle state of an IP containment block."""

    PENDING_APPROVAL = "pending_approval"
    ACTIVE = "active"
    EXPIRED = "expired"
    RELEASED = "released"


class PreventionActionType(str, enum.Enum):
    """Firewall operations recorded for every attempted enforcement."""

    BLOCK = "block"
    UNBLOCK = "unblock"
    EXTEND = "extend"
    RECONCILE = "reconcile"


class DecisionAction(str, enum.Enum):
    """Outcome of a policy evaluation."""

    BLOCK = "block"
    PENDING_APPROVAL = "pending_approval"
    ALERT_ONLY = "alert_only"
    NO_ACTION = "no_action"


def _enum_values(enum_cls: type[enum.Enum]) -> list[str]:
    """Persist enum values (lowercase), matching the Alembic schema."""
    return [member.value for member in enum_cls]


class BlockedIP(Base):
    """Enforced or simulated firewall block rule against a malicious IP."""

    __tablename__ = "blocked_ips"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    reason: Mapped[str] = mapped_column(String(255), nullable=False)

    status: Mapped[BlockStatus] = mapped_column(
        Enum(
            BlockStatus,
            name="block_status_enum",
            values_callable=_enum_values,
        ),
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
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )

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
    released_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
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
    cidr: Mapped[str] = mapped_column(
        String(45), unique=True, nullable=False, index=True
    )
    description: Mapped[str] = mapped_column(String(255), nullable=False)
    is_immutable: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )  # True for server IP, gateway, loopback

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
        return (
            f"<Whitelist id={self.id} cidr='{self.cidr}' immutable={self.is_immutable}>"
        )


class PreventionCandidate(Base):
    """A persisted Phase 5 candidate event used for repeat-count windows."""

    __tablename__ = "prevention_candidates"

    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"),
        primary_key=True,
        autoincrement=True,
    )
    event_id: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    candidate_id: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    detection_event_id: Mapped[str] = mapped_column(String(128), nullable=False)
    detection_id: Mapped[int | None] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"), nullable=True, index=True
    )
    flow_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    src_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    dst_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    dst_port: Mapped[int] = mapped_column(Integer, nullable=False)
    model_version: Mapped[str] = mapped_column(String(32), nullable=False)
    predicted_label: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    verdict: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    rare_class_flag: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    simulation: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    source_label: Mapped[str | None] = mapped_column(String(64), nullable=True)
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
        index=True,
    )
    processed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    __table_args__ = (
        Index("ix_prevention_candidates_ip_time", "src_ip", "observed_at"),
        Index("ix_prevention_candidates_label_time", "predicted_label", "observed_at"),
    )

    def __repr__(self) -> str:
        return f"<PreventionCandidate id={self.id} src='{self.src_ip}' label='{self.predicted_label}'>"


class PreventionDecision(Base):
    """Every policy decision, including no-action decisions and their reasons."""

    __tablename__ = "prevention_decisions"

    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"),
        primary_key=True,
        autoincrement=True,
    )
    candidate_id: Mapped[str | None] = mapped_column(
        String(128), nullable=True, index=True
    )
    src_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    predicted_label: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    reason: Mapped[str] = mapped_column(String(500), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    block_duration_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    requires_approval: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    kill_switch_active: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    repeat_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    escalation_level: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    details_json: Mapped[str] = mapped_column(Text, default="{}", nullable=False)
    block_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("blocked_ips.id", ondelete="SET NULL"), nullable=True
    )
    actor_user_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
        index=True,
    )

    __table_args__ = (
        Index("ix_prevention_decisions_ip_time", "src_ip", "created_at"),
        Index("ix_prevention_decisions_action_time", "action", "created_at"),
    )

    def __repr__(self) -> str:
        return f"<PreventionDecision id={self.id} action='{self.action}' src='{self.src_ip}'>"


class PreventionAction(Base):
    """One attempted firewall operation and its exact command preview/result."""

    __tablename__ = "prevention_actions"

    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"),
        primary_key=True,
        autoincrement=True,
    )
    block_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("blocked_ips.id", ondelete="SET NULL"), nullable=True
    )
    decision_id: Mapped[int | None] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"),
        ForeignKey("prevention_decisions.id", ondelete="SET NULL"),
        nullable=True,
    )
    action: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    rule_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    dry_run: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    command_preview: Mapped[str | None] = mapped_column(Text, nullable=True)
    result: Mapped[str] = mapped_column(String(32), nullable=False)
    error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    attempted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
        index=True,
    )
    actor_user_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    correlation_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        Index("ix_prevention_actions_ip_time", "ip_address", "attempted_at"),
    )

    def __repr__(self) -> str:
        return f"<PreventionAction id={self.id} action='{self.action}' result='{self.result}'>"


class PolicyConfig(Base):
    """Versioned, runtime-editable prevention policy configuration."""

    __tablename__ = "policy_configs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    version: Mapped[str] = mapped_column(
        String(32), default="phase6-default", nullable=False
    )
    config_json: Mapped[str] = mapped_column(Text, default="{}", nullable=False)
    updated_by_user_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
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

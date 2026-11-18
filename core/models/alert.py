"""Alert Management Model.

Supports alert severity tiers, deduplication keys to prevent alert storms,
analyst assignment, resolution workflows, and SIEM forwarding status.
"""

from __future__ import annotations

import enum
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from core.db import Base

if TYPE_CHECKING:
    from core.models.detection import Detection
    from core.models.user import User


class AlertSeverity(str, enum.Enum):
    """Normalized security alert severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(str, enum.Enum):
    """Incident response workflow states."""

    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


def _enum_values(enum_cls: type[enum.Enum]) -> list[str]:
    """Persist enum values (lowercase), matching the Alembic schema."""
    return [member.value for member in enum_cls]


class Alert(Base):
    """Security alert generated from high-confidence malicious detections."""

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"),
        primary_key=True,
        autoincrement=True,
    )
    detection_id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"),
        ForeignKey("detections.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Deduplication key = sha256(src_ip + attack_type + 5_min_bucket)
    dedup_key: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    title: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    severity: Mapped[AlertSeverity] = mapped_column(
        Enum(
            AlertSeverity,
            name="alert_severity_enum",
            values_callable=_enum_values,
        ),
        default=AlertSeverity.MEDIUM,
        nullable=False,
        index=True,
    )
    status: Mapped[AlertStatus] = mapped_column(
        Enum(
            AlertStatus,
            name="alert_status_enum",
            values_callable=_enum_values,
        ),
        default=AlertStatus.NEW,
        nullable=False,
        index=True,
    )

    # Source / Target Details for Fast SOC Querying
    src_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    dst_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    dst_port: Mapped[int] = mapped_column(Integer, nullable=False)
    attack_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    # Workflow Assignment
    assigned_user_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    assigned_username: Mapped[str | None] = mapped_column(String(64), nullable=True)
    resolution_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # External Notification Tracking
    email_dispatched: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    webhook_dispatched: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
        index=True,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        nullable=False,
    )

    # Relationships
    detection: Mapped[Detection] = relationship("Detection", back_populates="alerts")  # type: ignore
    assigned_user: Mapped[User | None] = relationship("User")  # type: ignore

    __table_args__ = (
        Index("ix_alerts_status_sev_time", "status", "severity", "created_at"),
        Index("ix_alerts_src_time", "src_ip", "created_at"),
    )

    def __repr__(self) -> str:
        return f"<Alert id={self.id} severity='{self.severity.value}' status='{self.status.value}' src='{self.src_ip}'>"

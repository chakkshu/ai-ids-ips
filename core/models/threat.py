"""Threat-intelligence persistence models."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from core.db import Base


class IPProfile(Base):
    """Rolling intelligence profile for an observed source address."""

    __tablename__ = "ip_profiles"

    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"),
        primary_key=True,
        autoincrement=True,
    )
    ip_address: Mapped[str] = mapped_column(
        String(45), nullable=False, unique=True, index=True
    )
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
        index=True,
    )
    detection_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    attack_types_json: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    max_severity: Mapped[str] = mapped_column(
        String(16), default="low", nullable=False, index=True
    )
    reverse_dns: Mapped[str | None] = mapped_column(String(255), nullable=True)
    enrichment_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_enriched_at: Mapped[datetime | None] = mapped_column(
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

    __table_args__ = (
        Index("ix_ip_profiles_severity_seen", "max_severity", "last_seen"),
    )

    def __repr__(self) -> str:
        return f"<IPProfile id={self.id} ip='{self.ip_address}' detections={self.detection_count}>"


class ThreatBlocklistEntry(Base):
    """Validated external indicator imported into the local blocklist."""

    __tablename__ = "threat_blocklist_entries"

    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"),
        primary_key=True,
        autoincrement=True,
    )
    ip_address: Mapped[str] = mapped_column(
        String(45), nullable=False, unique=True, index=True
    )
    source: Mapped[str] = mapped_column(String(64), nullable=False, default="import")
    reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )

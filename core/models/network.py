"""Network Flow Model.

Represents bidirectional network flows assembled by the sensor service.
Structured to support PostgreSQL monthly range-partitioning and AES-256-GCM envelope
encryption for raw packet payloads.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import BigInteger, DateTime, Float, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from core.db import Base

if TYPE_CHECKING:
    from core.models.detection import Detection


class NetworkFlow(Base):
    """Bidirectional aggregated network flow entity."""

    __tablename__ = "network_flows"

    # Primary key supports SQLite tests and PostgreSQL 64-bit BigInt
    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"),
        primary_key=True,
        autoincrement=True,
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
        index=True,
    )

    flow_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    src_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    src_port: Mapped[int] = mapped_column(Integer, nullable=False)
    dst_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    dst_port: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    protocol: Mapped[str] = mapped_column(String(16), nullable=False)  # TCP, UDP, ICMP

    # Statistical Flow Summaries
    duration: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    total_fwd_packets: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_bwd_packets: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_fwd_bytes: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    total_bwd_bytes: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    flow_bytes_per_sec: Mapped[float] = mapped_column(
        Float, default=0.0, nullable=False
    )
    flow_packets_per_sec: Mapped[float] = mapped_column(
        Float, default=0.0, nullable=False
    )

    # Complete 80+ CICFlowMeter feature map (stored as JSON text)
    features_json: Mapped[str] = mapped_column(Text, nullable=False)

    # Envelope Encrypted Raw Snippet (AES-256-GCM)
    encrypted_payload: Mapped[str | None] = mapped_column(Text, nullable=True)
    encrypted_dek: Mapped[str | None] = mapped_column(String(255), nullable=True)
    nonce: Mapped[str | None] = mapped_column(String(64), nullable=True)
    auth_tag: Mapped[str | None] = mapped_column(String(64), nullable=True)
    key_version: Mapped[str | None] = mapped_column(String(16), nullable=True)

    # Relationships
    detection: Mapped[Detection | None] = relationship(  # type: ignore
        "Detection",
        back_populates="flow",
        uselist=False,
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        Index("ix_flows_src_dst_proto", "src_ip", "dst_ip", "protocol"),
        Index("ix_flows_dst_port_time", "dst_port", "timestamp"),
    )

    def __repr__(self) -> str:
        return f"<NetworkFlow id={self.id} {self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port} proto={self.protocol}>"

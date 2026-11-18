"""Tamper-Evident Hash-Chained Audit Log Model.

Every administrative, security, and state-altering event is recorded with an
HMAC-SHA256 hash chained to the preceding entry, forming a tamper-evident
ledger.

Two canonical formats are supported:

* ``hash_version == 1`` - the original Phase 2 format (no actor/IP/correlation).
* ``hash_version == 2`` - binds username, IP address, and correlation ID into
  the authenticated chain in addition to the original fields.

Existing rows keep their original version so historical chains remain valid.
"""

from __future__ import annotations

import hashlib
import hmac
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from core.db import Base

if TYPE_CHECKING:
    from core.models.user import User

GENESIS_HASH = "0" * 64
CURRENT_HASH_VERSION = 2


class AuditLog(Base):
    """Tamper-evident audit ledger entry with HMAC-SHA256 hash chaining."""

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
        index=True,
    )
    user_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    username: Mapped[str] = mapped_column(String(64), default="system", nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    resource_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    resource_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    status: Mapped[str] = mapped_column(
        String(16), default="SUCCESS", nullable=False
    )  # SUCCESS, FAILURE, DENIED, BLOCKED, LOCKED
    details: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )  # JSON-encoded payload
    correlation_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Tamper-Evident Hash-Chaining Fields
    previous_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    hash_version: Mapped[int] = mapped_column(
        Integer, default=CURRENT_HASH_VERSION, nullable=False
    )

    # Relationships
    user: Mapped[User | None] = relationship("User")  # type: ignore

    @classmethod
    def format_canonical_timestamp(cls, dt: datetime | str) -> str:
        """Format datetime into standard deterministic ISO timestamp for hashing."""
        if isinstance(dt, str):
            try:
                parsed = datetime.fromisoformat(dt)
            except ValueError:
                return dt
            dt = parsed
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    @classmethod
    def compute_hash(
        cls,
        hmac_key: str,
        prev_hash: str,
        timestamp: datetime | str,
        user_id: int | None,
        action: str,
        resource_type: str,
        resource_id: str | None,
        status: str,
        details_json: str | None,
        username: str = "system",
        ip_address: str | None = None,
        correlation_id: str | None = None,
        hash_version: int = CURRENT_HASH_VERSION,
    ) -> str:
        """Compute HMAC-SHA256 entry hash chained with ``previous_hash``."""
        timestamp_str = cls.format_canonical_timestamp(timestamp)
        details_digest = hashlib.sha256(
            (details_json or "").encode("utf-8")
        ).hexdigest()

        canonical_string = (
            f"{prev_hash}|"
            f"{timestamp_str}|"
            f"{user_id or 'none'}|"
            f"{action.upper()}|"
            f"{resource_type.upper()}|"
            f"{resource_id or 'none'}|"
            f"{status.upper()}|"
            f"{details_digest}"
        )

        if hash_version >= 2:
            canonical_string += (
                f"|v2|{username}|{ip_address or 'none'}|{correlation_id or 'none'}"
            )

        return hmac.new(
            hmac_key.encode("utf-8"),
            canonical_string.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    @classmethod
    def create_entry(
        cls,
        hmac_key: str,
        prev_hash: str,
        user_id: int | None,
        username: str,
        action: str,
        resource_type: str,
        resource_id: str | None = None,
        status: str = "SUCCESS",
        details: str | None = None,
        ip_address: str | None = None,
        correlation_id: str | None = None,
        timestamp: datetime | None = None,
        hash_version: int = CURRENT_HASH_VERSION,
    ) -> AuditLog:
        """Helper to create an audit log entry with synchronous timestamp and hash."""
        ts = timestamp or datetime.now(UTC)
        entry_hash = cls.compute_hash(
            hmac_key=hmac_key,
            prev_hash=prev_hash,
            timestamp=ts,
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            status=status,
            details_json=details,
            username=username,
            ip_address=ip_address,
            correlation_id=correlation_id,
            hash_version=hash_version,
        )
        return cls(
            timestamp=ts,
            user_id=user_id,
            username=username,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            ip_address=ip_address,
            status=status,
            details=details,
            correlation_id=correlation_id,
            previous_hash=prev_hash,
            entry_hash=entry_hash,
            hash_version=hash_version,
        )

    @classmethod
    def verify_chain(cls, hmac_key: str, entries: list[AuditLog]) -> list[int]:
        """Return IDs of the first invalid entry for each broken segment.

        The chain is verified in ascending ID order. A single broken link stops
        verification because every subsequent hash depends on it.
        """
        expected_prev_hash = GENESIS_HASH
        for entry in entries:
            if entry.previous_hash != expected_prev_hash:
                return [entry.id]
            recomputed = cls.compute_hash(
                hmac_key=hmac_key,
                prev_hash=entry.previous_hash,
                timestamp=entry.timestamp,
                user_id=entry.user_id,
                action=entry.action,
                resource_type=entry.resource_type,
                resource_id=entry.resource_id,
                status=entry.status,
                details_json=entry.details,
                username=entry.username,
                ip_address=entry.ip_address,
                correlation_id=entry.correlation_id,
                hash_version=entry.hash_version,
            )
            if recomputed != entry.entry_hash:
                return [entry.id]
            expected_prev_hash = entry.entry_hash
        return []

    def __repr__(self) -> str:
        return (
            f"<AuditLog id={self.id} action='{self.action}' "
            f"user='{self.username}' status='{self.status}'>"
        )

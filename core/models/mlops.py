"""MLOps Governance & Quality Tracking Models.

Manages model artifact versioning, staging/promotion states, drift monitoring metrics,
and analyst ground-truth feedback for continual retraining.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from core.db import Base


class ModelArtifact(Base):
    """Registered machine learning model version, feature signature, and validation metrics."""

    __tablename__ = "model_artifacts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    version: Mapped[str] = mapped_column(
        String(32), unique=True, nullable=False, index=True
    )
    algorithm: Mapped[str] = mapped_column(
        String(64), default="RandomForestClassifier", nullable=False
    )

    # Serialized file references
    model_path: Mapped[str] = mapped_column(String(255), nullable=False)
    scaler_path: Mapped[str] = mapped_column(String(255), nullable=False)
    encoder_path: Mapped[str] = mapped_column(String(255), nullable=False)
    isolation_forest_path: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    drift_baseline_path: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Feature contract & metadata
    features_list_json: Mapped[str] = mapped_column(
        Text, nullable=False
    )  # Ordered feature names
    metrics_json: Mapped[str] = mapped_column(
        Text, nullable=False
    )  # Accuracy, F1, Precision, Recall
    dataset_hash: Mapped[str] = mapped_column(
        String(64), nullable=False
    )  # SHA-256 of training set
    git_commit: Mapped[str | None] = mapped_column(String(40), nullable=True)
    checksums_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    training_config_json: Mapped[str] = mapped_column(
        Text, nullable=False, default="{}"
    )

    # Governance states
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="staged", index=True
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False, index=True
    )
    is_staged: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    activated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    promoted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    def __repr__(self) -> str:
        return f"<ModelArtifact version='{self.version}' active={self.is_active} staged={self.is_staged}>"


class DriftMetric(Base):
    """Feature and prediction distribution drift assessment records."""

    __tablename__ = "drift_metrics"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    model_version: Mapped[str] = mapped_column(String(32), nullable=False, index=True)

    psi_score: Mapped[float] = mapped_column(
        Float, nullable=False
    )  # Population Stability Index
    ks_statistic: Mapped[float] = mapped_column(
        Float, nullable=False
    )  # Kolmogorov-Smirnov test stat
    ks_p_value: Mapped[float] = mapped_column(Float, nullable=False)

    drift_detected: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False, index=True
    )
    drifted_features_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    sample_size: Mapped[int] = mapped_column(Integer, nullable=False)

    evaluated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
        index=True,
    )

    def __repr__(self) -> str:
        return f"<DriftMetric id={self.id} version='{self.model_version}' psi={self.psi_score:.3f} drift={self.drift_detected}>"


class AnalystFeedback(Base):
    """Ground-truth validation submitted by SOC analysts to correct or verify model detections."""

    __tablename__ = "analyst_feedback"

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
    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    is_false_positive: Mapped[bool] = mapped_column(Boolean, nullable=False)
    verified_label: Mapped[str] = mapped_column(String(64), nullable=False)
    analyst_notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    used_in_retraining: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<AnalystFeedback id={self.id} detection={self.detection_id} fp={self.is_false_positive}>"

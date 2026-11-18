"""Authorised service layer for model-registry lifecycle changes."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from core.models.mlops import ModelArtifact
from core.models.user import User
from core.rbac import Permission, has_permission
from core.security import audit_details, log_security_event
from ml.registry import store
from ml.registry.paths import validate_version


def require_model_manager(actor_user_id: int, db_session: Session) -> User:
    """Reject any actor without the explicit ``models:manage`` permission."""

    actor = db_session.query(User).filter_by(id=actor_user_id).one_or_none()
    if actor is None or not has_permission(actor.role, Permission.MODELS_MANAGE):
        raise PermissionError(
            "model lifecycle changes require the models:manage permission"
        )
    return actor


def record_staged_version(
    version: str,
    checksums: dict[str, str],
    metadata: dict[str, Any],
    db_session: Session,
    *,
    actor_user_id: int | None = None,
) -> ModelArtifact:
    """Record an already disk-staged version as a non-active registry row.

    Training stages and seals artifacts once in ``store.stage_version``; this
    function only creates the registry row and audit event, so it must not copy
    or move artifacts again.
    """

    safe_version = validate_version(version)
    prefix = f"staging/{safe_version}/"
    artifact = ModelArtifact(
        version=safe_version,
        algorithm=str(metadata.get("algorithm", "RandomForestClassifier")),
        model_path=prefix + "model.joblib",
        scaler_path=prefix + "scaler.joblib",
        encoder_path=prefix + "encoder.joblib",
        isolation_forest_path=prefix + "isolation_forest.joblib",
        drift_baseline_path=prefix + "baseline.json",
        features_list_json=json.dumps(metadata.get("feature_names", [])),
        metrics_json=json.dumps(metadata.get("metrics", {})),
        dataset_hash=str(metadata.get("dataset_hash", "")),
        git_commit=metadata.get("git_commit"),
        checksums_json=json.dumps(checksums, sort_keys=True),
        training_config_json=json.dumps(
            metadata.get("training_config", {}), sort_keys=True
        ),
        status="staged",
        is_staged=True,
        is_active=False,
    )
    db_session.add(artifact)
    db_session.flush()

    actor = (
        db_session.query(User).filter_by(id=actor_user_id).one_or_none()
        if actor_user_id is not None
        else None
    )
    log_security_event(
        action="MODEL_STAGED",
        resource_type="MODEL",
        resource_id=safe_version,
        user_id=actor.id if actor else None,
        username=actor.username if actor else "system",
        details=audit_details(version=safe_version, dataset_hash=artifact.dataset_hash),
        db_session=db_session,
    )
    return artifact


def register_staged_version(
    version: str,
    artifact_sources: dict[str, Path],
    metadata: dict[str, Any],
    db_session: Session,
    *,
    root: Path | str | None = None,
    actor_user_id: int | None = None,
) -> ModelArtifact:
    """Stage artifacts on disk and record a non-active registry row."""

    safe_version = validate_version(version)
    checksums = store.stage_version(safe_version, artifact_sources, metadata, root)
    return record_staged_version(
        safe_version,
        checksums,
        metadata,
        db_session,
        actor_user_id=actor_user_id,
    )


def _rewrite_paths(artifact: ModelArtifact, area: str) -> None:
    prefix = f"{area}/{artifact.version}/"
    for field_name in (
        "model_path",
        "scaler_path",
        "encoder_path",
        "isolation_forest_path",
        "drift_baseline_path",
    ):
        value = getattr(artifact, field_name)
        if isinstance(value, str) and "/" in value:
            setattr(artifact, field_name, prefix + value.rsplit("/", 1)[-1])


def promote_version(
    version: str,
    actor_user_id: int,
    db_session: Session,
    *,
    root: Path | str | None = None,
) -> ModelArtifact:
    """Explicitly promote a staged version. Never called automatically."""

    actor = require_model_manager(actor_user_id, db_session)
    safe_version = validate_version(version)
    previous, promoted = store.promote_version(safe_version, root)
    now = datetime.now(UTC)
    for other in (
        db_session.query(ModelArtifact).filter(ModelArtifact.is_active.is_(True)).all()
    ):
        other.is_active = False
        other.status = "archived"
    artifact = db_session.query(ModelArtifact).filter_by(version=promoted).one_or_none()
    if artifact is None:
        raise RuntimeError(f"registry row missing for staged version {promoted}")
    artifact.is_active = True
    artifact.is_staged = False
    artifact.status = "active"
    artifact.activated_at = now
    artifact.promoted_at = now
    _rewrite_paths(artifact, "active")
    db_session.flush()

    log_security_event(
        action="MODEL_PROMOTED",
        resource_type="MODEL",
        resource_id=promoted,
        user_id=actor.id,
        username=actor.username,
        details=audit_details(version=promoted, previous_active=previous),
        db_session=db_session,
    )
    return artifact


def rollback_version(
    actor_user_id: int,
    db_session: Session,
    *,
    target_version: str | None = None,
    root: Path | str | None = None,
) -> ModelArtifact:
    """Restore an archived version to active, with an audited actor."""

    actor = require_model_manager(actor_user_id, db_session)
    previous, restored = store.rollback_version(root, target_version)
    now = datetime.now(UTC)
    for other in (
        db_session.query(ModelArtifact).filter(ModelArtifact.is_active.is_(True)).all()
    ):
        other.is_active = False
        other.status = "archived"
    artifact = db_session.query(ModelArtifact).filter_by(version=restored).one_or_none()
    if artifact is None:
        raise RuntimeError(f"registry row missing for archived version {restored}")
    artifact.is_active = True
    artifact.is_staged = False
    artifact.status = "active"
    artifact.activated_at = now
    artifact.promoted_at = now
    _rewrite_paths(artifact, "active")
    db_session.flush()

    log_security_event(
        action="MODEL_ROLLED_BACK",
        resource_type="MODEL",
        resource_id=restored,
        user_id=actor.id,
        username=actor.username,
        details=audit_details(version=restored, previous_active=previous),
        db_session=db_session,
    )
    return artifact


def list_artifacts(db_session: Session) -> list[ModelArtifact]:
    """Return all registry rows ordered newest first."""

    return (
        db_session.query(ModelArtifact)
        .order_by(ModelArtifact.created_at.desc(), ModelArtifact.id.desc())
        .all()
    )

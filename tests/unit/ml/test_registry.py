"""Registry path safety, checksum enforcement, RBAC, and audit tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import joblib
import pytest
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler

from core.config import settings
from core.models.audit import AuditLog
from core.models.mlops import ModelArtifact
from core.models.user import UserRole
from ml.registry import service, store
from ml.registry.errors import ChecksumError, RegistryError
from ml.registry.paths import (
    RegistryPathError,
    artifact_path,
    validate_filename,
    validate_version,
)
from ml.schema import MODEL_FEATURES


def _create_fake_work(work_dir: Path) -> dict[str, Path]:
    work_dir.mkdir(parents=True, exist_ok=True)
    X = [[0.0] * len(MODEL_FEATURES), [1.0] * len(MODEL_FEATURES)]
    y = ["BENIGN", "DDoS"]
    model = RandomForestClassifier(n_estimators=2, random_state=1).fit(X, [0, 1])
    scaler = StandardScaler().fit(X)
    encoder = LabelEncoder().fit(y)
    isolation = {"model": IsolationForest(random_state=1).fit(X), "threshold": 0.5}
    joblib.dump(model, work_dir / "model.joblib")
    joblib.dump(scaler, work_dir / "scaler.joblib")
    joblib.dump(encoder, work_dir / "encoder.joblib")
    joblib.dump(isolation, work_dir / "isolation_forest.joblib")
    payloads: dict[str, Any] = {
        "features.json": {
            "features": list(MODEL_FEATURES),
            "impute_values": [0.0] * len(MODEL_FEATURES),
        },
        "config.json": {
            "confidence_threshold": 0.7,
            "anomaly_threshold": 0.6,
            "seed": 1,
        },
        "baseline.json": {
            "feature_names": list(MODEL_FEATURES),
            "features": {},
            "prediction_distribution": {"BENIGN": 1, "DDoS": 1},
            "confidence_ks_reference": [0.6, 0.9],
        },
        "metrics.json": {"split": "test", "accuracy": 1.0, "sample_count": 2},
    }
    for name, payload in payloads.items():
        (work_dir / name).write_text(json.dumps(payload), encoding="utf-8")
    return {
        name: work_dir / name
        for name in list(payloads)
        + [
            "model.joblib",
            "scaler.joblib",
            "encoder.joblib",
            "isolation_forest.joblib",
        ]
    }


def _stage_fake_version(version: str, root: Path, work_dir: Path) -> dict[str, str]:
    sources = _create_fake_work(work_dir)
    return store.stage_version(
        version,
        sources,
        {
            "algorithm": "RandomForestClassifier",
            "feature_names": list(MODEL_FEATURES),
            "metrics": {"accuracy": 1.0},
            "dataset_hash": "0" * 64,
            "training_config": {"seed": 1},
        },
        root,
    )


def _register(
    version: str, root: Path, db_session: Any, work_dir: Path
) -> ModelArtifact:
    # The work directory still contains the original files; the service stages
    # them itself, so the test exercises the real service path.
    sources = {name: work_dir / name for name in store.REQUIRED_ARTIFACTS}
    return service.register_staged_version(
        version,
        sources,
        {
            "algorithm": "RandomForestClassifier",
            "feature_names": list(MODEL_FEATURES),
            "metrics": {"accuracy": 1.0},
            "dataset_hash": "0" * 64,
            "git_commit": None,
            "training_config": {"seed": 1},
        },
        db_session,
        root=root,
        actor_user_id=None,
    )


def test_path_traversal_and_invalid_names_rejected(tmp_path: Path) -> None:
    with pytest.raises(RegistryPathError):
        validate_version("../escape")
    with pytest.raises(RegistryPathError):
        validate_version("..")
    with pytest.raises(RegistryPathError):
        validate_filename("../../secret.joblib")
    with pytest.raises(RegistryPathError):
        artifact_path("v1", "a/b.joblib", tmp_path)


def test_tampered_artifact_refuses_verification(tmp_path: Path) -> None:
    root = tmp_path / "registry"
    _stage_fake_version("v1.0", root, tmp_path / "work")
    assert store.verify_artifacts("v1.0", root, area="staging")["model.joblib"]

    target = store.version_directory("v1.0", root, area="staging") / "model.joblib"
    target.write_bytes(b"tampered pickle")
    with pytest.raises(ChecksumError):
        store.verify_artifacts("v1.0", root, area="staging")


def test_staged_version_is_not_active(tmp_path: Path) -> None:
    root = tmp_path / "registry"
    _stage_fake_version("staged-only", root, tmp_path / "work")
    assert store.active_version(root) is None
    assert (root / "staging" / "staged-only").is_dir()
    assert not (root / "active" / "staged-only").exists()


def test_promote_rollback_audit_and_rbac(
    tmp_path: Path, db_session: Any, make_user: Any
) -> None:
    root = tmp_path / "registry"
    admin_id = make_user(username="ml-admin", role=UserRole.ADMIN)
    analyst_id = make_user(username="ml-analyst", role=UserRole.ANALYST)

    _create_fake_work(tmp_path / "work1")
    _register("v1.0", root, db_session, tmp_path / "work1")
    db_session.commit()
    assert store.active_version(root) is None
    assert (
        db_session.query(ModelArtifact).filter_by(version="v1.0").one().status
        == "staged"
    )

    with pytest.raises(PermissionError):
        service.promote_version("v1.0", analyst_id, db_session, root=root)
    assert store.active_version(root) is None

    promoted = service.promote_version("v1.0", admin_id, db_session, root=root)
    assert promoted.status == "active"
    assert store.active_version(root) == "v1.0"
    assert (root / "metadata.json").exists() is False
    assert (root / "active" / "v1.0" / "metadata.json").is_file()

    _create_fake_work(tmp_path / "work2")
    _register("v2.0", root, db_session, tmp_path / "work2")
    service.promote_version("v2.0", admin_id, db_session, root=root)
    assert store.active_version(root) == "v2.0"
    assert (root / "archive" / "v1.0").is_dir()
    assert (root / "active" / "v2.0").is_dir()

    rolled = service.rollback_version(admin_id, db_session, root=root)
    assert rolled.version == "v1.0"
    assert store.active_version(root) == "v1.0"

    db_session.commit()
    actions = [
        entry.action
        for entry in db_session.query(AuditLog).order_by(AuditLog.id.asc()).all()
    ]
    assert "MODEL_PROMOTED" in actions
    assert "MODEL_ROLLED_BACK" in actions
    logs = db_session.query(AuditLog).order_by(AuditLog.id.asc()).all()
    assert AuditLog.verify_chain(settings.AUDIT_HMAC_SECRET, logs) == []


def test_registry_error_types() -> None:
    assert issubclass(ChecksumError, RegistryError)

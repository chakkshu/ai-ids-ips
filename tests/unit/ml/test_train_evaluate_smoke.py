"""End-to-end smoke and leakage invariant tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ml import evaluate, preprocess
from ml.schema import MODEL_FEATURES
from ml.train_model import TrainingConfig, smoke_test, train_pipeline

FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "ml"


def test_smoke_test_stages_artifacts_and_evaluates(tmp_path: Any) -> None:
    work = tmp_path / "work"
    root = tmp_path / "registry"
    result = smoke_test(root, work, n_iter=2, cv_folds=2)

    assert result.metrics["sample_count"] > 0
    assert not (root / "active.json").exists()
    assert result.staging_dir == root / "staging" / result.version
    for name in (
        "model.joblib",
        "scaler.joblib",
        "encoder.joblib",
        "isolation_forest.joblib",
        "features.json",
        "config.json",
        "baseline.json",
        "metrics.json",
        "checksums.json",
    ):
        assert (result.staging_dir / name).is_file()

    contract = json.loads(
        (result.staging_dir / "features.json").read_text(encoding="utf-8")
    )
    assert contract["features"] == list(MODEL_FEATURES)
    config = json.loads(
        (result.staging_dir / "config.json").read_text(encoding="utf-8")
    )
    assert config["smoke_test"] is True
    assert config["resampling_detail"]["strategy"] == "none"

    production_models = Path(__file__).resolve().parents[2].parent / "ml" / "models"
    assert not list(production_models.glob("*.joblib"))

    assert (
        evaluate.main(
            [
                "--processed-dir",
                str(work / "processed"),
                "--artifact-dir",
                str(result.staging_dir),
                "--output-dir",
                str(tmp_path / "evaluation"),
            ]
        )
        == 0
    )
    evaluation = tmp_path / "evaluation"
    metrics = json.loads((evaluation / "metrics.json").read_text(encoding="utf-8"))
    assert metrics["split"] == "test"
    for plot in (
        "confusion_matrix.png",
        "confusion_matrix_normalized.png",
        "roc_curves.png",
        "precision_recall_curves.png",
    ):
        assert (evaluation / plot).is_file()
    # The sealed artifact tree must remain byte-identical.
    from ml.registry import store

    store.verify_artifacts(result.version, root, area="staging")


def test_smote_resamples_training_split_only(tmp_path: Path) -> None:
    processed = tmp_path / "processed"
    preprocess.main(
        [
            "--input-dir",
            str(FIXTURE),
            "--output-dir",
            str(processed),
            "--chunksize",
            "0",
            "--seed",
            "9",
        ]
    )
    config = TrainingConfig(
        version="smoke-smote",
        seed=9,
        resampling="smote",
        rare_strategy="keep",
        n_iter=1,
        cv_folds=2,
        n_jobs=1,
        param_distributions={"n_estimators": [10]},
        confidence_threshold=0.7,
        anomaly_threshold=0.6,
        smoke_test=True,
    )
    result = train_pipeline(
        processed, tmp_path / "work", config, registry_root=tmp_path / "registry"
    )

    saved = json.loads((result.staging_dir / "config.json").read_text(encoding="utf-8"))
    detail = saved["resampling_detail"]
    assert detail["strategy"] == "smote"
    assert detail["rows_after"] > detail["rows_before"]
    bundle = preprocess.load_preprocessing(processed)
    assert result.metrics["sample_count"] == len(bundle["split"].test)

"""Reproducible Random Forest training for the Phase 3 ML pipeline.

This module never writes directly to the active registry area. Artifacts are
built in a temporary working directory, sealed with checksums, and staged via
``ml.registry.store.stage_version``. A model becomes active only through the
explicit, audited service-layer promotion call.

``--smoke-test`` uses the labelled synthetic CSV fixture under ``tests/`` and a
temporary registry root. It never touches ``data/raw/`` or ``ml/models/``.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import tempfile
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import joblib
import numpy as np
from scipy.special import expit
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import f1_score, make_scorer
from sklearn.model_selection import RandomizedSearchCV, StratifiedKFold
from sklearn.preprocessing import LabelEncoder, StandardScaler

from core.config import settings
from core.logging import get_logger
from ml import evaluate, preprocess
from ml.registry import store
from ml.schema import BENIGN_LABEL, MODEL_FEATURES

logger = get_logger(__name__)

ResamplingStrategy = Literal["none", "smote", "undersample"]

DEFAULT_PARAM_DISTRIBUTIONS: dict[str, list[Any]] = {
    "n_estimators": [100, 200, 300],
    "max_depth": [None, 12, 20],
    "min_samples_split": [2, 5, 10],
    "min_samples_leaf": [1, 2, 4],
    "max_features": ["sqrt", 0.5],
}

FIXTURE_PATH = (
    Path(__file__).resolve().parent.parent
    / "tests"
    / "fixtures"
    / "ml"
    / "TEST_ONLY_synthetic_cicids.csv"
)


@dataclass
class TrainingConfig:
    """Every non-derived input that affects the resulting model."""

    version: str
    seed: int
    resampling: ResamplingStrategy
    rare_strategy: str
    n_iter: int
    cv_folds: int
    n_jobs: int
    param_distributions: dict[str, list[Any]]
    confidence_threshold: float
    anomaly_threshold: float
    smoke_test: bool = False

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TrainingResult:
    """Pointer to a newly staged, verified model version."""

    version: str
    staging_dir: Path
    checksums: dict[str, str]
    metrics: dict[str, Any]
    config: dict[str, Any]


def _git_commit() -> str | None:
    """Best-effort git SHA for reproducibility; never required for training."""

    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip() or None


def _resample_training_split(
    features: np.ndarray,
    labels: np.ndarray,
    *,
    strategy: ResamplingStrategy,
    seed: int,
) -> tuple[np.ndarray, np.ndarray, dict[str, Any]]:
    """Apply a resampling strategy to the training split only."""

    info: dict[str, Any] = {
        "strategy": strategy,
        "rows_before": len(labels),
        "class_counts_before": {
            str(k): int(v)
            for k, v in sorted(zip(*np.unique(labels, return_counts=True)))
        },
    }
    if strategy == "none":
        info["rows_after"] = len(labels)
        return features, labels, info

    min_count = int(np.min(np.unique(labels, return_counts=True)[1]))
    if strategy == "smote":
        if min_count < 2:
            raise ValueError("SMOTE requires at least two samples in every class")
        from imblearn.over_sampling import SMOTE

        sampler: Any = SMOTE(
            random_state=seed,
            k_neighbors=min(5, min_count - 1),
        )
    elif strategy == "undersample":
        from imblearn.under_sampling import RandomUnderSampler

        sampler = RandomUnderSampler(
            random_state=seed, sampling_strategy="not minority"
        )
    else:  # pragma: no cover - guarded by argparse choices
        raise ValueError(f"unknown resampling strategy: {strategy!r}")

    resampled_features, resampled_labels = sampler.fit_resample(features, labels)
    info["rows_after"] = len(resampled_labels)
    info["class_counts_after"] = {
        str(k): int(v)
        for k, v in sorted(zip(*np.unique(resampled_labels, return_counts=True)))
    }
    return np.asarray(resampled_features), np.asarray(resampled_labels), info


def _select_anomaly_threshold(
    validation_scores: np.ndarray,
    validation_labels: np.ndarray,
    benign_train_scores: np.ndarray,
    configured_threshold: float,
) -> tuple[float, str]:
    """Choose a threshold on validation data using Youden's J statistic.

    Scores are in [0, 1] and higher means more anomalous. The validation label
    is used only to pick a decision threshold after the Isolation Forest has
    been fit exclusively on benign training traffic. If validation lacks either
    benign or attack examples, a stable 95th-percentile benign-training cutoff
    is used instead and the method is recorded in the config.
    """

    positive = (validation_labels != BENIGN_LABEL).astype(int)
    if positive.min() == positive.max():
        return (
            float(np.quantile(benign_train_scores, 0.95)),
            "quantile_95_benign_train",
        )
    candidates = np.unique(
        np.concatenate(
            [
                np.linspace(0.0, 1.0, 501),
                validation_scores,
            ]
        )
    )
    best_threshold = float(configured_threshold)
    best_j = -1.0
    for candidate in candidates:
        predicted = (validation_scores >= candidate).astype(int)
        tpr = float(predicted[positive == 1].mean())
        fpr = float(predicted[positive == 0].mean())
        youden_j = tpr - fpr
        if youden_j > best_j:
            best_j = youden_j
            best_threshold = float(candidate)
    return best_threshold, "youden_j_validation"


def _anomaly_scores(model: IsolationForest, scaled_features: np.ndarray) -> np.ndarray:
    """Map IsolationForest.score_samples to a [0, 1] anomaly score."""

    return expit(-model.score_samples(scaled_features))


def _json_safe(value: Any) -> Any:
    """Convert numpy scalars/arrays into JSON-serialisable Python values."""

    if isinstance(value, np.generic):
        return value.item()
    if isinstance(value, np.ndarray):
        return [_json_safe(item) for item in value.tolist()]
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return value


def _build_baseline(
    train_raw: np.ndarray,
    validation_features: np.ndarray,
    validation_proba: np.ndarray,
    validation_labels: np.ndarray,
    feature_names: list[str],
) -> dict[str, Any]:
    """Store feature, prediction, and confidence baselines for drift checks."""

    quantile_levels = [0.0, 0.1, 0.25, 0.5, 0.75, 0.9, 1.0]
    features_baseline: dict[str, Any] = {}
    for index, name in enumerate(feature_names):
        column = train_raw[:, index]
        features_baseline[name] = {
            "quantiles": np.quantile(column, quantile_levels).tolist(),
            "quantile_levels": quantile_levels,
            "mean": float(column.mean()),
            "std": float(column.std()),
            "ks_reference": np.random.default_rng(0)
            .choice(column, size=min(500, len(column)), replace=False)
            .tolist(),
        }
    predicted_indices = validation_proba.argmax(axis=1)
    predicted_labels = [str(x) for x in validation_labels[predicted_indices]]
    counts: dict[str, int] = {}
    for label in predicted_labels:
        counts[label] = counts.get(label, 0) + 1
    confidences = validation_proba.max(axis=1)
    return {
        "feature_names": feature_names,
        "features": features_baseline,
        "prediction_distribution": counts,
        "confidence_quantiles": np.quantile(confidences, quantile_levels).tolist(),
        "confidence_quantile_levels": quantile_levels,
        "confidence_ks_reference": confidences.tolist(),
        "baseline_rows": len(train_raw),
        "validation_rows": len(validation_features),
    }


def train_pipeline(
    processed_dir: Path,
    work_dir: Path,
    config: TrainingConfig,
    *,
    registry_root: Path | None,
) -> TrainingResult:
    """Run the full training pipeline and stage the resulting artifacts."""

    if config.n_iter < 1 or config.cv_folds < 2:
        raise ValueError("n_iter must be >= 1 and cv_folds must be >= 2")

    bundle = preprocess.load_preprocessing(Path(processed_dir))
    features: Any = bundle["features"]
    labels: Any = bundle["labels"]
    split: preprocess.SplitIndices = bundle["split"]
    scaler: StandardScaler = bundle["scaler"]
    metadata: dict[str, Any] = bundle["metadata"]

    if list(bundle["feature_names"]) != list(MODEL_FEATURES):
        raise ValueError(
            "saved feature contract does not match ml.schema.MODEL_FEATURES"
        )

    train_raw = features.iloc[split.train].to_numpy(dtype="float64")
    validation_raw = features.iloc[split.validation].to_numpy(dtype="float64")
    test_raw = features.iloc[split.test].to_numpy(dtype="float64")
    y_train = labels.iloc[split.train].to_numpy()
    y_validation = labels.iloc[split.validation].to_numpy()
    y_test = labels.iloc[split.test].to_numpy()

    encoder = LabelEncoder().fit(y_train)
    y_train_encoded = encoder.transform(y_train)
    y_test_encoded = encoder.transform(y_test)

    x_train_scaled = scaler.transform(train_raw)
    x_validation_scaled = scaler.transform(validation_raw)
    x_test_scaled = scaler.transform(test_raw)

    x_resampled, y_resampled, resampling_info = _resample_training_split(
        x_train_scaled,
        y_train_encoded,
        strategy=config.resampling,
        seed=config.seed,
    )
    min_class_count = int(np.min(np.unique(y_resampled, return_counts=True)[1]))
    cv_folds = min(config.cv_folds, min_class_count)
    if cv_folds < 2:
        raise ValueError(
            "fewer than two samples in the smallest class after resampling"
        )

    class_weight: str | None = None if config.resampling != "none" else "balanced"
    forest = RandomForestClassifier(
        random_state=config.seed,
        class_weight=class_weight,
        n_jobs=1,
    )
    search = RandomizedSearchCV(
        estimator=forest,
        param_distributions=config.param_distributions,
        n_iter=config.n_iter,
        scoring=make_scorer(f1_score, average="macro", zero_division=0),
        cv=StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=config.seed),
        random_state=config.seed,
        n_jobs=config.n_jobs,
        refit=True,
        error_score="raise",
    )
    search.fit(x_resampled, y_resampled)
    model = search.best_estimator_

    benign_mask = y_train == BENIGN_LABEL
    if not benign_mask.any():
        raise ValueError(
            "Isolation Forest requires benign examples in the training split"
        )
    isolation = IsolationForest(
        n_estimators=100,
        contamination="auto",
        random_state=config.seed,
        n_jobs=config.n_jobs,
    )
    isolation.fit(x_train_scaled[benign_mask])
    benign_train_scores = _anomaly_scores(isolation, x_train_scaled[benign_mask])
    validation_scores = _anomaly_scores(isolation, x_validation_scaled)
    anomaly_threshold, threshold_method = _select_anomaly_threshold(
        validation_scores,
        y_validation,
        benign_train_scores,
        config.anomaly_threshold,
    )

    started = time.perf_counter()
    test_proba = model.predict_proba(x_test_scaled)
    batch_seconds = time.perf_counter() - started
    single_started = time.perf_counter()
    model.predict_proba(x_test_scaled[:1])
    single_seconds = time.perf_counter() - single_started

    metrics = evaluate.evaluate_split(
        y_true=y_test_encoded,
        y_pred=test_proba.argmax(axis=1),
        y_proba=test_proba,
        classes=list(encoder.classes_),
        output_dir=work_dir,
        latency_seconds=batch_seconds,
        single_flow_seconds=single_seconds,
    )

    validation_proba = model.predict_proba(x_validation_scaled)
    baseline = _build_baseline(
        train_raw,
        validation_raw,
        validation_proba,
        encoder.classes_,
        list(MODEL_FEATURES),
    )

    work_dir.mkdir(parents=True, exist_ok=True)
    evaluate.write_metrics(metrics, work_dir)
    feature_contract = {
        "features": list(MODEL_FEATURES),
        "feature_count": len(MODEL_FEATURES),
        "label_column": "Label",
        "impute_values": np.nanmedian(train_raw, axis=0).tolist(),
        "destination_port_note": (
            "Destination Port is included because it is available at flow "
            "creation; dataset-specific port bias is documented in docs/ml_pipeline.md"
        ),
    }
    config_payload: dict[str, Any] = {
        **config.as_dict(),
        "cv_folds_used": cv_folds,
        "effective_class_weight": class_weight,
        "resampling_detail": resampling_info,
        "best_params": _json_safe(search.best_params_),
        "best_cv_macro_f1": float(search.best_score_),
        "anomaly_threshold_method": threshold_method,
        "anomaly_threshold": float(anomaly_threshold),
        "git_commit": _git_commit(),
        "dataset_hash": metadata["fingerprint"]["combined_sha256"],
        "dataset_files": metadata["fingerprint"]["files"],
        "class_counts_after_cleaning": metadata["cleaning"]["class_counts_after"],
        "trained_at": datetime.now(UTC).isoformat(),
    }
    artifacts = {
        "model.joblib": work_dir / "model.joblib",
        "scaler.joblib": work_dir / "scaler.joblib",
        "encoder.joblib": work_dir / "encoder.joblib",
        "isolation_forest.joblib": work_dir / "isolation_forest.joblib",
        "features.json": work_dir / "features.json",
        "config.json": work_dir / "config.json",
        "baseline.json": work_dir / "baseline.json",
        "metrics.json": work_dir / "metrics.json",
    }
    joblib.dump(model, artifacts["model.joblib"], compress=3)
    joblib.dump(scaler, artifacts["scaler.joblib"], compress=3)
    joblib.dump(encoder, artifacts["encoder.joblib"], compress=3)
    joblib.dump(
        {
            "model": isolation,
            "threshold": float(anomaly_threshold),
            "threshold_method": threshold_method,
            "score_method": "sigmoid_negative_score_samples",
        },
        artifacts["isolation_forest.joblib"],
        compress=3,
    )
    for name, payload in (
        ("features.json", feature_contract),
        ("config.json", config_payload),
        ("baseline.json", baseline),
    ):
        artifacts[name].write_text(
            json.dumps(payload, indent=2, sort_keys=True, default=str),
            encoding="utf-8",
        )

    root = (
        Path(registry_root) if registry_root else Path(settings.ML_MODEL_REGISTRY_PATH)
    )
    stage_metadata = {
        "algorithm": "RandomForestClassifier",
        "feature_names": list(MODEL_FEATURES),
        "metrics": metrics,
        "dataset_hash": config_payload["dataset_hash"],
        "git_commit": config_payload["git_commit"],
        "training_config": config_payload,
    }
    checksums = store.stage_version(config.version, artifacts, stage_metadata, root)
    staging_dir = store.version_directory(config.version, root, area="staging")
    logger.info(
        "Staged version %s (train=%d, resampled=%d, test=%d, cv=%d)",
        config.version,
        len(y_train),
        len(y_resampled),
        len(y_test),
        cv_folds,
    )
    return TrainingResult(
        version=config.version,
        staging_dir=staging_dir,
        checksums=checksums,
        metrics=metrics,
        config=config_payload,
    )


def _register_staged(
    result: TrainingResult,
    db_session: Any,
    *,
    root: Path,
    actor_user_id: int | None,
) -> None:
    from ml.registry import service

    service.register_staged_version(
        result.version,
        {name: result.staging_dir / name for name in result.checksums},
        {
            "algorithm": "RandomForestClassifier",
            "feature_names": list(MODEL_FEATURES),
            "metrics": result.metrics,
            "dataset_hash": result.config["dataset_hash"],
            "git_commit": result.config.get("git_commit"),
            "training_config": result.config,
        },
        db_session,
        root=root,
        actor_user_id=actor_user_id,
    )


def smoke_test(
    registry_root: Path,
    work_dir: Path,
    *,
    fixture: Path = FIXTURE_PATH,
    n_iter: int = 2,
    cv_folds: int = 2,
    seed: int = settings.ML_RANDOM_SEED,
    resampling: ResamplingStrategy = "none",
) -> TrainingResult:
    """End-to-end pipeline exercise on the labelled test fixture only."""

    if not fixture.is_file():
        raise FileNotFoundError(f"synthetic test fixture missing: {fixture}")
    processed_dir = work_dir / "processed"
    preprocess.main(
        [
            "--input-dir",
            str(fixture.parent),
            "--output-dir",
            str(processed_dir),
            "--chunksize",
            "0",
            "--rare-strategy",
            "keep",
            "--seed",
            str(seed),
        ]
    )
    config = TrainingConfig(
        version=f"smoke-{datetime.now(UTC):%Y%m%dT%H%M%S}",
        seed=seed,
        resampling=resampling,
        rare_strategy="keep",
        n_iter=n_iter,
        cv_folds=cv_folds,
        n_jobs=1,
        param_distributions={
            "n_estimators": [25, 50],
            "max_depth": [None, 8],
            "min_samples_leaf": [1, 2],
        },
        confidence_threshold=settings.ML_CONFIDENCE_THRESHOLD,
        anomaly_threshold=settings.ML_ANOMALY_SCORE_THRESHOLD,
        smoke_test=True,
    )
    return train_pipeline(
        processed_dir,
        work_dir / "artifacts",
        config,
        registry_root=registry_root,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Train and stage a CICIDS2017 model")
    parser.add_argument("--processed-dir", type=Path, default=None)
    parser.add_argument(
        "--registry-root", type=Path, default=Path(settings.ML_MODEL_REGISTRY_PATH)
    )
    parser.add_argument("--work-dir", type=Path, default=None)
    parser.add_argument("--version", default=None)
    parser.add_argument("--seed", type=int, default=settings.ML_RANDOM_SEED)
    parser.add_argument("--n-iter", type=int, default=10)
    parser.add_argument("--cv-folds", type=int, default=5)
    parser.add_argument("--n-jobs", type=int, default=-1)
    parser.add_argument(
        "--resampling",
        choices=("none", "smote", "undersample"),
        default="none",
    )
    parser.add_argument(
        "--rare-strategy", choices=preprocess.RARE_STRATEGIES, default="keep"
    )
    parser.add_argument(
        "--confidence-threshold", type=float, default=settings.ML_CONFIDENCE_THRESHOLD
    )
    parser.add_argument(
        "--anomaly-threshold", type=float, default=settings.ML_ANOMALY_SCORE_THRESHOLD
    )
    parser.add_argument("--smoke-test", action="store_true")
    parser.add_argument("--fixture", type=Path, default=FIXTURE_PATH)
    parser.add_argument("--no-register", action="store_true")
    parser.add_argument("--actor-id", type=int, default=None)
    args = parser.parse_args(argv)

    temporary_workdir = args.work_dir is None
    work_dir = args.work_dir or Path(tempfile.mkdtemp(prefix="ai_ids_train_"))
    try:
        if args.smoke_test:
            registry_root = (
                args.registry_root
                if args.registry_root != Path(settings.ML_MODEL_REGISTRY_PATH)
                else Path(tempfile.mkdtemp(prefix="ai_ids_smoke_registry_"))
            )
            result = smoke_test(
                registry_root,
                work_dir,
                fixture=args.fixture,
                n_iter=args.n_iter,
                cv_folds=args.cv_folds,
                seed=args.seed,
                resampling=args.resampling,
            )
            register = False
        else:
            if args.processed_dir is None:
                parser.error("--processed-dir is required unless --smoke-test is used")
            version = args.version or f"rf-{datetime.now(UTC):%Y%m%dT%H%M%S}"
            config = TrainingConfig(
                version=version,
                seed=args.seed,
                resampling=args.resampling,
                rare_strategy=args.rare_strategy,
                n_iter=args.n_iter,
                cv_folds=args.cv_folds,
                n_jobs=args.n_jobs,
                param_distributions=DEFAULT_PARAM_DISTRIBUTIONS,
                confidence_threshold=args.confidence_threshold,
                anomaly_threshold=args.anomaly_threshold,
            )
            result = train_pipeline(
                args.processed_dir,
                work_dir,
                config,
                registry_root=args.registry_root,
            )
            register = not args.no_register

        if register:
            from core.db import get_db_session

            with get_db_session() as session:
                _register_staged(
                    result,
                    session,
                    root=args.registry_root,
                    actor_user_id=args.actor_id,
                )

        print(
            json.dumps(
                {
                    "status": "staged",
                    "version": result.version,
                    "staging_dir": str(result.staging_dir),
                    "checksums": result.checksums,
                    "test_accuracy": result.metrics["accuracy"],
                    "smoke_test": args.smoke_test,
                },
                indent=2,
                sort_keys=True,
            )
        )
        logger.info("Model version %s is staged, not active", result.version)
        return 0
    finally:
        if temporary_workdir:
            shutil.rmtree(work_dir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())

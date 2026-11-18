"""Verified loading and inference-contract tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import pytest
from sklearn.preprocessing import LabelEncoder, StandardScaler

from ml.predict import ModelCache, load_artifacts_from_directory
from ml.registry import store
from ml.registry.errors import ChecksumError
from ml.schema import MODEL_FEATURES


class FakeModel:
    """Deterministic model stub used only by these tests."""

    def __init__(self, probabilities: tuple[float, float], n_features: int) -> None:
        self.probabilities = np.asarray(probabilities, dtype="float64")
        self.feature_importances_ = np.arange(n_features, dtype="float64")

    def predict_proba(self, values: Any) -> np.ndarray:
        return np.tile(self.probabilities, (len(values), 1))


class FakeIsolation:
    """Deterministic anomaly-score stub used only by these tests."""

    def __init__(self, score: float) -> None:
        self.score = score

    def score_samples(self, values: Any) -> np.ndarray:
        return np.full(len(values), self.score, dtype="float64")


def _stage_version(
    root: Path,
    version: str,
    *,
    probabilities: tuple[float, float] = (0.9, 0.1),
    anomaly_score: float = 5.0,
) -> Path:
    work = root.parent / f"work-{version}"
    work.mkdir(parents=True, exist_ok=True)
    n = len(MODEL_FEATURES)
    joblib.dump(FakeModel(probabilities, n), work / "model.joblib")
    joblib.dump(StandardScaler().fit(np.zeros((2, n))), work / "scaler.joblib")
    joblib.dump(LabelEncoder().fit(["BENIGN", "DDoS"]), work / "encoder.joblib")
    joblib.dump(
        {
            "model": FakeIsolation(anomaly_score),
            "threshold": 0.6,
            "threshold_method": "test_stub",
        },
        work / "isolation_forest.joblib",
    )
    payloads = {
        "features.json": {
            "features": list(MODEL_FEATURES),
            "impute_values": [0.0] * n,
        },
        "config.json": {
            "confidence_threshold": 0.7,
            "anomaly_threshold": 0.6,
            "seed": 1,
        },
        "baseline.json": {"feature_names": list(MODEL_FEATURES)},
        "metrics.json": {"accuracy": 1.0},
    }
    for name, payload in payloads.items():
        (work / name).write_text(json.dumps(payload), encoding="utf-8")
    names = [
        "model.joblib",
        "scaler.joblib",
        "encoder.joblib",
        "isolation_forest.joblib",
        *payloads,
    ]
    store.stage_version(
        version,
        {name: work / name for name in names},
        {"feature_names": list(MODEL_FEATURES), "metrics": {"accuracy": 1.0}},
        root,
    )
    return store.version_directory(version, root, area="staging")


def _flow(value: float = 1.0) -> dict[str, float]:
    return {name: value for name in MODEL_FEATURES}


def test_checksum_failure_refuses_before_joblib_load(
    tmp_path: Path, monkeypatch: Any
) -> None:
    root = tmp_path / "registry"
    directory = _stage_version(root, "v1.0")
    (directory / "model.joblib").write_bytes(b"tampered")

    def _unexpected_load(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("joblib.load must not be called before verification")

    monkeypatch.setattr("ml.predict.joblib.load", _unexpected_load)
    with pytest.raises(ChecksumError):
        load_artifacts_from_directory(directory)


def test_feature_order_and_contract_enforcement(tmp_path: Path) -> None:
    root = tmp_path / "registry"
    directory = _stage_version(root, "v1.0")
    bundle = load_artifacts_from_directory(directory)

    expected = bundle.predict_single(_flow())
    shuffled = dict(reversed(list(_flow().items())))
    assert bundle.predict_single(shuffled).predicted_class == expected.predicted_class

    frame = pd.DataFrame([_flow()], columns=list(reversed(MODEL_FEATURES)))
    assert bundle.predict_single(frame).predicted_class == expected.predicted_class

    missing = _flow()
    missing.pop(MODEL_FEATURES[0])
    with pytest.raises(ValueError, match="feature contract"):
        bundle.predict_single(missing)

    extra = _flow()
    extra["surprise"] = 1.0
    with pytest.raises(ValueError, match="feature contract"):
        bundle.predict_single(extra)


def test_nan_and_infinity_are_handled_safely(tmp_path: Path) -> None:
    root = tmp_path / "registry"
    bundle = load_artifacts_from_directory(_stage_version(root, "v1.0"))
    flow = _flow()
    flow[MODEL_FEATURES[0]] = float("nan")
    flow[MODEL_FEATURES[1]] = float("inf")
    prediction = bundle.predict_single(flow)
    assert np.isfinite(prediction.confidence)
    assert np.isfinite(prediction.anomaly_score)


def test_verdicts_and_top_features(tmp_path: Path) -> None:
    root = tmp_path / "registry"
    uncertain_dir = _stage_version(root, "uncertain", probabilities=(0.55, 0.45))
    uncertain = load_artifacts_from_directory(uncertain_dir).predict_single(_flow())
    assert uncertain.verdict == "uncertain"
    assert len(uncertain.top_probabilities) == 2
    assert len(uncertain.top_features) == 3
    assert [name for name, _ in uncertain.top_features] == list(
        reversed(MODEL_FEATURES[-3:])
    )

    benign_dir = _stage_version(
        tmp_path / "registry2",
        "anomaly",
        probabilities=(0.95, 0.05),
        anomaly_score=-8.0,
    )
    anomalous = load_artifacts_from_directory(benign_dir).predict_single(_flow())
    assert anomalous.verdict == "anomaly"

    known_dir = _stage_version(
        tmp_path / "registry3", "known", probabilities=(0.05, 0.95), anomaly_score=-8.0
    )
    known = load_artifacts_from_directory(known_dir).predict_single(_flow())
    assert known.verdict == "known attack"


def test_cache_hot_reloads_when_active_version_changes(tmp_path: Path) -> None:
    root = tmp_path / "registry"
    _stage_version(root, "v1.0", probabilities=(0.9, 0.1))
    store.promote_version("v1.0", root)

    cache = ModelCache(root)
    assert cache.get().version == "v1.0"
    assert cache.get().predict_single(_flow()).predicted_class == "BENIGN"

    _stage_version(root, "v2.0", probabilities=(0.1, 0.9))
    store.promote_version("v2.0", root)
    assert cache.get().version == "v2.0"
    assert cache.get().predict_single(_flow()).predicted_class == "DDoS"

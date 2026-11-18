"""Drift metric calculations and persistence tests."""

from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd

from core.models.mlops import DriftMetric
from ml import drift
from ml.schema import MODEL_FEATURES


def _baseline(reference: np.ndarray) -> dict[str, Any]:
    return {
        "feature_names": list(MODEL_FEATURES[:1]),
        "features": {
            MODEL_FEATURES[0]: {
                "ks_reference": reference.tolist(),
                "mean": float(reference.mean()),
            }
        },
        "prediction_distribution": {"BENIGN": 50, "DDoS": 50},
        "confidence_ks_reference": np.linspace(0.5, 0.95, 100).tolist(),
    }


def test_psi_on_known_distributions() -> None:
    rng = np.random.default_rng(7)
    reference = rng.normal(0, 1, 1000)
    assert drift.psi(reference, rng.normal(0, 1, 1000)) < 0.1
    assert drift.psi(reference, rng.normal(5, 1, 1000)) > 0.25
    assert drift.psi(reference, reference) == 0.0


def test_distribution_psi_handles_categorical_counts() -> None:
    same = drift.distribution_psi(
        {"BENIGN": 50, "DDoS": 50}, {"BENIGN": 50, "DDoS": 50}
    )
    shifted = drift.distribution_psi(
        {"BENIGN": 50, "DDoS": 50}, {"BENIGN": 5, "DDoS": 95}
    )
    assert same < 0.01
    assert shifted > 0.25


def test_compute_drift_levels() -> None:
    reference = np.random.default_rng(3).normal(0, 1, 500)
    baseline = _baseline(reference)
    frame = pd.DataFrame({MODEL_FEATURES[0]: reference})

    stable = drift.compute_drift(
        "v1.0",
        baseline,
        frame,
        predictions=["BENIGN"] * 50 + ["DDoS"] * 50,
        confidences=np.linspace(0.5, 0.95, 100),
    )
    assert stable.level == "ok"
    assert not stable.drift_detected

    shifted_frame = pd.DataFrame({MODEL_FEATURES[0]: reference + 6})
    shifted = drift.compute_drift(
        "v1.0",
        baseline,
        shifted_frame,
        predictions=["DDoS"] * 100,
        confidences=np.linspace(0.05, 0.2, 100),
    )
    assert shifted.level == "critical"
    assert shifted.drift_detected
    assert MODEL_FEATURES[0] in shifted.drifted_features
    assert "prediction_distribution" in shifted.drifted_features


def test_record_drift_writes_db_row(db_session: Any) -> None:
    reference = np.random.default_rng(1).normal(0, 1, 200)
    result = drift.compute_drift(
        "v1.0", _baseline(reference), pd.DataFrame({MODEL_FEATURES[0]: reference})
    )
    metric = drift.record_drift(result, db_session)
    db_session.flush()
    assert isinstance(metric, DriftMetric)
    assert (
        db_session.query(DriftMetric).filter_by(model_version="v1.0").one().sample_size
        == 200
    )

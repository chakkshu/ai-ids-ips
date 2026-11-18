"""Feature, prediction, and confidence drift measurement.

Baseline statistics (including a bounded KS reference sample) are saved at
training time. PSI uses equal-count quantile bins derived from that reference;
KS uses ``scipy.stats.ks_2samp``. Every result can be persisted to the Phase 1
``DriftMetric`` table with ``record_drift``.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from scipy.stats import ks_2samp

from core.config import settings

EPSILON = 1e-4


@dataclass
class FeatureDrift:
    feature: str
    psi: float
    ks_statistic: float
    ks_p_value: float
    level: str


@dataclass
class DriftResult:
    model_version: str
    sample_size: int
    psi_score: float
    ks_statistic: float
    ks_p_value: float
    features: list[FeatureDrift]
    prediction_psi: float
    confidence_psi: float
    confidence_ks_p_value: float | None
    level: str
    drift_detected: bool
    drifted_features: list[str]

    def as_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["features"] = [asdict(item) for item in self.features]
        return payload


def psi(
    expected: Any, actual: Any, *, bins: int = 10, epsilon: float = EPSILON
) -> float:
    """Population Stability Index between two one-dimensional samples."""

    expected_array = np.asarray(expected, dtype="float64").ravel()
    actual_array = np.asarray(actual, dtype="float64").ravel()
    expected_array = expected_array[np.isfinite(expected_array)]
    actual_array = actual_array[np.isfinite(actual_array)]
    if len(expected_array) == 0 or len(actual_array) == 0:
        return 0.0
    levels = np.linspace(0.0, 1.0, bins + 1)
    edges = np.unique(np.quantile(expected_array, levels))
    if len(edges) < 2:
        return 0.0 if np.allclose(actual_array, expected_array[0]) else 1.0
    edges[0], edges[-1] = -np.inf, np.inf
    expected_counts = np.histogram(expected_array, bins=edges)[0].astype(float)
    actual_counts = np.histogram(actual_array, bins=edges)[0].astype(float)
    expected_pct = (expected_counts + epsilon) / (
        expected_counts.sum() + bins * epsilon
    )
    actual_pct = (actual_counts + epsilon) / (actual_counts.sum() + bins * epsilon)
    return float(
        np.sum((actual_pct - expected_pct) * np.log(actual_pct / expected_pct))
    )


def distribution_psi(
    expected_counts: dict[str, int], actual_counts: dict[str, int]
) -> float:
    """PSI for categorical distributions (predicted classes, verdicts, etc.)."""

    keys = sorted(set(expected_counts) | set(actual_counts))
    if not keys:
        return 0.0
    expected = (
        np.array([expected_counts.get(k, 0) for k in keys], dtype=float) + EPSILON
    )
    actual = np.array([actual_counts.get(k, 0) for k in keys], dtype=float) + EPSILON
    expected_pct = expected / expected.sum()
    actual_pct = actual / actual.sum()
    return float(
        np.sum((actual_pct - expected_pct) * np.log(actual_pct / expected_pct))
    )


def _clean_features(
    features: pd.DataFrame | np.ndarray,
    feature_names: list[str],
    baseline: dict[str, Any],
) -> np.ndarray:
    if isinstance(features, pd.DataFrame):
        missing = [name for name in feature_names if name not in features.columns]
        extra = [name for name in features.columns if name not in feature_names]
        if missing or extra:
            raise ValueError(
                f"feature contract violation: missing={missing}, extra={extra}"
            )
        values = features.loc[:, feature_names].to_numpy(dtype="float64", copy=True)
    else:
        values = np.asarray(features, dtype="float64")
        if values.ndim == 1:
            values = values.reshape(1, -1)
        if values.shape[1] != len(feature_names):
            raise ValueError(
                f"expected {len(feature_names)} features, got shape {values.shape}"
            )
    values[~np.isfinite(values)] = np.nan
    for index, name in enumerate(feature_names):
        column = values[:, index]
        mask = np.isnan(column)
        if mask.any():
            fill = float(baseline["features"][name].get("mean", 0.0))
            column[mask] = fill
    return values


def compute_drift(
    model_version: str,
    baseline: dict[str, Any],
    features: pd.DataFrame | np.ndarray,
    *,
    predictions: list[str] | np.ndarray | None = None,
    confidences: list[float] | np.ndarray | None = None,
    warn_psi: float = settings.ML_DRIFT_THRESHOLD_PSI,
    critical_psi: float = settings.ML_DRIFT_CRITICAL_PSI,
    p_value_threshold: float = settings.ML_DRIFT_P_VALUE_THRESHOLD,
) -> DriftResult:
    """Compare current traffic against the saved training baseline."""

    feature_names = list(baseline["feature_names"])
    values = _clean_features(features, feature_names, baseline)
    feature_results: list[FeatureDrift] = []
    for index, name in enumerate(feature_names):
        reference = np.asarray(
            baseline["features"][name]["ks_reference"], dtype="float64"
        )
        current = values[:, index]
        feature_psi = psi(reference, current)
        ks = ks_2samp(reference, current)
        if feature_psi >= critical_psi or ks.pvalue < p_value_threshold:
            level = "critical" if feature_psi >= critical_psi else "warn"
        elif feature_psi >= warn_psi:
            level = "warn"
        else:
            level = "ok"
        feature_results.append(
            FeatureDrift(
                feature=name,
                psi=feature_psi,
                ks_statistic=float(ks.statistic),
                ks_p_value=float(ks.pvalue),
                level=level,
            )
        )

    prediction_psi = 0.0
    if predictions is not None:
        expected_counts = {
            str(k): int(v)
            for k, v in baseline.get("prediction_distribution", {}).items()
        }
        actual_counts = dict(Counter(str(x) for x in predictions))
        prediction_psi = distribution_psi(expected_counts, actual_counts)

    confidence_psi = 0.0
    confidence_p_value: float | None = None
    if confidences is not None and baseline.get("confidence_ks_reference"):
        current_conf = np.asarray(confidences, dtype="float64")
        reference_conf = np.asarray(
            baseline["confidence_ks_reference"], dtype="float64"
        )
        confidence_psi = psi(reference_conf, current_conf)
        confidence_p_value = float(ks_2samp(reference_conf, current_conf).pvalue)

    max_psi = max(
        [item.psi for item in feature_results] + [prediction_psi, confidence_psi]
    )
    max_ks = max((item.ks_statistic for item in feature_results), default=0.0)
    min_p = min((item.ks_p_value for item in feature_results), default=1.0)
    if confidence_p_value is not None:
        min_p = min(min_p, confidence_p_value)

    drifted = [item.feature for item in feature_results if item.level != "ok"]
    if prediction_psi >= warn_psi:
        drifted.append("prediction_distribution")
    if confidence_psi >= warn_psi:
        drifted.append("confidence_distribution")

    if max_psi >= critical_psi:
        level = "critical"
    elif (
        max_psi >= warn_psi
        or min_p < p_value_threshold
        or any(item.level != "ok" for item in feature_results)
    ):
        level = "warn"
    else:
        level = "ok"

    return DriftResult(
        model_version=model_version,
        sample_size=len(values),
        psi_score=float(max_psi),
        ks_statistic=float(max_ks),
        ks_p_value=float(min_p),
        features=feature_results,
        prediction_psi=float(prediction_psi),
        confidence_psi=float(confidence_psi),
        confidence_ks_p_value=confidence_p_value,
        level=level,
        drift_detected=level in {"warn", "critical"},
        drifted_features=sorted(set(drifted)),
    )


def load_baseline(path: Path | str) -> dict[str, Any]:
    """Load a saved training baseline from a staged artifact directory."""

    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or "feature_names" not in payload:
        raise ValueError("invalid drift baseline file")
    return payload


def record_drift(result: DriftResult, db_session: Any) -> Any:
    """Persist a drift result to the DriftMetric table."""

    from core.models.mlops import DriftMetric

    metric = DriftMetric(
        model_version=result.model_version,
        psi_score=result.psi_score,
        ks_statistic=result.ks_statistic,
        ks_p_value=result.ks_p_value,
        drift_detected=result.drift_detected,
        drifted_features_json=json.dumps(result.drifted_features, sort_keys=True),
        sample_size=result.sample_size,
    )
    db_session.add(metric)
    db_session.flush()
    return metric

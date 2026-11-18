"""Verified, contract-enforcing inference for staged AI-IDS/IPS models.

A model is never deserialised until every artifact SHA-256 digest in the
registry's ``checksums.json`` matches the bytes on disk. Feature names and
order are enforced from the saved contract, and the active model is reloaded
when the registry pointer changes.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from scipy.special import expit

from core.config import settings
from ml.registry import store
from ml.registry.errors import ChecksumError
from ml.registry.paths import validate_filename
from ml.schema import BENIGN_LABEL, DEFAULT_FEATURE_VARIANT, features_for_variant

Verdict = str


@dataclass(frozen=True)
class Prediction:
    """One flow's combined classification and explanation."""

    predicted_class: str
    confidence: float
    top_probabilities: tuple[tuple[str, float], ...]
    anomaly_score: float
    verdict: Verdict
    top_features: tuple[tuple[str, float], ...]


@dataclass
class ModelBundle:
    """Verified, immutable-in-practice set of loaded artifacts."""

    version: str
    model: Any
    scaler: Any
    encoder: Any
    isolation: dict[str, Any]
    feature_names: list[str]
    feature_variant: str
    impute_values: np.ndarray
    feature_importances: np.ndarray
    confidence_threshold: float
    anomaly_threshold: float
    git_commit: str | None = None

    def _coerce_batch(self, flows: Any) -> np.ndarray:
        """Validate feature names/order and return a clean float matrix."""

        if isinstance(flows, pd.DataFrame):
            columns = list(flows.columns)
            self._check_columns(columns)
            frame = flows.loc[:, self.feature_names]
        elif (
            isinstance(flows, Sequence)
            and len(flows) == 1
            and isinstance(flows[0], pd.DataFrame)
        ):
            frame = flows[0].loc[:, self.feature_names]
            self._check_columns(list(flows[0].columns))
        elif isinstance(flows, Mapping):
            columns = list(flows.keys())
            self._check_columns(columns)
            frame = pd.DataFrame([flows], columns=self.feature_names)
        elif isinstance(flows, Sequence) and flows and isinstance(flows[0], Mapping):
            rows = [dict(item) for item in flows]
            for item in rows:
                self._check_columns(list(item.keys()))
            frame = pd.DataFrame(rows, columns=self.feature_names)
        else:
            array = np.asarray(flows, dtype="float32")
            if array.ndim == 1:
                array = array.reshape(1, -1)
            if array.ndim != 2 or array.shape[1] != len(self.feature_names):
                raise ValueError(
                    f"expected {len(self.feature_names)} features, got shape {array.shape}"
                )
            frame = pd.DataFrame(array, columns=self.feature_names)

        values = frame.to_numpy(dtype="float32", copy=True)
        values[~np.isfinite(values)] = np.nan
        nan_rows, nan_columns = np.where(np.isnan(values))
        if len(nan_rows):
            values[nan_rows, nan_columns] = self.impute_values[nan_columns]
        return values

    def _check_columns(self, columns: Sequence[Any]) -> None:
        actual = [str(column) for column in columns]
        expected = self.feature_names
        missing = [name for name in expected if name not in actual]
        extra = [name for name in actual if name not in expected]
        if missing or extra:
            raise ValueError(
                "feature contract violation: "
                f"missing={missing}, extra={extra}, expected_order={expected}"
            )

    def _verdict(self, label: str, confidence: float, anomaly_score: float) -> Verdict:
        if confidence < self.confidence_threshold:
            return "uncertain"
        if label == BENIGN_LABEL:
            return "anomaly" if anomaly_score >= self.anomaly_threshold else "benign"
        return "known attack"

    def _top_features(
        self, scaled_row: np.ndarray, top_k: int
    ) -> tuple[tuple[str, float], ...]:
        if top_k <= 0 or len(self.feature_importances) != len(self.feature_names):
            return ()
        weighted = np.abs(scaled_row) * self.feature_importances
        indices = np.argsort(weighted)[::-1][:top_k]
        return tuple(
            (self.feature_names[int(i)], float(weighted[int(i)])) for i in indices
        )

    def predict_single(self, flow: Any, *, top_k: int = 3) -> Prediction:
        """Classify one flow supplied as a mapping, DataFrame row, or vector."""

        return self.predict_batch([flow], top_k=top_k)[0]

    def predict_batch(self, flows: Any, *, top_k: int = 3) -> list[Prediction]:
        """Classify a batch while enforcing the saved feature contract."""

        values = self._coerce_batch(flows)
        if len(values) == 0:
            return []
        scaled = np.asarray(self.scaler.transform(values), dtype="float32")
        probabilities = np.asarray(self.model.predict_proba(scaled), dtype="float64")
        predicted_indices = probabilities.argmax(axis=1)
        labels = [
            str(label) for label in self.encoder.inverse_transform(predicted_indices)
        ]
        iso_model = self.isolation["model"]
        anomaly_scores = expit(
            -np.asarray(iso_model.score_samples(scaled), dtype="float64")
        )

        predictions: list[Prediction] = []
        for row_index, label in enumerate(labels):
            row_proba = probabilities[row_index]
            order = np.argsort(row_proba)[::-1][:top_k]
            top = tuple(
                (str(self.encoder.classes_[int(i)]), float(row_proba[int(i)]))
                for i in order
            )
            confidence = float(row_proba[predicted_indices[row_index]])
            anomaly = float(anomaly_scores[row_index])
            predictions.append(
                Prediction(
                    predicted_class=label,
                    confidence=confidence,
                    top_probabilities=top,
                    anomaly_score=anomaly,
                    verdict=self._verdict(label, confidence, anomaly),
                    top_features=self._top_features(scaled[row_index], top_k),
                )
            )
        return predictions


def _verify_directory(directory: Path) -> dict[str, str]:
    """Verify checksums.json against bytes on disk before any pickle is loaded."""

    checksums_path = directory / store.CHECKSUMS_FILE
    if not checksums_path.is_file():
        raise ChecksumError(f"missing registry checksum manifest: {checksums_path}")
    try:
        payload = json.loads(checksums_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ChecksumError("unreadable registry checksum manifest") from exc
    if not isinstance(payload, dict):
        raise ChecksumError("checksum manifest must be a JSON object")

    verified: dict[str, str] = {}
    for filename, expected in payload.items():
        safe_name = validate_filename(str(filename))
        path = directory / safe_name
        if not path.is_file():
            raise ChecksumError(f"missing verified artifact: {safe_name}")
        actual = store.sha256_file(path)
        if not isinstance(expected, str) or actual != expected:
            raise ChecksumError(f"checksum mismatch for artifact: {safe_name}")
        verified[safe_name] = actual
    return verified


def load_artifacts_from_directory(directory: Path | str) -> ModelBundle:
    """Load a verified model directory (staging, active, or archive)."""

    directory = Path(directory).resolve()
    _verify_directory(directory)

    model = joblib.load(directory / "model.joblib")
    scaler = joblib.load(directory / "scaler.joblib")
    encoder = joblib.load(directory / "encoder.joblib")
    isolation = joblib.load(directory / "isolation_forest.joblib")
    if not isinstance(isolation, dict) or "model" not in isolation:
        raise ChecksumError("invalid Isolation Forest artifact structure")

    features_contract = json.loads(
        (directory / "features.json").read_text(encoding="utf-8")
    )
    config = json.loads((directory / "config.json").read_text(encoding="utf-8"))
    # Older artifacts have no variant field; they used the original full
    # 78-feature contract, so defaulting to "full" preserves compatibility.
    feature_variant = str(
        features_contract.get("feature_variant")
        or config.get("feature_variant")
        or DEFAULT_FEATURE_VARIANT
    )
    expected_features = features_for_variant(feature_variant)
    feature_names = [str(name) for name in features_contract["features"]]
    if feature_names != list(expected_features):
        raise ChecksumError(
            f"saved feature contract does not match feature variant {feature_variant!r}"
        )
    impute_values = np.asarray(
        features_contract.get("impute_values", np.zeros(len(feature_names))),
        dtype="float64",
    )
    if len(impute_values) != len(feature_names):
        raise ChecksumError("saved imputation vector length does not match features")

    importance = getattr(model, "feature_importances_", None)
    importances = (
        np.asarray(importance, dtype="float64")
        if importance is not None
        else np.zeros(len(feature_names))
    )
    return ModelBundle(
        version=directory.name,
        model=model,
        scaler=scaler,
        encoder=encoder,
        isolation=isolation,
        feature_names=feature_names,
        feature_variant=feature_variant,
        impute_values=impute_values,
        feature_importances=importances,
        confidence_threshold=float(
            config.get("confidence_threshold", settings.ML_CONFIDENCE_THRESHOLD)
        ),
        anomaly_threshold=float(
            config.get("anomaly_threshold", settings.ML_ANOMALY_SCORE_THRESHOLD)
        ),
        git_commit=config.get("git_commit"),
    )


def load_version(version: str, root: Path | str | None = None) -> ModelBundle:
    """Load a verified version from any registry area."""

    from ml.registry.paths import AREAS, registry_root, version_directory

    base = registry_root(root)
    for area in AREAS:
        directory = version_directory(version, base, area=area)
        if directory.is_dir():
            return load_artifacts_from_directory(directory)
    raise ChecksumError(f"model version not found in registry: {version}")


class ModelCache:
    """Thread-safe cache that hot-reloads when the active pointer changes."""

    def __init__(
        self,
        root: Path | str | None = None,
        *,
        confidence_threshold: float | None = None,
        anomaly_threshold: float | None = None,
    ) -> None:
        from ml.registry.paths import registry_root

        self.root = registry_root(root)
        self.confidence_threshold = confidence_threshold
        self.anomaly_threshold = anomaly_threshold
        self._lock = threading.RLock()
        self._version: str | None = None
        self._bundle: ModelBundle | None = None

    def get(self) -> ModelBundle:
        with self._lock:
            version = store.active_version(self.root)
            if version is None:
                raise ChecksumError("no active model version is configured")
            if self._bundle is not None and self._version == version:
                return self._bundle
            active_dir = store.version_directory(version, self.root, area="active")
            bundle = load_artifacts_from_directory(active_dir)
            if self.confidence_threshold is not None:
                bundle.confidence_threshold = self.confidence_threshold
            if self.anomaly_threshold is not None:
                bundle.anomaly_threshold = self.anomaly_threshold
            self._bundle = bundle
            self._version = version
            return bundle

    def clear(self) -> None:
        with self._lock:
            self._bundle = None
            self._version = None


_CACHE = ModelCache()


def predict_single(
    flow: Any, *, top_k: int = 3, cache: ModelCache | None = None
) -> Prediction:
    """Convenience wrapper for a single flow against the active model."""

    active_cache = cache or _CACHE
    return active_cache.get().predict_single(flow, top_k=top_k)


def predict_batch(
    flows: Any, *, top_k: int = 3, cache: ModelCache | None = None
) -> list[Prediction]:
    """Convenience wrapper for a batch against the active model."""

    active_cache = cache or _CACHE
    return active_cache.get().predict_batch(flows, top_k=top_k)

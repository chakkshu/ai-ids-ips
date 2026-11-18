"""Cleaning, splitting, sampling, and scaler tests on synthetic fixtures."""

from __future__ import annotations

import hashlib
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from ml import preprocess
from ml.schema import (
    IDENTIFIER_COLUMNS,
    LABEL_COLUMN,
    MODEL_FEATURES,
    RARE_CLASS_LABELS,
    RARE_GROUP_LABEL,
)

FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "fixtures"
    / "ml"
    / "TEST_ONLY_synthetic_cicids.csv"
)


def test_clean_frame_handles_all_known_quirks() -> None:
    problems: list[str] = []
    frame = pd.read_csv(FIXTURE)
    cleaned, report = preprocess.clean_frame(frame, problems=problems)

    assert report.inf_replaced > 0
    assert report.nan_rows_dropped > 0
    assert report.duplicate_rows_dropped > 0
    assert "Fwd Header Length_Duplicate" in cleaned.columns
    assert "Web Attack - Brute Force" in set(cleaned[LABEL_COLUMN])
    assert " BENIGN " not in set(cleaned[LABEL_COLUMN])
    assert not np.isinf(
        cleaned.loc[:, list(MODEL_FEATURES)].to_numpy(dtype="float64", na_value=np.nan)
    ).any()
    assert not problems


def test_stratified_split_is_disjoint_and_covers_all_rows() -> None:
    result = preprocess.preprocess([FIXTURE], seed=7)
    arrays = [
        result.split.train,
        result.split.validation,
        result.split.test,
    ]
    assert all(len(array) > 0 for array in arrays)
    assert not set(arrays[0]) & set(arrays[1])
    assert not set(arrays[0]) & set(arrays[2])
    assert not set(arrays[1]) & set(arrays[2])
    assert len(set(np.concatenate(arrays))) == len(result.features)

    for column in (result.labels.iloc[array] for array in arrays):
        assert set(column) == set(result.labels)


def test_scaler_is_fitted_on_training_rows_only() -> None:
    result = preprocess.preprocess([FIXTURE], seed=11)
    train = result.features.iloc[result.split.train].to_numpy(dtype="float64")
    all_rows = result.features.to_numpy(dtype="float64")
    np.testing.assert_allclose(result.scaler.mean_, train.mean(axis=0), rtol=1e-6)
    assert not np.allclose(result.scaler.mean_, all_rows.mean(axis=0), rtol=1e-6)


def test_rare_class_strategies_are_explicit() -> None:
    frame = pd.read_csv(FIXTURE)

    kept, kept_report = preprocess.clean_frame(frame, rare_strategy="keep")
    assert RARE_CLASS_LABELS.intersection(set(kept[LABEL_COLUMN]))
    assert kept_report.rare_rows_dropped == 0

    merged, merged_report = preprocess.clean_frame(frame, rare_strategy="merge")
    assert RARE_GROUP_LABEL in set(merged[LABEL_COLUMN])
    assert merged_report.rare_rows_merged > 0
    assert RARE_CLASS_LABELS.isdisjoint(set(merged[LABEL_COLUMN]))

    dropped, dropped_report = preprocess.clean_frame(frame, rare_strategy="drop")
    assert RARE_CLASS_LABELS.isdisjoint(set(dropped[LABEL_COLUMN]))
    assert dropped_report.rare_rows_dropped > 0


def test_sampling_options_are_deterministic() -> None:
    fraction = preprocess.preprocess([FIXTURE], seed=3, sample_fraction=0.5)
    capped = preprocess.preprocess([FIXTURE], seed=3, max_rows_per_class=10)
    assert len(fraction.features) < len(
        preprocess.preprocess([FIXTURE], seed=3).features
    )
    assert capped.labels.value_counts().max() <= 10

    again = preprocess.preprocess([FIXTURE], seed=3, sample_fraction=0.5)
    pd.testing.assert_frame_equal(fraction.features, again.features)


def test_optional_identifier_columns_are_not_schema_problems(tmp_path: Path) -> None:
    frame = pd.read_csv(FIXTURE)
    without_ids = frame.loc[
        :, [c for c in frame.columns if c.strip() not in IDENTIFIER_COLUMNS]
    ]
    path = tmp_path / "no_identifiers.csv"
    without_ids.to_csv(path, index=False)

    result = preprocess.preprocess([path], seed=5)
    assert not result.report.problems
    assert list(result.features.columns) == list(MODEL_FEATURES)
    assert len(result.features) > 0


def test_stream_sampling_is_deterministic_and_accounted_for() -> None:
    first = preprocess.preprocess(
        [FIXTURE], seed=5, sample_fraction=0.5, chunksize=20, stream=True
    )
    again = preprocess.preprocess(
        [FIXTURE], seed=5, sample_fraction=0.5, chunksize=20, stream=True
    )

    pd.testing.assert_frame_equal(first.features, again.features)
    assert first.report.streamed
    assert first.report.rows_scanned == 194
    assert 0 < first.report.rows_sampled < first.report.rows_scanned
    assert first.report.class_counts_scanned
    assert first.report.sample_fraction == 0.5


def test_stream_sampling_preserves_rare_classes() -> None:
    result = preprocess.preprocess(
        [FIXTURE], seed=9, sample_fraction=0.01, chunksize=20, stream=True
    )
    scanned = result.report.class_counts_scanned
    labels = set(result.labels)
    assert result.report.rare_rows_preserved > 0
    for label in RARE_CLASS_LABELS & set(scanned):
        assert label in labels


def test_stream_sampling_requires_fraction_and_chunksize() -> None:
    with pytest.raises(ValueError, match="chunksize"):
        preprocess.preprocess([FIXTURE], sample_fraction=0.5, stream=True)
    with pytest.raises(ValueError, match="sample_fraction"):
        preprocess.preprocess([FIXTURE], chunksize=20, stream=True)


def test_stream_class_cap_is_deterministic_and_bounded() -> None:
    first = preprocess.preprocess(
        [FIXTURE], seed=4, max_rows_per_class=10, chunksize=20, stream=True
    )
    again = preprocess.preprocess(
        [FIXTURE], seed=4, max_rows_per_class=10, chunksize=20, stream=True
    )

    pd.testing.assert_frame_equal(first.features, again.features)
    assert first.report.streamed
    assert first.report.max_rows_per_class == 10
    assert max(first.report.class_counts_kept.values()) <= 10
    assert first.report.rows_sampled < first.report.rows_scanned
    assert first.labels.value_counts().max() <= 10


def test_features_and_scaler_statistics_are_float32() -> None:
    result = preprocess.preprocess([FIXTURE], seed=2)
    assert set(result.features.dtypes) == {np.dtype("float32")}
    assert result.scaler.mean_.dtype == np.dtype("float32")
    assert result.scaler.scale_.dtype == np.dtype("float32")


def test_fingerprint_changes_with_file_bytes(tmp_path: Path) -> None:
    original = FIXTURE
    copy = tmp_path / "copy.csv"
    copy.write_bytes(original.read_bytes())
    first = preprocess.fingerprint_files([original])
    second = preprocess.fingerprint_files([copy, original])
    assert first["files"][original.name] == second["files"][original.name]
    assert first["combined_sha256"] != second["combined_sha256"]

    copy.write_text(copy.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    changed = preprocess.fingerprint_files([copy])
    assert (
        changed["files"][copy.name] != hashlib.sha256(original.read_bytes()).hexdigest()
    )

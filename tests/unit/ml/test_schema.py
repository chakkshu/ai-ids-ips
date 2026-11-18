"""Schema contract tests for the CICIDS2017 single source of truth."""

from __future__ import annotations

import pytest

from ml.schema import (
    CANONICAL_LABELS,
    DESTINATION_PORT,
    FEATURE_VARIANTS,
    IDENTIFIER_COLUMNS,
    MODEL_FEATURES,
    RAW_COLUMNS,
    RAW_FEATURE_NAMES,
    canonicalize_columns,
    features_for_variant,
    is_known_label,
    normalize_label,
)


def test_schema_counts_and_feature_contract() -> None:
    assert len(RAW_FEATURE_NAMES) == 84
    assert len(RAW_COLUMNS) == 85
    assert len(MODEL_FEATURES) == 78
    assert len(CANONICAL_LABELS) == 15
    assert "Destination Port" in MODEL_FEATURES
    assert "Fwd Header Length_Duplicate" in MODEL_FEATURES
    assert IDENTIFIER_COLUMNS.issubset(set(RAW_FEATURE_NAMES))
    assert IDENTIFIER_COLUMNS.isdisjoint(MODEL_FEATURES)
    assert "Label" not in MODEL_FEATURES


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (" BENIGN ", "BENIGN"),
        ("Web Attack â€“ Brute Force", "Web Attack - Brute Force"),
        ("Web Attack \x96 Brute Force", "Web Attack - Brute Force"),
        ("web attack   XSS", "Web Attack - XSS"),
        ("SSH-Patator", "SSH-Patator"),
        ("DoS Hulk", "DoS Hulk"),
        ("Heartbleed", "Heartbleed"),
    ],
)
def test_label_normalization(raw: str, expected: str) -> None:
    assert normalize_label(raw) == expected
    assert is_known_label(raw)


def test_unknown_label_is_not_silently_renamed() -> None:
    assert normalize_label("Totally New Attack") == "Totally New Attack"
    assert not is_known_label("Totally New Attack")


def test_feature_variants_are_ordered_subsets() -> None:
    assert list(features_for_variant("full")) == list(MODEL_FEATURES)
    no_port = features_for_variant("no_destination_port")
    assert len(no_port) == 77
    assert DESTINATION_PORT not in no_port
    assert no_port == tuple(f for f in MODEL_FEATURES if f != DESTINATION_PORT)
    assert set(FEATURE_VARIANTS) == {"full", "no_destination_port"}


def test_unknown_feature_variant_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown feature variant"):
        features_for_variant("no_such_variant")


def test_canonicalize_columns_handles_whitespace_and_duplicate() -> None:
    raw = [" Flow ID ", "Fwd Header Length", " Fwd Header Length.1 ", " Label "]
    assert canonicalize_columns(raw) == [
        "Flow ID",
        "Fwd Header Length",
        "Fwd Header Length_Duplicate",
        "Label",
    ]

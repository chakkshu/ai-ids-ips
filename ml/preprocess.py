"""Memory-conscious preprocessing for CICIDS2017 MachineLearningCVE CSVs.

The module never downloads or generates data. It reads CSVs from caller-supplied
paths, canonicalises the schema once (``ml.schema``), cleans the data, produces
a stratified split, fits the scaler on the training split only, and records a
SHA-256 dataset fingerprint for the model registry.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import RobustScaler, StandardScaler

from core.config import settings
from core.logging import get_logger
from ml.schema import (
    CANONICAL_LABELS,
    LABEL_COLUMN,
    MODEL_FEATURES,
    RARE_CLASS_LABELS,
    RARE_GROUP_LABEL,
    RAW_COLUMNS,
    canonicalize_columns,
    normalize_label,
)

logger = get_logger(__name__)

RARE_STRATEGIES = ("keep", "merge", "drop")
SPLIT_FRACTIONS = (0.70, 0.15, 0.15)


@dataclass
class SplitIndices:
    """Row positions into the cleaned dataset for each immutable split."""

    train: np.ndarray
    validation: np.ndarray
    test: np.ndarray

    def as_json(self) -> dict[str, list[int]]:
        return {
            "train": [int(i) for i in self.train],
            "validation": [int(i) for i in self.validation],
            "test": [int(i) for i in self.test],
        }

    @classmethod
    def from_json(cls, payload: dict[str, list[int]]) -> SplitIndices:
        return cls(
            train=np.asarray(payload["train"], dtype=np.int64),
            validation=np.asarray(payload["validation"], dtype=np.int64),
            test=np.asarray(payload["test"], dtype=np.int64),
        )


@dataclass
class CleaningReport:
    """Class distributions and data-quality findings for one cleaning run."""

    class_counts_before: dict[str, int] = field(default_factory=dict)
    class_counts_after: dict[str, int] = field(default_factory=dict)
    rows_in: int = 0
    rows_out: int = 0
    inf_replaced: int = 0
    nan_rows_dropped: int = 0
    duplicate_rows_dropped: int = 0
    rare_strategy: str = "keep"
    rare_rows_merged: int = 0
    rare_rows_dropped: int = 0
    problems: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "class_counts_before": self.class_counts_before,
            "class_counts_after": self.class_counts_after,
            "rows_in": self.rows_in,
            "rows_out": self.rows_out,
            "inf_replaced": self.inf_replaced,
            "nan_rows_dropped": self.nan_rows_dropped,
            "duplicate_rows_dropped": self.duplicate_rows_dropped,
            "rare_strategy": self.rare_strategy,
            "rare_rows_merged": self.rare_rows_merged,
            "rare_rows_dropped": self.rare_rows_dropped,
            "problems": self.problems,
        }


@dataclass
class PreprocessResult:
    """Everything downstream stages need, with no raw-file mutation."""

    features: pd.DataFrame
    labels: pd.Series
    split: SplitIndices
    scaler: StandardScaler | RobustScaler
    scaler_type: str
    fingerprint: dict[str, Any]
    report: CleaningReport
    feature_names: list[str]

    def as_metadata(self) -> dict[str, Any]:
        return {
            "feature_names": self.feature_names,
            "split_sizes": {
                "train": len(self.split.train),
                "validation": len(self.split.validation),
                "test": len(self.split.test),
            },
            "split_fractions": list(SPLIT_FRACTIONS),
            "scaler_type": self.scaler_type,
            "fingerprint": self.fingerprint,
            "cleaning": self.report.as_dict(),
        }


def sha256_file(path: Path) -> str:
    """Stream a file through SHA-256 without loading it into memory."""

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fingerprint_files(paths: Iterable[Path]) -> dict[str, Any]:
    """Return per-file digests plus a combined, order-stable dataset hash."""

    files = [Path(p) for p in paths]
    per_file = {p.name: sha256_file(p) for p in files}
    combined = hashlib.sha256()
    for name in sorted(per_file):
        combined.update(f"{name}:{per_file[name]}\n".encode("ascii"))
    return {"files": per_file, "combined_sha256": combined.hexdigest()}


def _downcast_numeric(frame: pd.DataFrame) -> pd.DataFrame:
    """Coerce feature columns to numeric dtypes and downcast where safe."""

    for column in frame.columns:
        if column == LABEL_COLUMN:
            continue
        numeric = pd.to_numeric(frame[column], errors="coerce")
        if numeric.dropna().empty:
            frame[column] = numeric.astype("float32")
            continue
        if np.isinf(numeric.to_numpy(dtype="float64", na_value=np.nan)).any():
            frame[column] = numeric.astype("float32")
            continue
        integer_like = np.allclose(
            numeric.dropna().to_numpy(dtype="float64"),
            np.round(numeric.dropna().to_numpy(dtype="float64")),
        )
        if integer_like:
            frame[column] = pd.to_numeric(
                numeric.round(), errors="coerce", downcast="integer"
            )
        else:
            frame[column] = pd.to_numeric(numeric, errors="coerce", downcast="float")
    return frame


def canonicalize_frame(frame: pd.DataFrame, problems: list[str]) -> pd.DataFrame:
    """Strip/rename columns and enforce the schema from ``ml.schema``."""

    frame = frame.rename(columns=lambda name: str(name).strip())
    frame.columns = canonicalize_columns(frame.columns)
    expected = set(RAW_COLUMNS)
    missing = sorted(expected.difference(frame.columns))
    if missing:
        problems.append(f"missing expected columns: {', '.join(missing)}")
    extra = sorted(set(frame.columns).difference(expected))
    if extra:
        problems.append(f"unexpected columns ignored: {', '.join(extra)}")
    # Missing columns are added as NaN so the downstream NaN policy is explicit.
    for column in missing:
        frame[column] = np.nan
    return frame.loc[:, list(RAW_COLUMNS)].copy()


def clean_frame(
    frame: pd.DataFrame,
    *,
    rare_strategy: str = "keep",
    problems: list[str] | None = None,
) -> tuple[pd.DataFrame, CleaningReport]:
    """Canonicalise, clean, and label-normalise one in-memory DataFrame."""

    if rare_strategy not in RARE_STRATEGIES:
        raise ValueError(f"unknown rare-class strategy: {rare_strategy!r}")
    findings = problems if problems is not None else []
    report = CleaningReport(rows_in=len(frame), rare_strategy=rare_strategy)
    frame = canonicalize_frame(frame, findings)
    frame = _downcast_numeric(frame)

    report.class_counts_before = dict(
        sorted(Counter(normalize_label(v) for v in frame[LABEL_COLUMN]).items())
    )
    report.inf_replaced = int(
        np.isinf(
            frame[list(MODEL_FEATURES)].to_numpy(dtype="float64", na_value=np.nan)
        ).sum()
    )
    frame[list(MODEL_FEATURES)] = frame[list(MODEL_FEATURES)].replace(
        [np.inf, -np.inf], np.nan
    )

    before_nan = len(frame)
    frame = frame.dropna(subset=list(MODEL_FEATURES) + [LABEL_COLUMN])
    report.nan_rows_dropped = before_nan - len(frame)

    before_duplicates = len(frame)
    frame = frame.drop_duplicates(ignore_index=True)
    report.duplicate_rows_dropped = before_duplicates - len(frame)

    frame[LABEL_COLUMN] = frame[LABEL_COLUMN].map(normalize_label)
    frame = frame[frame[LABEL_COLUMN] != ""]

    known = set(CANONICAL_LABELS) | {RARE_GROUP_LABEL}
    unknown = sorted(
        {label for label in frame[LABEL_COLUMN].unique() if label not in known}
    )
    if unknown:
        findings.append(f"unmapped labels retained: {', '.join(unknown)}")

    rare_mask = frame[LABEL_COLUMN].isin(RARE_CLASS_LABELS)
    if rare_strategy == "merge":
        report.rare_rows_merged = int(rare_mask.sum())
        frame.loc[rare_mask, LABEL_COLUMN] = RARE_GROUP_LABEL
    elif rare_strategy == "drop":
        report.rare_rows_dropped = int(rare_mask.sum())
        frame = frame.loc[~rare_mask].copy()

    frame = frame.reset_index(drop=True)
    report.rows_out = len(frame)
    report.class_counts_after = dict(
        sorted(Counter(frame[LABEL_COLUMN].astype(str)).items())
    )
    report.problems = list(findings)
    return frame, report


def read_csv_chunks(path: Path, chunksize: int | None) -> Iterable[pd.DataFrame]:
    """Yield canonicalised chunks; ``chunksize=None`` yields the whole file."""

    reader = pd.read_csv(
        path,
        chunksize=chunksize,
        low_memory=False,
        skipinitialspace=True,
        encoding_errors="replace",
    )
    chunks = reader if chunksize else [reader]
    for chunk in chunks:
        # Canonicalise before downcasting: the source contains two columns
        # literally named "Fwd Header Length", which pandas cannot index by name.
        yield _downcast_numeric(canonicalize_frame(chunk, []))


def _apply_sampling(
    frame: pd.DataFrame,
    *,
    sample_fraction: float | None,
    max_rows_per_class: int | None,
    seed: int,
) -> pd.DataFrame:
    if sample_fraction is not None:
        if not 0 < sample_fraction <= 1:
            raise ValueError("sample_fraction must be in (0, 1]")
        frame = frame.sample(frac=sample_fraction, random_state=seed)
    if max_rows_per_class is not None:
        if max_rows_per_class < 2:
            raise ValueError("max_rows_per_class must be at least 2")
        frame = (
            frame.groupby(LABEL_COLUMN, group_keys=False)
            .head(max_rows_per_class)
            .sample(frac=1, random_state=seed)
        )
    return frame.reset_index(drop=True)


def stratified_split(
    labels: pd.Series,
    *,
    seed: int = settings.ML_RANDOM_SEED,
    fractions: tuple[float, float, float] = SPLIT_FRACTIONS,
) -> SplitIndices:
    """Three-way stratified split. Rare classes with <2 rows are rejected."""

    counts = Counter(labels)
    too_small = {label: count for label, count in counts.items() if count < 2}
    if too_small:
        raise ValueError(
            "classes with fewer than 2 samples cannot be stratified: "
            + ", ".join(f"{k}={v}" for k, v in sorted(too_small.items()))
        )
    indices = np.arange(len(labels))
    train_frac, validation_frac, test_frac = fractions
    train_idx, remaining_idx = train_test_split(
        indices,
        test_size=1.0 - train_frac,
        stratify=labels,
        random_state=seed,
    )
    remaining_labels = labels.iloc[remaining_idx]
    relative_validation = validation_frac / (validation_frac + test_frac)
    validation_idx, test_idx = train_test_split(
        remaining_idx,
        test_size=1.0 - relative_validation,
        stratify=remaining_labels,
        random_state=seed,
    )
    return SplitIndices(
        train=np.sort(train_idx),
        validation=np.sort(validation_idx),
        test=np.sort(test_idx),
    )


def fit_scaler(
    features: pd.DataFrame, *, scaler_type: str = "standard"
) -> StandardScaler | RobustScaler:
    """Fit a scaler on the provided (training-only) rows."""

    if scaler_type == "standard":
        scaler: StandardScaler | RobustScaler = StandardScaler()
    elif scaler_type == "robust":
        scaler = RobustScaler()
    else:
        raise ValueError(f"unknown scaler type: {scaler_type!r}")
    scaler.fit(features.to_numpy(dtype="float64"))
    return scaler


def preprocess(
    input_paths: Iterable[Path],
    *,
    rare_strategy: str = "keep",
    sample_fraction: float | None = None,
    max_rows_per_class: int | None = None,
    seed: int = settings.ML_RANDOM_SEED,
    chunksize: int | None = None,
    scaler_type: str = "standard",
) -> PreprocessResult:
    """Load, clean, sample, split, and fit the scaler on train rows only."""

    paths = [Path(p) for p in input_paths]
    if not paths:
        raise ValueError("no input CSV files supplied")
    problems: list[str] = []
    frames: list[pd.DataFrame] = []
    for path in paths:
        if not path.is_file():
            raise FileNotFoundError(path)
        frames.extend(read_csv_chunks(path, chunksize))
    if not frames:
        raise ValueError("input CSV files contained no rows")

    combined = pd.concat(frames, ignore_index=True)
    del frames
    cleaned, report = clean_frame(
        combined, rare_strategy=rare_strategy, problems=problems
    )
    del combined
    cleaned = _apply_sampling(
        cleaned,
        sample_fraction=sample_fraction,
        max_rows_per_class=max_rows_per_class,
        seed=seed,
    )
    if cleaned.empty:
        raise ValueError("no rows left after cleaning/sampling")

    split = stratified_split(cleaned[LABEL_COLUMN], seed=seed)
    features = cleaned.loc[:, list(MODEL_FEATURES)].reset_index(drop=True)
    labels = cleaned.loc[:, LABEL_COLUMN].astype(str).reset_index(drop=True)
    scaler = fit_scaler(features.iloc[split.train], scaler_type=scaler_type)
    return PreprocessResult(
        features=features,
        labels=labels,
        split=split,
        scaler=scaler,
        scaler_type=scaler_type,
        fingerprint=fingerprint_files(paths),
        report=report,
        feature_names=list(MODEL_FEATURES),
    )


def save_preprocessing(result: PreprocessResult, output_dir: Path) -> None:
    """Persist the cleaned rows, split indices, scaler, and metadata."""

    output_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "features": result.features,
            "labels": result.labels,
            "feature_names": result.feature_names,
        },
        output_dir / "dataset.joblib",
        compress=3,
    )
    joblib.dump(result.scaler, output_dir / "scaler.joblib")
    (output_dir / "split_indices.json").write_text(
        json.dumps(result.split.as_json(), indent=2, sort_keys=True), encoding="utf-8"
    )
    (output_dir / "preprocessing.json").write_text(
        json.dumps(result.as_metadata(), indent=2, sort_keys=True, default=str),
        encoding="utf-8",
    )


def load_preprocessing(processed_dir: Path) -> dict[str, Any]:
    """Load a previously saved preprocessing bundle."""

    payload = joblib.load(processed_dir / "dataset.joblib")
    metadata = json.loads(
        (processed_dir / "preprocessing.json").read_text(encoding="utf-8")
    )
    return {
        **payload,
        "split": SplitIndices.from_json(
            json.loads(
                (processed_dir / "split_indices.json").read_text(encoding="utf-8")
            )
        ),
        "scaler": joblib.load(processed_dir / "scaler.joblib"),
        "metadata": metadata,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Preprocess CICIDS2017 CSV files")
    parser.add_argument("--input-dir", type=Path, default=Path(settings.ML_DATASET_DIR))
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--chunksize", type=int, default=100_000)
    parser.add_argument("--sample-fraction", type=float, default=None)
    parser.add_argument("--max-rows-per-class", type=int, default=None)
    parser.add_argument("--rare-strategy", choices=RARE_STRATEGIES, default="keep")
    parser.add_argument("--scaler", choices=("standard", "robust"), default="standard")
    parser.add_argument("--seed", type=int, default=settings.ML_RANDOM_SEED)
    args = parser.parse_args(argv)

    paths = sorted(args.input_dir.glob("*.csv"))
    result = preprocess(
        paths,
        rare_strategy=args.rare_strategy,
        sample_fraction=args.sample_fraction,
        max_rows_per_class=args.max_rows_per_class,
        seed=args.seed,
        chunksize=args.chunksize or None,
        scaler_type=args.scaler,
    )
    save_preprocessing(result, args.output_dir)
    logger.info(
        "Preprocessed %s rows into %s; split=%s; fingerprint=%s",
        len(result.features),
        args.output_dir,
        {k: len(v) for k, v in result.split.as_json().items()},
        result.fingerprint["combined_sha256"][:12],
    )
    logger.info(
        "Class counts after cleaning: %s", json.dumps(result.report.class_counts_after)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

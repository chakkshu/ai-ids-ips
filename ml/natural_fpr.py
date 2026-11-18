"""False-positive rate on a natural-distribution BENIGN sample.

The capped processed bundle is deliberately non-natural for large classes, so
its held-out benign FPR is not representative of production traffic. This
module reads the raw CSVs again, draws a uniform sample of BENIGN rows without
any per-class cap, and reports the fraction the staged model labels as an
attack. Only one chunk is materialised at a time.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from core.config import settings
from core.logging import get_logger
from ml import preprocess
from ml.memory import MemoryGuard
from ml.predict import load_artifacts_from_directory
from ml.schema import BENIGN_LABEL, LABEL_COLUMN, normalize_label

logger = get_logger(__name__)


def natural_benign_fpr(
    input_paths: Iterable[Path],
    artifact_dir: Path,
    *,
    max_rows: int = 20_000,
    chunksize: int = 50_000,
    seed: int = settings.ML_RANDOM_SEED,
    problems: list[str] | None = None,
    guard: MemoryGuard | None = None,
) -> dict[str, Any]:
    """Stream raw CSVs and score a uniform BENIGN-only sample."""

    if max_rows < 1:
        raise ValueError("max_rows must be at least 1")
    if chunksize < 1:
        raise ValueError("chunksize must be at least 1")

    bundle = load_artifacts_from_directory(artifact_dir)
    feature_names = list(bundle.feature_names)
    findings = problems if problems is not None else []
    paths = [Path(path) for path in input_paths]
    if not paths:
        raise ValueError("no input CSV files supplied")

    rng = np.random.default_rng(seed)
    reservoir: pd.DataFrame | None = None
    reservoir_keys: np.ndarray | None = None
    rows_scanned = 0
    benign_available = 0

    # Reservoir over *all* BENIGN rows in every file. Stopping at the first
    # chunk would bias the sample to a single capture window.
    for path in paths:
        if not path.is_file():
            raise FileNotFoundError(path)
        for chunk in preprocess.read_csv_chunks(path, chunksize, problems=findings):
            if guard is not None:
                guard.check()
            rows_scanned += len(chunk)
            chunk[LABEL_COLUMN] = chunk[LABEL_COLUMN].map(normalize_label)
            benign = chunk.loc[chunk[LABEL_COLUMN] == BENIGN_LABEL, feature_names]
            benign_available += len(benign)
            if benign.empty:
                continue
            incoming = benign.astype("float32").reset_index(drop=True)
            incoming_keys = rng.random(len(incoming))
            if reservoir is None or reservoir_keys is None:
                reservoir, reservoir_keys = incoming, incoming_keys
                continue
            all_rows = pd.concat([reservoir, incoming], ignore_index=True)
            all_keys = np.concatenate([reservoir_keys, incoming_keys])
            if len(all_keys) > max_rows:
                selected = np.argpartition(all_keys, max_rows - 1)[:max_rows]
                all_rows = all_rows.iloc[selected].reset_index(drop=True)
                all_keys = all_keys[selected]
            reservoir, reservoir_keys = all_rows, all_keys

    if reservoir is None:
        raise ValueError("no BENIGN rows found in the supplied CSV files")
    matrix = reservoir.to_numpy(dtype="float32", copy=True)
    del reservoir
    matrix[~np.isfinite(matrix)] = np.nan
    nan_rows, nan_columns = np.where(np.isnan(matrix))
    if len(nan_rows):
        matrix[nan_rows, nan_columns] = bundle.impute_values[nan_columns]

    if guard is not None:
        guard.check()
    scaled = bundle.scaler.transform(matrix)
    probabilities = bundle.model.predict_proba(scaled)
    predicted = bundle.encoder.inverse_transform(probabilities.argmax(axis=1))
    false_positives = int(np.count_nonzero(predicted != BENIGN_LABEL))

    return {
        "artifact_dir": str(artifact_dir),
        "feature_variant": bundle.feature_variant,
        "feature_count": len(feature_names),
        "sampling": (
            "seeded reservoir sample of raw BENIGN rows across all input CSVs; "
            "no per-class cap and no train/validation/test reuse"
        ),
        "rows_scanned": rows_scanned,
        "benign_rows_available": benign_available,
        "rows_scored": len(matrix),
        "max_rows": max_rows,
        "seed": seed,
        "false_positives": false_positives,
        "false_positive_rate": false_positives / len(matrix),
        "problems": list(findings),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Score BENIGN traffic from raw CSVs for an honest FPR"
    )
    parser.add_argument("--input-dir", type=Path, default=Path(settings.ML_DATASET_DIR))
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--max-rows", type=int, default=20_000)
    parser.add_argument("--chunksize", type=int, default=50_000)
    parser.add_argument("--seed", type=int, default=settings.ML_RANDOM_SEED)
    parser.add_argument("--min-available-gb", type=float, default=0.5)
    parser.add_argument("--memory-interval", type=float, default=15.0)
    parser.add_argument("--memory-log", type=Path, default=None)
    args = parser.parse_args(argv)

    guard = MemoryGuard(
        min_available_gb=args.min_available_gb,
        interval_seconds=args.memory_interval,
        label="natural-fpr",
        log_path=args.memory_log,
    )
    guard.start()
    try:
        payload = natural_benign_fpr(
            sorted(args.input_dir.glob("*.csv")),
            args.artifact_dir,
            max_rows=args.max_rows,
            chunksize=args.chunksize,
            seed=args.seed,
            guard=guard,
        )
    finally:
        guard.stop()

    rendered = json.dumps(payload, indent=2, sort_keys=True)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    logger.info(
        "Natural BENIGN FPR=%.6f on %d rows (%s)",
        payload["false_positive_rate"],
        payload["rows_scored"],
        args.artifact_dir,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

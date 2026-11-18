"""Held-out test-set evaluation for staged ML models.

All metrics are computed on the immutable test split only. Plots use the
non-interactive Agg backend and are written next to the staged artifacts.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    classification_report,
    confusion_matrix,
    precision_recall_curve,
    roc_auc_score,
    roc_curve,
)

from core.logging import get_logger

logger = get_logger(__name__)

MIN_SUPPORT_FOR_TRUSTWORTHY_METRICS = 20


def evaluate_split(
    *,
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_proba: np.ndarray,
    classes: list[str],
    output_dir: Path,
    latency_seconds: float,
    single_flow_seconds: float,
    min_support: int = MIN_SUPPORT_FOR_TRUSTWORTHY_METRICS,
) -> dict[str, Any]:
    """Compute metrics/plots for one held-out split and return the metric dict."""

    output_dir.mkdir(parents=True, exist_ok=True)
    labels = list(range(len(classes)))
    report = classification_report(
        y_true,
        y_pred,
        labels=labels,
        target_names=classes,
        output_dict=True,
        zero_division=0,
    )
    matrix = confusion_matrix(y_true, y_pred, labels=labels)
    row_totals = matrix.sum(axis=1).astype(float)
    fnr = {
        classes[i]: (
            float(matrix[i].sum() - matrix[i, i]) / row_totals[i]
            if row_totals[i]
            else None
        )
        for i in range(len(classes))
    }
    benign_index = classes.index("BENIGN") if "BENIGN" in classes else None
    if benign_index is None:
        benign_fpr = None
    else:
        positive = matrix.sum() - matrix[benign_index].sum()
        benign_fpr = (
            float(matrix[benign_index].sum() - matrix[benign_index, benign_index])
            / float(positive)
            if positive
            else None
        )

    supports = {
        classes[i]: int(row_totals[i]) if row_totals[i] else 0
        for i in range(len(classes))
    }
    low_support = sorted(
        name for name, count in supports.items() if 0 < count < min_support
    )
    absent = sorted(name for name, count in supports.items() if count == 0)

    roc_curves: dict[str, Any] = {}
    pr_curves: dict[str, Any] = {}
    for index, name in enumerate(classes):
        if supports[name] < min_support:
            continue
        positive = (y_true == index).astype(int)
        if positive.sum() == 0 or positive.sum() == len(positive):
            continue
        score = y_proba[:, index]
        try:
            fpr, tpr, _ = roc_curve(positive, score)
            precision, recall, _ = precision_recall_curve(positive, score)
            roc_curves[name] = {
                "auc": float(roc_auc_score(positive, score)),
                "fpr": fpr.tolist(),
                "tpr": tpr.tolist(),
            }
            pr_curves[name] = {
                "average_precision": float(average_precision_score(positive, score)),
                "precision": precision.tolist(),
                "recall": recall.tolist(),
            }
        except ValueError:  # pragma: no cover - degenerate tiny fixture
            continue

    _plot_curves(
        roc_curves,
        output_dir / "roc_curves.png",
        "fpr",
        "tpr",
        "False positive rate",
        "True positive rate",
    )
    _plot_curves(
        pr_curves,
        output_dir / "precision_recall_curves.png",
        "recall",
        "precision",
        "Recall",
        "Precision",
    )
    _plot_confusion(
        matrix, classes, output_dir / "confusion_matrix.png", normalize=False
    )
    _plot_confusion(
        matrix, classes, output_dir / "confusion_matrix_normalized.png", normalize=True
    )

    row_sums = matrix.sum(axis=1, keepdims=True)
    normalized = np.divide(
        matrix, row_sums, out=np.zeros_like(matrix, dtype=float), where=row_sums != 0
    )
    metrics: dict[str, Any] = {
        "split": "test",
        "sample_count": len(y_true),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "macro_avg": report["macro avg"],
        "weighted_avg": report["weighted avg"],
        "per_class": {name: report[name] for name in classes if name in report},
        "confusion_matrix": {
            "labels": classes,
            "raw": matrix.tolist(),
            "normalized": normalized.tolist(),
        },
        "false_negative_rate": fnr,
        "benign_false_positive_rate": benign_fpr,
        "low_support_classes": low_support,
        "absent_classes": absent,
        "min_support_threshold": min_support,
        "roc_auc": {name: curve["auc"] for name, curve in roc_curves.items()},
        "average_precision": {
            name: curve["average_precision"] for name, curve in pr_curves.items()
        },
        "inference": {
            "batch_seconds": float(latency_seconds),
            "single_flow_seconds": float(single_flow_seconds),
            "throughput_flows_per_second": (
                float(len(y_true) / latency_seconds) if latency_seconds > 0 else None
            ),
        },
    }
    return metrics


def _plot_curves(
    curves: dict[str, Any],
    path: Path,
    x_key: str,
    y_key: str,
    x_label: str,
    y_label: str,
) -> None:
    figure, axis = plt.subplots(figsize=(7, 5))
    for name, curve in curves.items():
        axis.plot(curve[x_key], curve[y_key], label=name, linewidth=1.2)
    axis.set_xlabel(x_label)
    axis.set_ylabel(y_label)
    axis.set_xlim(0, 1)
    axis.set_ylim(0, 1)
    axis.grid(alpha=0.3)
    if curves:
        axis.legend(fontsize=7, loc="best")
    else:
        axis.text(0.5, 0.5, "No class met the minimum support threshold", ha="center")
    figure.tight_layout()
    figure.savefig(path, dpi=120)
    plt.close(figure)


def _plot_confusion(
    matrix: np.ndarray, classes: list[str], path: Path, *, normalize: bool
) -> None:
    figure, axis = plt.subplots(
        figsize=(max(7, len(classes)), max(6, len(classes) // 2))
    )
    values = matrix.astype(float)
    if normalize:
        totals = values.sum(axis=1, keepdims=True)
        values = np.divide(values, totals, out=np.zeros_like(values), where=totals != 0)
    image = axis.imshow(values, cmap="Blues")
    axis.set_xticks(range(len(classes)), classes, rotation=90, fontsize=6)
    axis.set_yticks(range(len(classes)), classes, fontsize=6)
    axis.set_xlabel("Predicted")
    axis.set_ylabel("Actual")
    figure.colorbar(image, ax=axis, fraction=0.046, pad=0.04)
    figure.tight_layout()
    figure.savefig(path, dpi=120)
    plt.close(figure)


def write_metrics(metrics: dict[str, Any], output_dir: Path) -> Path:
    path = output_dir / "metrics.json"
    path.write_text(
        json.dumps(metrics, indent=2, sort_keys=True, default=str), encoding="utf-8"
    )
    return path


def main(argv: list[str] | None = None) -> int:
    """Re-evaluate an already staged active model on its saved test split."""

    parser = argparse.ArgumentParser(description="Evaluate a staged model")
    parser.add_argument("--processed-dir", type=Path, required=True)
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Report directory; kept outside the checksum-sealed artifact tree",
    )
    args = parser.parse_args(argv)

    from ml.predict import load_artifacts_from_directory  # local import avoids cycles

    bundle = load_artifacts_from_directory(args.artifact_dir)
    payload = joblib_load_processed(args.processed_dir)
    indices = payload["split"].test
    features = payload["features"].iloc[indices]
    labels = payload["labels"].iloc[indices].to_numpy()
    scaled = bundle.scaler.transform(features.to_numpy(dtype="float64"))
    started = time.perf_counter()
    probabilities = bundle.model.predict_proba(scaled)
    batch_seconds = time.perf_counter() - started
    single_started = time.perf_counter()
    bundle.model.predict_proba(scaled[:1])
    single_seconds = time.perf_counter() - single_started
    metrics = evaluate_split(
        y_true=bundle.encoder.transform(labels),
        y_pred=probabilities.argmax(axis=1),
        y_proba=probabilities,
        classes=list(bundle.encoder.classes_),
        output_dir=args.output_dir,
        latency_seconds=batch_seconds,
        single_flow_seconds=single_seconds,
    )
    path = write_metrics(metrics, args.output_dir)
    logger.info("Wrote evaluation metrics to %s", path)
    return 0


def joblib_load_processed(processed_dir: Path) -> dict[str, Any]:
    import joblib

    from ml.preprocess import SplitIndices

    return {
        **joblib.load(processed_dir / "dataset.joblib"),
        "split": SplitIndices.from_json(
            json.loads(
                (processed_dir / "split_indices.json").read_text(encoding="utf-8")
            )
        ),
    }


if __name__ == "__main__":
    raise SystemExit(main())

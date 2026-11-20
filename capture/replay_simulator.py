"""Held-out test-split replay generator for the Phase 5 pipeline.

Only indices in ``split_indices.json['test']`` are ever streamed. Training and
validation rows are never read by this simulator, and every generated event is
explicitly tagged ``SIMULATION`` with its canonical ground-truth label.
"""

from __future__ import annotations

import json
import math
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
from redis import Redis

from capture.flow_meter import NO_PORT_VARIANT
from core.config import settings
from core.events import SIMULATION_TAG, RawFlowEvent, new_event_id, utc_now
from core.logging import get_logger
from core.streams import BackpressureError, producer_from_settings
from ml.registry import store
from ml.registry.paths import registry_root, version_directory
from ml.schema import features_for_variant

logger = get_logger(__name__)

DEFAULT_DATASET_DIR = (
    Path(__file__).resolve().parents[1] / "artifacts" / "processed" / "cicids-80k"
)


@dataclass(frozen=True)
class ReplayRow:
    """One held-out test row with its canonical ground-truth label."""

    source_index: int
    features: dict[str, float]
    source_label: str


def saved_active_feature_names() -> list[str]:
    """Read and return the active model's saved ordered feature list."""

    version = store.active_version(registry_root())
    if version is None:
        raise RuntimeError(
            "no active model is configured; replay cannot select features"
        )
    features_path = (
        version_directory(version, registry_root(), area="active") / "features.json"
    )
    contract = json.loads(features_path.read_text(encoding="utf-8"))
    names = [str(name) for name in contract["features"]]
    if names != list(features_for_variant(NO_PORT_VARIANT)):
        raise RuntimeError(
            "active model is not the expected 77-feature no-port contract"
        )
    return names


def read_test_indices(dataset_dir: Path | str = DEFAULT_DATASET_DIR) -> list[int]:
    """Return only the held-out TEST indices, rejecting split overlap."""

    path = Path(dataset_dir) / "split_indices.json"
    splits = json.loads(path.read_text(encoding="utf-8"))
    test = [int(index) for index in splits["test"]]
    train = {int(index) for index in splits["train"]}
    validation = {int(index) for index in splits["validation"]}
    if not test or set(test) & (train | validation):
        raise ValueError("invalid split file: test indices overlap another split")
    return test


def load_test_rows(
    dataset_dir: Path | str = DEFAULT_DATASET_DIR,
    *,
    limit: int | None = None,
) -> Iterator[ReplayRow]:
    """Yield held-out test rows using only the saved active feature list."""

    if limit is not None and limit <= 0:
        raise ValueError("limit must be positive or None")

    feature_names = saved_active_feature_names()
    indices = read_test_indices(dataset_dir)
    if limit is not None:
        indices = indices[:limit]
    bundle = joblib.load(Path(dataset_dir) / "dataset.joblib")
    features = bundle["features"]
    labels = bundle["labels"]
    for name in feature_names:
        if name not in features.columns:
            raise ValueError(f"processed bundle is missing saved feature {name!r}")

    for index in indices:
        row = features.iloc[index]
        values: dict[str, float] = {}
        for name in feature_names:
            value = float(row[name])
            values[name] = value if math.isfinite(value) else 0.0
        yield ReplayRow(
            source_index=int(index),
            features=values,
            source_label=str(labels.iloc[index]),
        )


def simulated_event(row: ReplayRow) -> RawFlowEvent:
    """Build a strictly labeled simulation event from one test row."""

    index = row.source_index
    return RawFlowEvent(
        event_id=new_event_id("sim-flow", seed=str(index)),
        timestamp=utc_now(),
        source="simulation",
        tags=[SIMULATION_TAG],
        flow_id=f"sim-test-{index}",
        src_ip=f"198.51.100.{1 + index % 254}",
        src_port=49152 + index % 16384,
        dst_ip=f"203.0.113.{1 + (index // 254) % 254}",
        dst_port=443,
        protocol="TCP",
        features=dict(row.features),  # exact saved order, no Destination Port
        source_label=row.source_label,
        source_index=index,
    )


def run_simulator(
    speed: float = 10.0,
    loop: bool = False,
    publisher: Any | None = None,
    dataset_dir: Path | str = DEFAULT_DATASET_DIR,
    limit: int | None = None,
    stop_event: threading.Event | None = None,
) -> int:
    """Stream test rows through the publisher at ``speed`` flows/second.

    Returns the number of successfully published events.
    """

    if speed <= 0:
        raise ValueError("simulation speed must be positive flows/second")
    stop = stop_event or threading.Event()
    if publisher is None:
        publisher = producer_from_settings(
            Redis.from_url(settings.get_redis_url()),
            stream=settings.STREAM_RAW_FLOWS,
            dead_letter_stream=settings.STREAM_DEAD_LETTER,
            consumer_name="simulation-publisher",
        )
        owns_publisher = True
    else:
        owns_publisher = False

    interval = 1.0 / speed
    published = 0
    skipped = 0
    try:
        while not stop.is_set():
            for row in load_test_rows(dataset_dir, limit=limit):
                if stop.is_set():
                    break
                started = time.perf_counter()
                try:
                    publisher.publish(simulated_event(row))
                except BackpressureError as exc:
                    skipped += 1
                    logger.warning(
                        "Simulation publish blocked by backpressure: %s", exc
                    )
                else:
                    published += 1
                if interval:
                    remaining = interval - (time.perf_counter() - started)
                    if remaining > 0:
                        stop.wait(remaining)
            if not loop:
                break
    finally:
        if owns_publisher:
            close = getattr(publisher.client, "close", None)
            if close is not None:
                close()
    logger.info(
        "Simulation finished: published=%d skipped=%d speed=%.2f flows/s loop=%s",
        published,
        skipped,
        speed,
        loop,
    )
    return published

"""Unit tests for the held-out replay simulator.

The dataset is a tiny temporary joblib bundle; the active model registry is the
real one on disk and is only read through ``saved_active_feature_names()``.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

import joblib
import pandas as pd
import pytest

from capture.replay_simulator import (
    ReplayRow,
    load_test_rows,
    read_test_indices,
    run_simulator,
    saved_active_feature_names,
    simulated_event,
)
from core.events import SIMULATION_TAG
from core.streams import BackpressureError

_EXPECTED_LABELS = {3: "BENIGN", 4: "DDoS", 5: "BENIGN"}
_SPLITS: dict[str, list[int]] = {"train": [0, 1], "validation": [2], "test": [3, 4, 5]}


@pytest.fixture
def replay_dataset(tmp_path: Path) -> Path:
    feature_names = saved_active_feature_names()
    columns = [*feature_names, "Destination Port"]
    data = {
        name: [float(index + offset) for index in range(6)]
        for offset, name in enumerate(columns)
    }
    bundle = {
        "features": pd.DataFrame(data, columns=columns),
        "labels": pd.Series(
            ["BENIGN", "BENIGN", "BENIGN", "BENIGN", "DDoS", "BENIGN"], name="Label"
        ),
    }
    joblib.dump(bundle, tmp_path / "dataset.joblib")
    (tmp_path / "split_indices.json").write_text(json.dumps(_SPLITS), encoding="utf-8")
    return tmp_path


class FakePublisher:
    """Collect published events and optionally simulate stream backpressure."""

    def __init__(self, *, fail_on: int | None = None) -> None:
        self.events: list[Any] = []
        self.fail_on = fail_on

    def publish(self, event: Any) -> None:
        if self.fail_on is not None and event.source_index == self.fail_on:
            raise BackpressureError("fake stream is full")
        self.events.append(event)


def test_saved_active_feature_names_are_the_no_port_contract() -> None:
    saved = saved_active_feature_names()
    assert len(saved) == 77
    assert "Destination Port" not in saved
    assert saved[0] == "Flow Duration"
    assert saved[-1] == "Idle Min"


def test_load_test_rows_uses_only_held_out_test_indices(replay_dataset: Path) -> None:
    saved = saved_active_feature_names()
    rows = list(load_test_rows(replay_dataset))

    assert [row.source_index for row in rows] == _SPLITS["test"]
    for row in rows:
        assert row.source_index in _SPLITS["test"]
        assert row.source_index not in _SPLITS["train"]
        assert row.source_index not in _SPLITS["validation"]
        assert row.source_label == _EXPECTED_LABELS[row.source_index]
        assert list(row.features.keys()) == saved
        assert "Destination Port" not in row.features
        assert all(math.isfinite(value) for value in row.features.values())

    # Values come from the dataset row, not from train/validation neighbours.
    assert rows[0].features["Flow Duration"] == 3.0
    assert rows[1].features["Flow Duration"] == 4.0
    assert rows[2].features["Flow Duration"] == 5.0


def test_load_test_rows_limit_and_invalid_splits(replay_dataset: Path) -> None:
    assert [row.source_index for row in load_test_rows(replay_dataset, limit=2)] == [
        3,
        4,
    ]
    with pytest.raises(ValueError, match="limit must be positive"):
        list(load_test_rows(replay_dataset, limit=0))

    overlapping = replay_dataset / "overlap"
    overlapping.mkdir()
    (overlapping / "split_indices.json").write_text(
        json.dumps({"train": [0], "validation": [3], "test": [3, 4]}), encoding="utf-8"
    )
    with pytest.raises(ValueError, match="overlap"):
        read_test_indices(overlapping)


def test_simulated_event_is_explicitly_labeled(replay_dataset: Path) -> None:
    row: ReplayRow = next(iter(load_test_rows(replay_dataset)))
    event = simulated_event(row)

    assert event.event_type == "raw_flow"
    assert event.source == "simulation"
    assert SIMULATION_TAG in event.tags
    assert event.source_index == row.source_index
    assert event.source_label == row.source_label
    assert event.flow_id == f"sim-test-{row.source_index}"
    assert event.features == row.features
    assert list(event.features.keys()) == list(row.features.keys())
    assert "Destination Port" not in event.features


def test_run_simulator_publishes_each_test_row_once(replay_dataset: Path) -> None:
    publisher = FakePublisher()

    published = run_simulator(
        speed=100_000.0, loop=False, publisher=publisher, dataset_dir=replay_dataset
    )

    assert published == 3
    assert [event.source_index for event in publisher.events] == [3, 4, 5]
    assert [event.source_label for event in publisher.events] == [
        "BENIGN",
        "DDoS",
        "BENIGN",
    ]
    for event in publisher.events:
        assert event.source == "simulation"
        assert SIMULATION_TAG in event.tags


def test_run_simulator_honors_limit(replay_dataset: Path) -> None:
    publisher = FakePublisher()

    published = run_simulator(
        speed=100_000.0, publisher=publisher, dataset_dir=replay_dataset, limit=2
    )

    assert published == 2
    assert [event.source_index for event in publisher.events] == [3, 4]


def test_run_simulator_skips_backpressure_errors(replay_dataset: Path) -> None:
    publisher = FakePublisher(fail_on=4)

    published = run_simulator(
        speed=100_000.0, publisher=publisher, dataset_dir=replay_dataset
    )

    assert published == 2
    assert [event.source_index for event in publisher.events] == [3, 5]
    assert all(SIMULATION_TAG in event.tags for event in publisher.events)


def test_run_simulator_rejects_nonpositive_speed(replay_dataset: Path) -> None:
    with pytest.raises(ValueError, match="speed must be positive"):
        run_simulator(speed=0.0, publisher=FakePublisher(), dataset_dir=replay_dataset)

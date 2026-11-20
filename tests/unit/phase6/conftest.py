"""Shared Phase 6 test helpers using only SQLite and in-memory fakes."""

from __future__ import annotations

import itertools
import json
from datetime import UTC, datetime
from typing import Any

import pytest

from core.events import SIMULATION_TAG, PreventionCandidateEvent, utc_now
from core.models.detection import Detection
from core.models.network import NetworkFlow


@pytest.fixture
def make_detection(db_session):
    """Create a persisted flow/detection pair for alert and engine tests."""

    sequence = itertools.count(1)

    def _make(
        *,
        src_ip: str = "45.33.32.156",
        label: str = "PortScan",
        confidence: float = 0.96,
        detection_id: int | None = None,
    ) -> tuple[NetworkFlow, Detection]:
        index = next(sequence)
        flow = NetworkFlow(
            flow_id=f"phase6-flow-{index}",
            timestamp=utc_now(),
            src_ip=src_ip,
            src_port=50000 + index,
            dst_ip="104.16.1.10",
            dst_port=443,
            protocol="TCP",
            features_json=json.dumps({}),
        )
        db_session.add(flow)
        db_session.flush()
        detection = Detection(
            flow_id=int(flow.id),
            predicted_label=label,
            is_malicious=True,
            confidence_score=confidence,
            is_anomaly=False,
            anomaly_score=0.1,
            model_version="cicids-80k-no-port",
        )
        if detection_id is not None:
            detection.id = detection_id
        db_session.add(detection)
        db_session.flush()
        return flow, detection

    return _make


@pytest.fixture
def candidate_payload() -> Any:
    """Return a factory for valid simulated prevention candidate events."""

    sequence = itertools.count(1)

    def _make(
        *,
        src_ip: str = "45.33.32.156",
        label: str = "PortScan",
        confidence: float = 0.96,
        detection_id: int | None = None,
        rare_class_flag: bool = False,
        at: datetime | None = None,
    ) -> dict[str, Any]:
        index = next(sequence)
        return PreventionCandidateEvent(
            event_id=f"phase6-candidate-event-{index}",
            candidate_id=f"phase6-candidate-{index}",
            detection_event_id=f"phase6-detection-event-{index}",
            detection_id=detection_id,
            flow_id=f"phase6-flow-{index}",
            src_ip=src_ip,
            dst_ip="104.16.1.10",
            dst_port=443,
            model_version="cicids-80k-no-port",
            predicted_label=label,
            verdict="known attack",
            confidence_score=confidence,
            prevention_confidence_threshold=0.85,
            rare_class_flag=rare_class_flag,
            source="simulation",
            tags=[SIMULATION_TAG],
            timestamp=at or datetime.now(UTC),
        ).model_dump(mode="json")

    return _make

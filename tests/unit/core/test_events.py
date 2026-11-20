"""Strict transport-contract tests for Phase 5 Redis-stream events."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from core.events import (
    SIMULATION_TAG,
    DetectionEvent,
    PreventionCandidateEvent,
    RawFlowEvent,
    utc_now,
)


def _raw_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "event_id": "flow-1",
        "timestamp": utc_now(),
        "source": "live",
        "flow_id": "flow-1",
        "src_ip": "198.51.100.10",
        "src_port": 49152,
        "dst_ip": "203.0.113.10",
        "dst_port": 443,
        "protocol": "TCP",
        "features": {"Flow Duration": 1.0, "Total Fwd Packets": 2.0},
    }
    payload.update(overrides)
    return payload


def _detection_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "event_id": "detection-1",
        "timestamp": utc_now(),
        "source": "live",
        "flow_id": "flow-1",
        "model_version": "cicids-80k-no-port",
        "predicted_label": "BENIGN",
        "verdict": "benign",
        "confidence_score": 0.95,
        "anomaly_score": 0.1,
        "is_malicious": False,
        "is_anomaly": False,
        "inference_latency_ms": 1.25,
        "queue_lag_ms": 2.5,
    }
    payload.update(overrides)
    return payload


def _candidate_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "event_id": "candidate-event-1",
        "timestamp": utc_now(),
        "source": "live",
        "flow_id": "flow-1",
        "candidate_id": "candidate-1",
        "detection_event_id": "detection-1",
        "src_ip": "198.51.100.10",
        "dst_ip": "203.0.113.10",
        "dst_port": 443,
        "model_version": "cicids-80k-no-port",
        "predicted_label": "DDoS",
        "verdict": "known attack",
        "confidence_score": 0.99,
        "prevention_confidence_threshold": 0.85,
    }
    payload.update(overrides)
    return payload


def test_raw_flow_event_rejects_extra_fields() -> None:
    payload = _raw_payload()
    payload["unexpected_operator_field"] = "mass-assignment"

    with pytest.raises(ValidationError) as excinfo:
        RawFlowEvent.model_validate(payload)

    assert "extra_forbidden" in str(excinfo.value)


@pytest.mark.parametrize("bad_value", [float("nan"), float("inf"), float("-inf")])
def test_raw_flow_event_rejects_nonfinite_features(bad_value: float) -> None:
    payload = _raw_payload(
        features={"Flow Duration": bad_value, "Total Fwd Packets": 2.0}
    )

    with pytest.raises(ValidationError, match="finite"):
        RawFlowEvent.model_validate(payload)


def test_raw_flow_event_rejects_simulation_source_without_simulation_tag() -> None:
    with pytest.raises(ValidationError, match="SIMULATION"):
        RawFlowEvent.model_validate(_raw_payload(source="simulation"))

    valid = RawFlowEvent.model_validate(
        _raw_payload(source="simulation", tags=[SIMULATION_TAG, SIMULATION_TAG])
    )
    assert valid.tags == [SIMULATION_TAG]


@pytest.mark.parametrize("verdict", ["known attack", "benign", "anomaly", "uncertain"])
def test_detection_event_accepts_all_four_verdicts(verdict: str) -> None:
    event = DetectionEvent.model_validate(_detection_payload(verdict=verdict))

    assert event.verdict == verdict
    assert event.model_version == "cicids-80k-no-port"


def test_prevention_candidate_is_always_dry_run_and_non_blocking() -> None:
    event = PreventionCandidateEvent.model_validate(_candidate_payload())

    assert event.blocking_candidate is False
    assert event.firewall_action == "dry_run"

    with pytest.raises(ValidationError):
        PreventionCandidateEvent.model_validate(
            _candidate_payload(blocking_candidate=True)
        )
    with pytest.raises(ValidationError):
        PreventionCandidateEvent.model_validate(
            _candidate_payload(firewall_action="active")
        )


def test_simulation_candidate_carries_simulation_tag() -> None:
    with pytest.raises(ValidationError, match="SIMULATION"):
        PreventionCandidateEvent.model_validate(_candidate_payload(source="simulation"))

    event = PreventionCandidateEvent.model_validate(
        _candidate_payload(source="simulation", tags=[SIMULATION_TAG])
    )

    assert event.simulation is True
    assert SIMULATION_TAG in event.tags
    assert event.blocking_candidate is False
    assert event.firewall_action == "dry_run"

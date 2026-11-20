"""Strict Redis-stream event schemas for the Phase 5 defensive pipeline.

These are transport contracts only. ``extra="forbid"`` prevents accidental
mass-assignment, and every simulation event must carry the visible
``SIMULATION`` tag so no downstream consumer can mistake replayed rows for
live traffic.
"""

from __future__ import annotations

import math
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SIMULATION_TAG = "SIMULATION"
SCHEMA_VERSION: Literal["1.0"] = "1.0"

Verdict = Literal["known attack", "benign", "anomaly", "uncertain"]
EventSource = Literal["live", "simulation"]


class EventModel(BaseModel):
    """Base class that rejects unknown fields and trims string inputs."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    event_id: str = Field(min_length=1, max_length=128)
    event_type: str
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    timestamp: datetime
    source: EventSource
    tags: list[str] = Field(default_factory=list)

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, values: list[str]) -> list[str]:
        if any(not value.strip() for value in values):
            raise ValueError("event tags must be non-empty strings")
        return list(dict.fromkeys(values))

    @model_validator(mode="after")
    def enforce_simulation_tag(self) -> EventModel:
        if self.source == "simulation" and SIMULATION_TAG not in self.tags:
            raise ValueError("simulation events must carry the SIMULATION tag")
        return self

    def to_stream_fields(self) -> dict[str, str]:
        """Serialize this event into a single Redis stream field."""

        import json

        return {"event": json.dumps(self.model_dump(mode="json"), sort_keys=True)}


class RawFlowEvent(EventModel):
    """One bidirectional flow published by the sensor to ``raw-flows``."""

    event_type: Literal["raw_flow"] = "raw_flow"
    flow_id: str = Field(min_length=1, max_length=128)
    src_ip: str = Field(min_length=1, max_length=45)
    src_port: int = Field(ge=0, le=65535)
    dst_ip: str = Field(min_length=1, max_length=45)
    dst_port: int = Field(ge=0, le=65535)
    protocol: str = Field(min_length=1, max_length=16)
    features: dict[str, float]
    source_label: str | None = None
    source_index: int | None = Field(default=None, ge=0)
    expired_reason: str | None = None
    # Explicit operator flag required before a rare/low-support class can be
    # considered as a future blocking candidate.
    allow_rare_class_candidate: bool = False

    @field_validator("features")
    @classmethod
    def validate_features(cls, values: dict[str, float]) -> dict[str, float]:
        if not values:
            raise ValueError("a flow event must contain model features")
        for name, value in values.items():
            if not name.strip():
                raise ValueError("feature names must be non-empty")
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise TypeError(f"feature {name!r} must be numeric")
            if not math.isfinite(float(value)):
                raise ValueError(f"feature {name!r} must be finite")
        return {name: float(value) for name, value in values.items()}


class DetectionEvent(EventModel):
    """Detection result published to the detections stream."""

    event_type: Literal["detection"] = "detection"
    flow_id: str = Field(min_length=1, max_length=128)
    model_version: str = Field(min_length=1, max_length=32)
    predicted_label: str = Field(min_length=1, max_length=64)
    verdict: Verdict
    confidence_score: float = Field(ge=0.0, le=1.0)
    anomaly_score: float = Field(ge=0.0, le=1.0)
    is_malicious: bool
    is_anomaly: bool
    inference_latency_ms: float = Field(ge=0.0)
    queue_lag_ms: float = Field(ge=0.0)
    top_features: list[tuple[str, float]] = Field(default_factory=list)
    source_label: str | None = None
    rare_class_flag: bool = False
    low_confidence_flag: bool = False
    allow_rare_class_candidate: bool = False
    detection_id: int | None = None


class PreventionCandidateEvent(EventModel):
    """Dry-run candidate for the future Phase 6 prevention engine.

    ``blocking_candidate`` is always False in Phase 5. The event records what
    a later engine may evaluate; it does not change any firewall state.
    """

    event_type: Literal["prevention_candidate"] = "prevention_candidate"
    candidate_id: str = Field(min_length=1, max_length=128)
    detection_event_id: str = Field(min_length=1, max_length=128)
    detection_id: int | None = Field(default=None, ge=1)
    flow_id: str = Field(min_length=1, max_length=128)
    src_ip: str = Field(min_length=1, max_length=45)
    dst_ip: str = Field(min_length=1, max_length=45)
    dst_port: int = Field(ge=0, le=65535)
    model_version: str = Field(min_length=1, max_length=32)
    predicted_label: str = Field(min_length=1, max_length=64)
    verdict: Verdict
    confidence_score: float = Field(ge=0.0, le=1.0)
    prevention_confidence_threshold: float = Field(ge=0.5, le=1.0)
    rare_class_flag: bool = False
    requires_manual_review: bool = False
    blocking_candidate: Literal[False] = False
    firewall_action: Literal["dry_run"] = "dry_run"
    simulation: bool = True
    source_label: str | None = None


class DeadLetterEvent(EventModel):
    """Wrapper written to a dead-letter stream after retry exhaustion."""

    event_type: Literal["dead_letter"] = "dead_letter"
    original_event_id: str = Field(min_length=1, max_length=128)
    original_event_type: str = Field(min_length=1, max_length=64)
    stream: str = Field(min_length=1, max_length=128)
    consumer_group: str = Field(min_length=1, max_length=128)
    attempts: int = Field(ge=1)
    error: str = Field(min_length=1, max_length=2000)
    payload: dict[str, Any]


def new_event_id(prefix: str, *, seed: str) -> str:
    """Create a short deterministic event id from stable identity fields."""

    import hashlib

    digest = hashlib.sha256(f"{prefix}|{seed}".encode()).hexdigest()[:20]
    return f"{prefix}-{digest}"


def utc_now() -> datetime:
    """Return an aware UTC timestamp for event creation."""

    return datetime.now(UTC)

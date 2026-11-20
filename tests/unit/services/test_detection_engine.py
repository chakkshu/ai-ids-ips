"""End-to-end Phase 5 detection tests with the real active model and fakeredis."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import fakeredis
import pytest

import core.models  # noqa: F401 - registers ORM tables for the SQLite test DB
from capture.replay_simulator import load_test_rows, simulated_event
from core.config import settings
from core.db import get_db_session
from core.events import SIMULATION_TAG, PreventionCandidateEvent, RawFlowEvent
from core.models.detection import Detection
from core.streams import RedisStreamIO, StreamConsumer, StreamLimits
from ml.predict import ModelCache, Prediction
from ml.registry import store
from ml.registry.paths import registry_root, version_directory
from services.detection_engine import DetectionEngine

ACTIVE_VERSION = "cicids-80k-no-port"
KNOWN_VERDICTS = {"known attack", "benign", "anomaly", "uncertain"}
RARE_CLASSES = ("Heartbleed", "Infiltration", "Web Attack - SQL Injection")


@pytest.fixture(scope="module", autouse=True)
def _active_model_artifacts_unchanged() -> Any:
    """Guard the active pointer and saved feature contract across this module."""

    root = registry_root()
    version = store.active_version(root)
    assert version == ACTIVE_VERSION

    paths = {
        "active.json": root / store.ACTIVE_POINTER,
        "features.json": version_directory(version, root, area="active")
        / "features.json",
    }
    before = {name: path.read_bytes() for name, path in paths.items()}
    yield
    after = {name: path.read_bytes() for name, path in paths.items()}
    assert after == before


@pytest.fixture(scope="module")
def held_out_event() -> RawFlowEvent:
    """Build one strictly tagged simulation event from a held-out test row."""

    row = next(load_test_rows(limit=1))
    return simulated_event(row)


@pytest.fixture
def stream_client() -> Any:
    fake = fakeredis.FakeRedis(decode_responses=True)
    try:
        yield fake
    finally:
        fake.flushall()
        fake.close()


@pytest.fixture
def pipeline(stream_client: Any) -> Any:
    limits = StreamLimits(
        maxlen=100,
        max_pending=50,
        retry_limit=3,
        batch_size=10,
        block_ms=0,
    )
    detections = RedisStreamIO(
        stream_client,
        "detections:stream",
        "detection-publisher",
        "detection-publisher",
        dead_letter_stream="detections:stream:dead-letter",
        limits=limits,
    )
    prevention = RedisStreamIO(
        stream_client,
        "prevention:action",
        "prevention-publisher",
        "prevention-publisher",
        dead_letter_stream="prevention:action:dead-letter",
        limits=limits,
    )
    engine = DetectionEngine(
        cache=ModelCache(),
        detections_stream=detections,
        prevention_stream=prevention,
    )
    return SimpleNamespace(
        client=stream_client,
        detections=detections,
        prevention=prevention,
        engine=engine,
    )


def _events(client: Any, stream: str) -> list[dict[str, Any]]:
    return [
        json.loads(fields["event"]) for _message_id, fields in client.xrange(stream)
    ]


def _force_prediction(
    monkeypatch: Any,
    pipeline: Any,
    event: RawFlowEvent,
    *,
    label: str,
    verdict: str = "known attack",
    confidence: float = 0.99,
) -> Prediction:
    """Override only the prediction result of the real, verified bundle."""

    bundle = pipeline.engine.cache.get()
    template = bundle.predict_single(event.features)
    forced = Prediction(
        predicted_class=label,
        confidence=confidence,
        top_probabilities=((label, confidence),),
        anomaly_score=template.anomaly_score,
        verdict=verdict,
        top_features=template.top_features,
    )
    monkeypatch.setattr(bundle, "predict_single", lambda _features, **_kwargs: forced)
    return forced


def test_real_active_model_persists_detection_and_emits_tagged_events(
    pipeline: Any, held_out_event: RawFlowEvent
) -> None:
    result = pipeline.engine.process_event(held_out_event.model_dump(mode="json"))

    assert result.model_version == ACTIVE_VERSION
    assert result.verdict in KNOWN_VERDICTS
    assert result.source == "simulation"
    assert SIMULATION_TAG in result.tags

    with get_db_session() as session:
        rows = session.query(Detection).all()
        assert len(rows) == 1
        row = rows[0]
        assert row.model_version == ACTIVE_VERSION
        assert row.predicted_label == result.predicted_label
        assert row.confidence_score == pytest.approx(result.confidence_score)
        assert row.is_malicious == result.is_malicious
        assert row.is_anomaly == result.is_anomaly
        assert row.flow is not None
        assert row.flow.flow_id == held_out_event.flow_id

    detection_events = _events(pipeline.client, pipeline.detections.stream)
    prevention_events = _events(pipeline.client, pipeline.prevention.stream)
    assert pipeline.detections.stream_length() == 1
    assert len(detection_events) == 1
    assert detection_events[0]["event_id"] == result.event_id
    assert detection_events[0]["model_version"] == ACTIVE_VERSION
    assert detection_events[0]["verdict"] in KNOWN_VERDICTS

    expected_candidates = int(
        result.verdict == "known attack"
        and not result.low_confidence_flag
        and not result.rare_class_flag
        and result.confidence_score >= settings.PREVENTION_CONFIDENCE_THRESHOLD
    )
    assert pipeline.prevention.stream_length() == expected_candidates
    assert len(prevention_events) == expected_candidates

    emitted = [*detection_events, *prevention_events]
    assert emitted
    assert all(event["source"] == "simulation" for event in emitted)
    assert all(SIMULATION_TAG in event["tags"] for event in emitted)
    for candidate in prevention_events:
        assert candidate["blocking_candidate"] is False
        assert candidate["firewall_action"] == "dry_run"


def test_confident_known_attack_emits_dry_run_candidate(
    monkeypatch: Any, pipeline: Any, held_out_event: RawFlowEvent
) -> None:
    _force_prediction(
        monkeypatch, pipeline, held_out_event, label="DDoS", verdict="known attack"
    )

    result = pipeline.engine.process_event(held_out_event.model_dump(mode="json"))

    assert result.verdict == "known attack"
    detection_events = _events(pipeline.client, pipeline.detections.stream)
    prevention_events = _events(pipeline.client, pipeline.prevention.stream)
    assert len(detection_events) == 1
    assert len(prevention_events) == 1

    candidate = PreventionCandidateEvent.model_validate(prevention_events[0])
    assert candidate.model_version == ACTIVE_VERSION
    assert candidate.verdict == "known attack"
    assert candidate.blocking_candidate is False
    assert candidate.firewall_action == "dry_run"
    assert candidate.simulation is True
    assert SIMULATION_TAG in candidate.tags
    assert candidate.rare_class_flag is False
    assert candidate.requires_manual_review is False

    emitted = [*detection_events, prevention_events[0]]
    assert all(SIMULATION_TAG in event["tags"] for event in emitted)
    assert pipeline.engine.metrics.candidates == 1


@pytest.mark.parametrize("violation", ["extra_destination_port", "missing_feature"])
def test_feature_contract_violations_are_rejected(
    pipeline: Any, held_out_event: RawFlowEvent, violation: str
) -> None:
    payload = held_out_event.model_dump(mode="json")
    features = dict(payload["features"])
    if violation == "extra_destination_port":
        features["Destination Port"] = 443.0
    else:
        features.pop(next(iter(features)))
    payload["features"] = features

    with pytest.raises(ValueError, match="feature contract"):
        pipeline.engine.process_event(payload)

    with get_db_session() as session:
        assert session.query(Detection).count() == 0
    assert pipeline.detections.stream_length() == 0
    assert pipeline.prevention.stream_length() == 0


@pytest.mark.parametrize("rare_label", RARE_CLASSES)
def test_rare_class_candidates_require_explicit_operator_flag(
    monkeypatch: Any,
    pipeline: Any,
    held_out_event: RawFlowEvent,
    rare_label: str,
) -> None:
    low_support = pipeline.engine.low_support_classes(ACTIVE_VERSION)
    assert rare_label in low_support

    _force_prediction(
        monkeypatch,
        pipeline,
        held_out_event,
        label=rare_label,
        verdict="known attack",
        confidence=0.99,
    )

    blocked = pipeline.engine.process_event(held_out_event.model_dump(mode="json"))
    assert blocked.verdict == "known attack"
    assert blocked.rare_class_flag is True
    assert blocked.allow_rare_class_candidate is False
    assert pipeline.prevention.stream_length() == 0
    assert pipeline.engine.metrics.rare_blocked == 1

    allowed_payload = held_out_event.model_dump(mode="json")
    allowed_payload["event_id"] = f"{held_out_event.event_id}-allowed"
    allowed_payload["flow_id"] = f"{held_out_event.flow_id}-allowed"
    allowed_payload["allow_rare_class_candidate"] = True
    allowed = pipeline.engine.process_event(allowed_payload)

    assert allowed.verdict == "known attack"
    assert allowed.rare_class_flag is True
    assert allowed.allow_rare_class_candidate is True
    assert pipeline.detections.stream_length() == 2
    assert pipeline.prevention.stream_length() == 1

    candidate = PreventionCandidateEvent.model_validate(
        _events(pipeline.client, pipeline.prevention.stream)[0]
    )
    assert candidate.rare_class_flag is True
    assert candidate.requires_manual_review is True
    assert candidate.blocking_candidate is False
    assert candidate.firewall_action == "dry_run"
    assert candidate.simulation is True
    assert SIMULATION_TAG in candidate.tags

    emitted = [
        *_events(pipeline.client, pipeline.detections.stream),
        candidate.model_dump(mode="json"),
    ]
    assert all(SIMULATION_TAG in event["tags"] for event in emitted)


def test_batch_results_match_single_flow_results_on_same_rows(pipeline: Any) -> None:
    rows = [*load_test_rows(limit=3)]
    payloads = [simulated_event(row).model_dump(mode="json") for row in rows]

    singles = [pipeline.engine.process_event(payload) for payload in payloads]
    batched = pipeline.engine.process_events(payloads)

    assert len(batched) == len(singles)
    for single, batch in zip(singles, batched):
        assert not isinstance(batch, BaseException)
        assert batch.predicted_label == single.predicted_label
        assert batch.verdict == single.verdict
        assert batch.confidence_score == pytest.approx(single.confidence_score)
        assert batch.anomaly_score == pytest.approx(single.anomaly_score)
        assert [name for name, _ in batch.top_features] == [
            name for name, _ in single.top_features
        ]
        assert [value for _, value in batch.top_features] == pytest.approx(
            [value for _, value in single.top_features]
        )
        assert batch.detection_id == single.detection_id


def test_batch_dead_letters_one_bad_flow_without_dropping_valid_flows(
    pipeline: Any, held_out_event: RawFlowEvent
) -> None:
    consumer = StreamConsumer(
        pipeline.client,
        "raw-flows",
        "test-batch-group",
        "test-batch-consumer",
        dead_letter_stream="raw-flows:dead-letter",
        limits=StreamLimits(
            maxlen=100, max_pending=50, retry_limit=3, batch_size=10, block_ms=0
        ),
    )
    good_payload = held_out_event.model_dump(mode="json")
    other_payload = held_out_event.model_dump(mode="json")
    other_payload["event_id"] = f"{held_out_event.event_id}-other"
    other_payload["flow_id"] = f"{held_out_event.flow_id}-other"
    bad_payload = held_out_event.model_dump(mode="json")
    bad_payload["event_id"] = f"{held_out_event.event_id}-bad"
    bad_payload["features"] = {
        **bad_payload["features"],
        "Destination Port": 443.0,
    }

    for payload in (good_payload, bad_payload, other_payload):
        consumer.publish(payload)

    reports = [
        consumer.process_batch(pipeline.engine.handle_batch, block_ms=0)
        for _ in range(3)
    ]

    assert [report.processed for report in reports] == [2, 0, 0]
    assert [report.retried for report in reports] == [1, 1, 0]
    assert [report.dead_lettered for report in reports] == [0, 0, 1]
    assert consumer.pending_count() == 0
    assert pipeline.detections.stream_length() == 2

    with get_db_session() as session:
        assert session.query(Detection).count() == 2

    dead_entries = pipeline.client.xrange(consumer.dead_letter_stream)
    assert len(dead_entries) == 1
    dead_letter = json.loads(dead_entries[0][1]["event"])
    assert dead_letter["original_event_id"] == bad_payload["event_id"]
    assert "feature contract violation" in dead_letter["error"]

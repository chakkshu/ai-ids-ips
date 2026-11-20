"""Detection engine consumer for the Phase 5 defensive pipeline.

The engine loads only the verified active model through ``ml.predict``,
rejects any feature-contract violation, stores a ``Detection`` row, and emits
explicitly dry-run candidates. It never touches a firewall.
"""

from __future__ import annotations

import json
import statistics
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from core.config import settings
from core.events import (
    SIMULATION_TAG,
    DetectionEvent,
    EventModel,
    PreventionCandidateEvent,
    RawFlowEvent,
    new_event_id,
    utc_now,
)
from core.logging import get_logger
from core.models.detection import Detection
from core.models.network import NetworkFlow
from core.streams import BackpressureError, RedisStreamIO
from ml.predict import ModelCache
from ml.registry import store
from ml.registry.paths import registry_root, version_directory

logger = get_logger(__name__)

SessionFactory = Callable[[], Any]


def _aware_timestamp(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


def load_low_support_classes(
    version: str | None = None, root: Path | str | None = None
) -> frozenset[str]:
    """Read low-support classes from the active model's saved metrics."""

    resolved = version or store.active_version(registry_root(root))
    if not resolved:
        raise RuntimeError("no active model version is configured")
    path = version_directory(resolved, root, area="active") / "metrics.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    return frozenset(str(label) for label in payload.get("low_support_classes", []))


@dataclass
class EngineMetrics:
    """In-process benchmark counters for the detection engine."""

    processed: int = 0
    malicious: int = 0
    anomalies: int = 0
    uncertain: int = 0
    candidates: int = 0
    rare_blocked: int = 0
    backpressure_drops: int = 0
    inference_latencies_ms: list[float] = field(default_factory=list)
    queue_lags_ms: list[float] = field(default_factory=list)

    def record(
        self,
        prediction: Any,
        *,
        latency_ms: float,
        queue_lag_ms: float,
        candidate_published: bool,
        rare_blocked: bool,
    ) -> None:
        self.processed += 1
        self.inference_latencies_ms.append(latency_ms)
        self.queue_lags_ms.append(queue_lag_ms)
        if prediction.verdict == "known attack":
            self.malicious += 1
        elif prediction.verdict == "anomaly":
            self.anomalies += 1
        elif prediction.verdict == "uncertain":
            self.uncertain += 1
        self.candidates += int(candidate_published)
        self.rare_blocked += int(rare_blocked)

    @staticmethod
    def _percentile(values: list[float], fraction: float) -> float:
        if not values:
            return 0.0
        ordered = sorted(values)
        position = min(len(ordered) - 1, int(fraction * (len(ordered) - 1)))
        return float(ordered[position])

    def summary(self) -> dict[str, float | int]:
        latencies = self.inference_latencies_ms
        lags = self.queue_lags_ms
        return {
            "processed": self.processed,
            "malicious": self.malicious,
            "anomalies": self.anomalies,
            "uncertain": self.uncertain,
            "candidates": self.candidates,
            "rare_blocked": self.rare_blocked,
            "backpressure_drops": self.backpressure_drops,
            "inference_latency_mean_ms": (
                statistics.fmean(latencies) if latencies else 0.0
            ),
            "inference_latency_p50_ms": self._percentile(latencies, 0.50),
            "inference_latency_p95_ms": self._percentile(latencies, 0.95),
            "queue_lag_mean_ms": statistics.fmean(lags) if lags else 0.0,
            "queue_lag_p95_ms": self._percentile(lags, 0.95),
        }


class DetectionEngine:
    """Consume raw-flow events and persist/emit inference results."""

    def __init__(
        self,
        *,
        cache: ModelCache | None = None,
        session_factory: SessionFactory | None = None,
        detections_stream: RedisStreamIO | None = None,
        prevention_stream: RedisStreamIO | None = None,
        registry_root_path: Path | str | None = None,
    ) -> None:
        self.cache = cache or ModelCache()
        self.session_factory = session_factory or self._default_session_factory
        self.detections_stream = detections_stream
        self.prevention_stream = prevention_stream
        self.registry_root_path = registry_root_path
        self.metrics = EngineMetrics()
        self._low_support_cache: frozenset[str] | None = None

    @staticmethod
    @contextmanager
    def _default_session_factory() -> Iterator[Any]:
        from core.db import get_db_session

        with get_db_session() as session:
            yield session

    def low_support_classes(self, version: str) -> frozenset[str]:
        if self._low_support_cache is None:
            self._low_support_cache = load_low_support_classes(
                version, self.registry_root_path
            )
        return self._low_support_cache

    def handle(self, payload: dict[str, Any], _message_id: str) -> None:
        """StreamConsumer callback; exceptions trigger retry/dead-letter."""

        self.process_event(payload)

    def handle_batch(
        self, items: Sequence[tuple[dict[str, Any], str]]
    ) -> dict[str, BaseException | None]:
        """Batch callback for :class:`StreamConsumer.process_batch`.

        Each payload is validated independently. Valid payloads share one model
        batch call and one database commit; errors are returned per message id
        so the stream helper can retry or dead-letter only the failed event.
        """

        results = self.process_events([payload for payload, _ in items])
        if len(results) != len(items):
            raise RuntimeError(
                f"batch result count {len(results)} does not match {len(items)}"
            )
        return {
            message_id: result if isinstance(result, BaseException) else None
            for (_, message_id), result in zip(items, results)
        }

    def process_events(
        self, payloads: Sequence[dict[str, Any]]
    ) -> list[DetectionEvent | BaseException]:
        """Process a stream batch while isolating per-event failures."""

        if not payloads:
            return []

        bundle = self.cache.get()
        expected = list(bundle.feature_names)
        rare_classes = self.low_support_classes(bundle.version)
        prepared: list[tuple[int, RawFlowEvent, dict[str, float]]] = []
        failures: dict[int, BaseException] = {}

        for index, payload in enumerate(payloads):
            try:
                event = RawFlowEvent.model_validate(payload)
                missing = [name for name in expected if name not in event.features]
                extra = [name for name in event.features if name not in expected]
                if missing or extra:
                    raise ValueError(
                        "feature contract violation: "
                        f"missing={missing}, extra={extra}, expected={expected}"
                    )
                features = {name: float(event.features[name]) for name in expected}
            except Exception as exc:  # noqa: BLE001 - per-event dead-letter boundary
                failures[index] = exc
            else:
                prepared.append((index, event, features))

        successes: dict[int, DetectionEvent] = {}
        if prepared:
            started = time.perf_counter()
            try:
                predictions = bundle.predict_batch(
                    [features for _, _, features in prepared], top_k=3
                )
                if len(predictions) != len(prepared):
                    raise RuntimeError(
                        "model batch returned an unexpected number of predictions"
                    )
            except Exception as exc:  # noqa: BLE001 - batch inference boundary
                for index, _, _ in prepared:
                    failures[index] = exc
                predictions = []
            else:
                batch_latency_ms = (
                    (time.perf_counter() - started) * 1000.0 / len(prepared)
                )

            if predictions:
                persistence_inputs: list[
                    tuple[RawFlowEvent, Any, Mapping[str, float], float, str]
                ] = []
                metadata: list[tuple[int, RawFlowEvent, Any, float, bool, bool]] = []
                for (index, event, features), prediction in zip(prepared, predictions):
                    queue_lag_ms = max(
                        (utc_now() - _aware_timestamp(event.timestamp)).total_seconds()
                        * 1000.0,
                        0.0,
                    )
                    rare_flag = prediction.predicted_class in rare_classes
                    low_confidence = (
                        prediction.verdict == "uncertain"
                        or prediction.confidence < bundle.confidence_threshold
                    )
                    persistence_inputs.append(
                        (event, prediction, features, batch_latency_ms, bundle.version)
                    )
                    metadata.append(
                        (
                            index,
                            event,
                            prediction,
                            queue_lag_ms,
                            rare_flag,
                            low_confidence,
                        )
                    )

                try:
                    detection_ids = self._persist_batch(persistence_inputs)
                    if len(detection_ids) != len(metadata):
                        raise RuntimeError(
                            "batch persistence returned an unexpected row count"
                        )
                except Exception as exc:  # noqa: BLE001 - batch DB boundary
                    for index, _, _ in prepared:
                        failures[index] = exc
                else:
                    for detection_id, (
                        index,
                        event,
                        prediction,
                        queue_lag_ms,
                        rare_flag,
                        low_confidence,
                    ) in zip(detection_ids, metadata):
                        detection_event = DetectionEvent(
                            event_id=new_event_id(
                                "detection",
                                seed=f"{event.event_id}:{bundle.version}",
                            ),
                            timestamp=utc_now(),
                            source=event.source,
                            tags=list(event.tags),
                            flow_id=event.flow_id,
                            model_version=bundle.version,
                            predicted_label=prediction.predicted_class,
                            verdict=prediction.verdict,  # type: ignore[arg-type]
                            confidence_score=float(prediction.confidence),
                            anomaly_score=float(prediction.anomaly_score),
                            is_malicious=prediction.verdict == "known attack",
                            is_anomaly=prediction.verdict == "anomaly",
                            inference_latency_ms=batch_latency_ms,
                            queue_lag_ms=queue_lag_ms,
                            top_features=[
                                (name, float(value))
                                for name, value in prediction.top_features
                            ],
                            source_label=event.source_label,
                            rare_class_flag=rare_flag,
                            low_confidence_flag=low_confidence,
                            allow_rare_class_candidate=event.allow_rare_class_candidate,
                            detection_id=detection_id,
                        )
                        try:
                            self._publish(
                                detection_event, self.detections_stream, "detection"
                            )
                            candidate_published = False
                            rare_blocked = False
                            if self._qualifies_for_candidate(
                                event, prediction, low_confidence, rare_flag
                            ):
                                candidate = self._build_candidate(
                                    event, detection_event, prediction, rare_flag
                                )
                                self._publish(
                                    candidate,
                                    self.prevention_stream,
                                    "prevention candidate",
                                )
                                candidate_published = True
                            elif (
                                rare_flag
                                and not event.allow_rare_class_candidate
                                and prediction.verdict == "known attack"
                            ):
                                rare_blocked = True
                                logger.warning(
                                    "Rare-class prediction %r was not promoted: "
                                    "explicit flag required",
                                    prediction.predicted_class,
                                )
                        except Exception as exc:  # noqa: BLE001 - publish boundary
                            failures[index] = exc
                            continue

                        successes[index] = detection_event
                        self.metrics.record(
                            prediction,
                            latency_ms=batch_latency_ms,
                            queue_lag_ms=queue_lag_ms,
                            candidate_published=candidate_published,
                            rare_blocked=rare_blocked,
                        )

        results: list[DetectionEvent | BaseException] = []
        for index in range(len(payloads)):
            if index in failures:
                results.append(failures[index])
            elif index in successes:
                results.append(successes[index])
            else:
                results.append(
                    RuntimeError(f"payload at position {index} was not processed")
                )
        return results

    def process_event(self, payload: dict[str, Any]) -> DetectionEvent:
        """Validate, infer, persist and publish one raw-flow event."""

        event = RawFlowEvent.model_validate(payload)
        bundle = self.cache.get()
        expected = list(bundle.feature_names)
        missing = [name for name in expected if name not in event.features]
        extra = [name for name in event.features if name not in expected]
        if missing or extra:
            raise ValueError(
                "feature contract violation: "
                f"missing={missing}, extra={extra}, expected={expected}"
            )
        features = {name: float(event.features[name]) for name in expected}

        started = time.perf_counter()
        prediction = bundle.predict_single(features)
        latency_ms = (time.perf_counter() - started) * 1000.0

        queue_lag_ms = max(
            (utc_now() - _aware_timestamp(event.timestamp)).total_seconds() * 1000.0,
            0.0,
        )
        rare_classes = self.low_support_classes(bundle.version)
        rare_flag = prediction.predicted_class in rare_classes
        low_confidence = (
            prediction.verdict == "uncertain"
            or prediction.confidence < bundle.confidence_threshold
        )
        detection_id = self._persist(
            event, prediction, features, latency_ms, bundle.version
        )
        detection_event = DetectionEvent(
            event_id=new_event_id(
                "detection", seed=f"{event.event_id}:{bundle.version}"
            ),
            timestamp=utc_now(),
            source=event.source,
            tags=list(event.tags),
            flow_id=event.flow_id,
            model_version=bundle.version,
            predicted_label=prediction.predicted_class,
            verdict=prediction.verdict,  # type: ignore[arg-type]
            confidence_score=float(prediction.confidence),
            anomaly_score=float(prediction.anomaly_score),
            is_malicious=prediction.verdict == "known attack",
            is_anomaly=prediction.verdict == "anomaly",
            inference_latency_ms=latency_ms,
            queue_lag_ms=queue_lag_ms,
            top_features=[
                (name, float(value)) for name, value in prediction.top_features
            ],
            source_label=event.source_label,
            rare_class_flag=rare_flag,
            low_confidence_flag=low_confidence,
            allow_rare_class_candidate=event.allow_rare_class_candidate,
            detection_id=detection_id,
        )
        self._publish(detection_event, self.detections_stream, "detection")

        candidate_published = False
        rare_blocked = False
        if self._qualifies_for_candidate(event, prediction, low_confidence, rare_flag):
            candidate = self._build_candidate(
                event, detection_event, prediction, rare_flag
            )
            self._publish(candidate, self.prevention_stream, "prevention candidate")
            candidate_published = True
        elif (
            rare_flag
            and not event.allow_rare_class_candidate
            and (prediction.verdict == "known attack")
        ):
            rare_blocked = True
            logger.warning(
                "Rare-class prediction %r was not promoted: explicit flag required",
                prediction.predicted_class,
            )

        self.metrics.record(
            prediction,
            latency_ms=latency_ms,
            queue_lag_ms=queue_lag_ms,
            candidate_published=candidate_published,
            rare_blocked=rare_blocked,
        )
        return detection_event

    def _qualifies_for_candidate(
        self,
        event: RawFlowEvent,
        prediction: Any,
        low_confidence: bool,
        rare_flag: bool,
    ) -> bool:
        if low_confidence or prediction.verdict != "known attack":
            return False
        if prediction.confidence < settings.PREVENTION_CONFIDENCE_THRESHOLD:
            return False
        return not (rare_flag and not event.allow_rare_class_candidate)

    def _build_candidate(
        self,
        event: RawFlowEvent,
        detection_event: DetectionEvent,
        prediction: Any,
        rare_flag: bool,
    ) -> PreventionCandidateEvent:
        simulation = event.source == "simulation" or settings.is_simulation_mode()
        tags = list(event.tags)
        if simulation and SIMULATION_TAG not in tags:
            tags.append(SIMULATION_TAG)
        return PreventionCandidateEvent(
            event_id=new_event_id(
                "prevention-candidate", seed=detection_event.event_id
            ),
            timestamp=utc_now(),
            source=event.source,
            tags=tags,
            candidate_id=new_event_id(
                "candidate", seed=f"{event.flow_id}:{detection_event.event_id}"
            ),
            detection_event_id=detection_event.event_id,
            detection_id=detection_event.detection_id,
            flow_id=event.flow_id,
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            dst_port=event.dst_port,
            model_version=detection_event.model_version,
            predicted_label=prediction.predicted_class,
            verdict=prediction.verdict,  # type: ignore[arg-type]
            confidence_score=float(prediction.confidence),
            prevention_confidence_threshold=settings.PREVENTION_CONFIDENCE_THRESHOLD,
            rare_class_flag=rare_flag,
            requires_manual_review=rare_flag,
            simulation=simulation,
            source_label=event.source_label,
        )

    def _publish(
        self,
        event: EventModel,
        stream: RedisStreamIO | None,
        label: str,
    ) -> None:
        if stream is None:
            return
        try:
            stream.publish(event)
        except BackpressureError as exc:
            self.metrics.backpressure_drops += 1
            logger.warning("Dropped %s event under backpressure: %s", label, exc)

    def _persist(
        self,
        event: RawFlowEvent,
        prediction: Any,
        features: Mapping[str, float],
        latency_ms: float,
        model_version: str,
    ) -> int:
        return self._persist_batch(
            [(event, prediction, features, latency_ms, model_version)]
        )[0]

    def _persist_batch(
        self,
        entries: Sequence[tuple[RawFlowEvent, Any, Mapping[str, float], float, str]],
    ) -> list[int]:
        """Persist one stream batch in a single database transaction."""

        detection_ids: list[int] = []
        with self.session_factory() as session:
            for event, prediction, features, latency_ms, model_version in entries:
                detection_ids.append(
                    self._write_detection(
                        session,
                        event,
                        prediction,
                        features,
                        latency_ms,
                        model_version,
                    )
                )
        return detection_ids

    @staticmethod
    def _write_detection(
        session: Any,
        event: RawFlowEvent,
        prediction: Any,
        features: Mapping[str, float],
        latency_ms: float,
        model_version: str,
    ) -> int:
        timestamp = _aware_timestamp(event.timestamp)
        flow = (
            session.query(NetworkFlow)
            .filter(NetworkFlow.flow_id == event.flow_id)
            .order_by(NetworkFlow.id.desc())
            .first()
        )
        if flow is None:
            flow = NetworkFlow(flow_id=event.flow_id)
            session.add(flow)
        flow.timestamp = timestamp
        flow.src_ip = event.src_ip
        flow.src_port = event.src_port
        flow.dst_ip = event.dst_ip
        flow.dst_port = event.dst_port
        flow.protocol = event.protocol
        flow.duration = float(features.get("Flow Duration", 0.0))
        flow.total_fwd_packets = int(features.get("Total Fwd Packets", 0.0))
        flow.total_bwd_packets = int(features.get("Total Backward Packets", 0.0))
        flow.total_fwd_bytes = int(features.get("Total Length of Fwd Packets", 0.0))
        flow.total_bwd_bytes = int(features.get("Total Length of Bwd Packets", 0.0))
        flow.flow_bytes_per_sec = float(features.get("Flow Bytes/s", 0.0))
        flow.flow_packets_per_sec = float(features.get("Flow Packets/s", 0.0))
        flow.features_json = json.dumps(dict(features), sort_keys=True)
        session.flush()

        detection = (
            session.query(Detection).filter(Detection.flow_id == flow.id).first()
        )
        if detection is None:
            detection = Detection(flow_id=flow.id)
            session.add(detection)
        detection.timestamp = timestamp
        detection.predicted_label = prediction.predicted_class
        detection.is_malicious = prediction.verdict == "known attack"
        detection.confidence_score = float(prediction.confidence)
        detection.is_anomaly = prediction.verdict == "anomaly"
        detection.anomaly_score = float(prediction.anomaly_score)
        detection.top_features_json = json.dumps(
            [[name, float(value)] for name, value in prediction.top_features]
        )
        detection.model_version = model_version
        detection.inference_latency_ms = latency_ms
        session.flush()
        return int(detection.id)

"""Detection engine service package."""

from __future__ import annotations

import threading
from typing import Any

from core.config import settings
from core.logging import get_logger
from core.streams import consumer_from_settings, producer_from_settings

from .engine import DetectionEngine, EngineMetrics, load_low_support_classes

logger = get_logger(__name__)

__all__ = [
    "DetectionEngine",
    "EngineMetrics",
    "load_low_support_classes",
    "run_detection_engine",
]


def run_detection_engine(
    *,
    client: Any | None = None,
    engine: DetectionEngine | None = None,
    stop_event: threading.Event | None = None,
) -> dict[str, Any]:
    """Consume ``raw-flows`` until ``stop_event`` is set."""

    from redis import Redis

    owns_client = client is None
    client = client or Redis.from_url(settings.get_redis_url())
    stop = stop_event or threading.Event()
    if engine is None:
        engine = DetectionEngine(
            detections_stream=producer_from_settings(
                client,
                stream=settings.STREAM_DETECTIONS,
                dead_letter_stream=settings.STREAM_DETECTIONS_DEAD_LETTER,
                consumer_name="detection-publisher",
            ),
            prevention_stream=producer_from_settings(
                client,
                stream=settings.STREAM_PREVENTION,
                dead_letter_stream=settings.STREAM_DEAD_LETTER,
                consumer_name="prevention-publisher",
            ),
        )
    consumer = consumer_from_settings(
        client,
        stream=settings.STREAM_RAW_FLOWS,
        dead_letter_stream=settings.STREAM_DEAD_LETTER,
    )
    consumer.ensure_group()
    logger.info(
        "Detection engine started: stream=%s group=%s mode=%s",
        settings.STREAM_RAW_FLOWS,
        settings.STREAM_CONSUMER_GROUP,
        settings.get_capture_mode(),
    )
    try:
        while not stop.is_set():
            consumer.process(engine.handle)
    finally:
        if owns_client:
            close = getattr(client, "close", None)
            if close is not None:
                close()
    return engine.metrics.summary()

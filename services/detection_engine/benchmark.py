"""Local, honest benchmark for the Phase 5 in-process pipeline.

Runs held-out test rows through fakeredis and a temporary SQLite database with
the real active model. It does not start Docker Redis or change the registry.
"""

from __future__ import annotations

import os
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import psutil
from fakeredis import FakeRedis
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import core.models  # noqa: F401 - registers all ORM tables
from capture.replay_simulator import load_test_rows, simulated_event
from core.config import settings
from core.db import Base
from core.streams import StreamLimits, consumer_from_settings, producer_from_settings

from .engine import DetectionEngine


@contextmanager
def _temporary_sessions() -> Iterator[Any]:
    descriptor, path = tempfile.mkstemp(prefix="phase5_bench_", suffix=".sqlite3")
    os.close(descriptor)
    engine = create_engine(f"sqlite:///{Path(path).as_posix()}")
    Base.metadata.create_all(engine)
    maker = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    try:
        with maker() as session:
            yield session
            session.commit()
    finally:
        engine.dispose()
        try:
            os.unlink(path)
        except OSError:  # pragma: no cover - best-effort cleanup
            pass


def benchmark_pipeline(*, flows: int = 100) -> dict[str, Any]:
    """Publish and process ``flows`` held-out rows, returning real timings."""

    client = FakeRedis(decode_responses=True)
    limits = StreamLimits(
        maxlen=max(10_000, flows * 2),
        max_pending=max(512, flows * 2),
        retry_limit=settings.STREAM_MAX_ATTEMPTS,
        batch_size=32,
        block_ms=0,
    )
    raw = producer_from_settings(
        client,
        stream=settings.STREAM_RAW_FLOWS,
        dead_letter_stream=settings.STREAM_DEAD_LETTER,
        consumer_name="benchmark-publisher",
    )
    raw.limits = limits
    engine = DetectionEngine(
        session_factory=_temporary_sessions,
        detections_stream=producer_from_settings(
            client,
            stream=settings.STREAM_DETECTIONS,
            dead_letter_stream=settings.STREAM_DETECTIONS_DEAD_LETTER,
            consumer_name="benchmark-detection-publisher",
        ),
        prevention_stream=producer_from_settings(
            client,
            stream=settings.STREAM_PREVENTION,
            dead_letter_stream=settings.STREAM_DEAD_LETTER,
            consumer_name="benchmark-prevention-publisher",
        ),
    )
    for stream in (engine.detections_stream, engine.prevention_stream):
        if stream is not None:
            stream.limits = limits

    warmup_started = time.perf_counter()
    engine.cache.get()
    model_load_seconds = time.perf_counter() - warmup_started
    for row in load_test_rows(limit=flows):
        raw.publish(simulated_event(row))
    consumer = consumer_from_settings(
        client,
        stream=settings.STREAM_RAW_FLOWS,
        dead_letter_stream=settings.STREAM_DEAD_LETTER,
        consumer_name="benchmark-consumer",
    )
    consumer.limits = limits
    consumer.ensure_group()

    queue_backlog = raw.stream_length()
    started = time.perf_counter()
    while engine.metrics.processed < flows:
        before = engine.metrics.processed
        consumer.process(engine.handle, block_ms=0)
        if engine.metrics.processed == before and consumer.pending_count() == 0:
            break
    elapsed = max(time.perf_counter() - started, 1e-9)

    summary: dict[str, Any] = dict(engine.metrics.summary())
    summary["flows_requested"] = flows
    summary["queue_backlog_at_start"] = queue_backlog
    summary["throughput_flows_per_sec"] = flows / elapsed
    summary["elapsed_seconds"] = elapsed
    summary["cold_model_load_seconds"] = model_load_seconds
    summary["available_ram_gb"] = psutil.virtual_memory().available / 1024**3
    summary["redis_backend"] = "fakeredis"
    return summary

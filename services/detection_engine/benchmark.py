"""Local, honest benchmark for the Phase 5 in-process pipeline.

Runs held-out test rows through fakeredis and a temporary SQLite database with
the real active model. It does not start Docker Redis or change the registry.
"""

from __future__ import annotations

import os
import tempfile
import threading
import time
from collections.abc import Callable, Iterator
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
def _temporary_session_factory() -> Iterator[Callable[[], Any]]:
    """Create a temp SQLite DB once and yield a per-call session context."""

    descriptor, path = tempfile.mkstemp(prefix="phase5_bench_", suffix=".sqlite3")
    os.close(descriptor)
    engine = create_engine(f"sqlite:///{Path(path).as_posix()}")
    Base.metadata.create_all(engine)
    maker = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    @contextmanager
    def _session_scope() -> Iterator[Any]:
        with maker() as session:
            try:
                yield session
                session.commit()
            except Exception:
                session.rollback()
                raise

    try:
        yield _session_scope
    finally:
        engine.dispose()
        try:
            os.unlink(path)
        except OSError:  # pragma: no cover - best-effort cleanup
            pass


def benchmark_pipeline(*, flows: int = 100) -> dict[str, Any]:
    """Publish and process ``flows`` held-out rows, returning real timings."""

    with _temporary_session_factory() as session_factory:
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
            session_factory=session_factory,
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
            consumer.process_batch(engine.handle_batch, block_ms=0)
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
        summary["processing_mode"] = "batched"
        summary["stream_batch_size"] = limits.batch_size
        return summary


def benchmark_concurrent_queue_lag(
    *, flows: int = 200, rate_flows_per_sec: float = 20.0
) -> dict[str, Any]:
    """Measure queue lag with producer and consumer running concurrently."""

    if flows <= 0:
        raise ValueError("flows must be positive")
    if rate_flows_per_sec <= 0:
        raise ValueError("rate_flows_per_sec must be positive")

    with _temporary_session_factory() as session_factory:
        client = FakeRedis(decode_responses=True)
        limits = StreamLimits(
            maxlen=max(10_000, flows * 2),
            max_pending=max(512, flows * 2),
            retry_limit=settings.STREAM_MAX_ATTEMPTS,
            batch_size=32,
            block_ms=10,
        )
        raw = producer_from_settings(
            client,
            stream=settings.STREAM_RAW_FLOWS,
            dead_letter_stream=settings.STREAM_DEAD_LETTER,
            consumer_name="benchmark-lag-publisher",
        )
        raw.limits = limits
        engine = DetectionEngine(
            session_factory=session_factory,
            detections_stream=producer_from_settings(
                client,
                stream=settings.STREAM_DETECTIONS,
                dead_letter_stream=settings.STREAM_DETECTIONS_DEAD_LETTER,
                consumer_name="benchmark-lag-detection-publisher",
            ),
            prevention_stream=producer_from_settings(
                client,
                stream=settings.STREAM_PREVENTION,
                dead_letter_stream=settings.STREAM_DEAD_LETTER,
                consumer_name="benchmark-lag-prevention-publisher",
            ),
        )
        for stream in (engine.detections_stream, engine.prevention_stream):
            if stream is not None:
                stream.limits = limits

        engine.cache.get()  # Exclude cold model load from the lag measurement.
        consumer = consumer_from_settings(
            client,
            stream=settings.STREAM_RAW_FLOWS,
            dead_letter_stream=settings.STREAM_DEAD_LETTER,
            consumer_name="benchmark-lag-consumer",
        )
        consumer.limits = limits
        consumer.ensure_group()

        rows = list(load_test_rows(limit=flows))
        producer_done = threading.Event()
        stop_consumer = threading.Event()
        consumer_errors: list[BaseException] = []

        def _consume() -> None:
            try:
                while engine.metrics.processed < flows and not stop_consumer.is_set():
                    before = engine.metrics.processed
                    consumer.process_batch(
                        engine.handle_batch, block_ms=limits.block_ms
                    )
                    if (
                        engine.metrics.processed == before
                        and consumer.pending_count() == 0
                        and producer_done.is_set()
                    ):
                        break
            except BaseException as exc:  # noqa: BLE001 - report from worker thread
                consumer_errors.append(exc)

        consumer_thread = threading.Thread(
            target=_consume, name="benchmark-lag-consumer", daemon=True
        )
        consumer_started = time.perf_counter()
        consumer_thread.start()
        interval = 1.0 / rate_flows_per_sec
        producer_started = time.perf_counter()
        try:
            for row in rows:
                publish_started = time.perf_counter()
                raw.publish(simulated_event(row))
                remaining = interval - (time.perf_counter() - publish_started)
                if remaining > 0:
                    stop_consumer.wait(remaining)
        finally:
            producer_elapsed = max(time.perf_counter() - producer_started, 1e-9)
            producer_done.set()

        consumer_thread.join(timeout=60.0)
        if consumer_thread.is_alive():
            stop_consumer.set()
            consumer_thread.join(timeout=5.0)
        if consumer_errors:
            raise consumer_errors[0]

        consumer_elapsed = max(time.perf_counter() - consumer_started, 1e-9)
        summary: dict[str, Any] = dict(engine.metrics.summary())
        summary.update(
            {
                "flows_requested": flows,
                "rate_flows_per_sec": rate_flows_per_sec,
                "producer_elapsed_seconds": producer_elapsed,
                "consumer_elapsed_seconds": consumer_elapsed,
                "stream_length_at_end": raw.stream_length(),  # acks retain entries
                "available_ram_gb": psutil.virtual_memory().available / 1024**3,
                "redis_backend": "fakeredis",
                "producer_consumer_mode": "concurrent",
            }
        )
        return summary

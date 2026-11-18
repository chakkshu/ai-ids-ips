"""Lightweight memory sampling and a fail-safe guard for heavy ML jobs.

The guard is advisory between checkpoints: a daemon thread samples RSS and
system-wide available RAM, records every sample (optionally to a JSONL file),
logs breaches, and sets ``exceeded``. Long-running callers invoke
:meth:`MemoryGuard.check` at safe checkpoints so work stops before an OS-level
out-of-memory kill rather than aborting mid-write.

``psutil`` is an optional dependency here; if it is unavailable, monitoring is
silently disabled and ``check`` is a no-op.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Self

from core.logging import get_logger

logger = get_logger(__name__)


@dataclass(frozen=True)
class MemorySample:
    """One point-in-time memory observation."""

    total_gb: float
    available_gb: float
    percent_used: float
    process_rss_gb: float


def _import_psutil() -> Any | None:
    try:
        import psutil
    except ImportError:  # pragma: no cover - psutil is in requirements
        return None
    return psutil


def memory_snapshot() -> MemorySample | None:
    """Return a memory snapshot, or ``None`` when psutil is unavailable."""

    psutil = _import_psutil()
    if psutil is None:
        return None
    virtual = psutil.virtual_memory()
    process = psutil.Process()
    return MemorySample(
        total_gb=virtual.total / 1024**3,
        available_gb=virtual.available / 1024**3,
        percent_used=float(virtual.percent),
        process_rss_gb=process.memory_info().rss / 1024**3,
    )


class MemoryGuard:
    """Sample memory in the background and raise at caller checkpoints."""

    def __init__(
        self,
        *,
        min_available_gb: float = 0.5,
        max_process_rss_gb: float | None = None,
        interval_seconds: float = 15.0,
        label: str = "ml-job",
        log_path: Path | None = None,
    ) -> None:
        if min_available_gb < 0:
            raise ValueError("min_available_gb must be non-negative")
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be positive")
        self.min_available_gb = min_available_gb
        self.max_process_rss_gb = max_process_rss_gb
        self.interval_seconds = interval_seconds
        self.label = label
        self.log_path = Path(log_path) if log_path else None
        self.exceeded = False
        self.reason: str | None = None
        self.latest: MemorySample | None = None
        self.min_available_gb_seen: float | None = None
        self.max_process_rss_gb_seen: float | None = None
        self.sample_count = 0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    def start(self) -> Self:
        """Start the sampling thread and take an immediate baseline sample."""

        if self._thread is not None:
            return self
        self._sample()
        if memory_snapshot() is None:
            return self
        self._thread = threading.Thread(
            target=self._run, name=f"memory-guard-{self.label}", daemon=True
        )
        self._thread.start()
        return self

    def stop(self) -> None:
        """Stop the sampling thread and append a summary line; never raises."""

        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self.interval_seconds + 1)
            self._thread = None
        self._write(self.summary())

    def check(self) -> None:
        """Raise ``MemoryError`` if a prior sample breached a configured limit."""

        self._sample()
        if self.exceeded:
            raise MemoryError(f"memory guard triggered for {self.label}: {self.reason}")

    def summary(self) -> dict[str, Any]:
        """Return the observed memory extremes for this run."""

        return {
            "event": "summary",
            "label": self.label,
            "samples": self.sample_count,
            "min_available_gb": self.min_available_gb_seen,
            "max_process_rss_gb": self.max_process_rss_gb_seen,
            "threshold_available_gb": self.min_available_gb,
            "exceeded": self.exceeded,
            "reason": self.reason,
            "latest": self._as_dict(self.latest),
        }

    def __enter__(self) -> Self:
        return self.start()

    def __exit__(self, *_: object) -> None:
        self.stop()

    @staticmethod
    def _as_dict(sample: MemorySample | None) -> dict[str, float] | None:
        if sample is None:
            return None
        return {
            "total_gb": sample.total_gb,
            "available_gb": sample.available_gb,
            "percent_used": sample.percent_used,
            "process_rss_gb": sample.process_rss_gb,
        }

    def _write(self, payload: dict[str, Any]) -> None:
        if self.log_path is None:
            return
        payload = {**payload, "timestamp": datetime.now(UTC).isoformat()}
        with self._lock:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.log_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, sort_keys=True) + "\n")

    def _sample(self) -> None:
        sample = memory_snapshot()
        if sample is None:
            return
        with self._lock:
            self.latest = sample
            self.sample_count += 1
            self.min_available_gb_seen = (
                sample.available_gb
                if self.min_available_gb_seen is None
                else min(self.min_available_gb_seen, sample.available_gb)
            )
            self.max_process_rss_gb_seen = (
                sample.process_rss_gb
                if self.max_process_rss_gb_seen is None
                else max(self.max_process_rss_gb_seen, sample.process_rss_gb)
            )
            self._write(
                {
                    "event": "sample",
                    "label": self.label,
                    **self._as_dict(sample),  # type: ignore[dict-item]
                    "exceeded": self.exceeded,
                }
            )
            if sample.available_gb < self.min_available_gb:
                self.exceeded = True
                self.reason = (
                    f"available RAM {sample.available_gb:.2f} GB < "
                    f"{self.min_available_gb:.2f} GB minimum"
                )
            elif (
                self.max_process_rss_gb is not None
                and sample.process_rss_gb > self.max_process_rss_gb
            ):
                self.exceeded = True
                self.reason = (
                    f"process RSS {sample.process_rss_gb:.2f} GB > "
                    f"{self.max_process_rss_gb:.2f} GB maximum"
                )
            if self.exceeded:
                logger.warning(
                    "Memory guard (%s): %s; total=%.2f GB available=%.2f GB rss=%.2f GB",
                    self.label,
                    self.reason,
                    sample.total_gb,
                    sample.available_gb,
                    sample.process_rss_gb,
                )

    def _run(self) -> None:
        while not self._stop.wait(self.interval_seconds):
            self._sample()

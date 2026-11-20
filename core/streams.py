"""Small Redis Stream helper used by the Phase 5 sensor and detection engine.

The helper deliberately exposes only defensive primitives: publish, consumer
group creation, read, acknowledge, dead-letter, and backpressure checks. It is
usable with a real ``redis.Redis`` client or ``fakeredis.FakeRedis`` in tests.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from redis.exceptions import ResponseError

from core.events import (
    SIMULATION_TAG,
    DeadLetterEvent,
    EventModel,
    new_event_id,
    utc_now,
)


class StreamError(RuntimeError):
    """Base class for stream contract failures."""


class BackpressureError(StreamError):
    """Raised when a publisher would exceed configured stream limits."""


@dataclass(frozen=True)
class StreamLimits:
    """Backpressure and retry policy for one stream."""

    maxlen: int = 10_000
    max_pending: int = 512
    retry_limit: int = 3
    batch_size: int = 32
    block_ms: int = 1000


@dataclass(frozen=True)
class StreamMessage:
    """A decoded stream entry."""

    message_id: str
    payload: dict[str, Any]


@dataclass
class ProcessingReport:
    """Per-batch counters returned by :class:`StreamConsumer`."""

    processed: int = 0
    retried: int = 0
    dead_lettered: int = 0
    skipped: int = 0


def _as_text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _pending_count(result: Any) -> int:
    """Normalize the several shapes returned by ``XPENDING``."""

    if isinstance(result, Mapping):
        return int(result.get("pending", 0))
    if isinstance(result, (tuple, list)) and result:
        first = result[0]
        if isinstance(first, Mapping):
            return int(first.get("pending", 0))
        if isinstance(first, int):
            return first
    return 0


class RedisStreamIO:
    """Publish/read/acknowledge events on a Redis stream."""

    def __init__(
        self,
        client: Any,
        stream: str,
        consumer_group: str,
        consumer_name: str,
        *,
        dead_letter_stream: str,
        limits: StreamLimits | None = None,
    ) -> None:
        self.client = client
        self.stream = stream
        self.consumer_group = consumer_group
        self.consumer_name = consumer_name
        self.dead_letter_stream = dead_letter_stream
        self.limits = limits or StreamLimits()

    def ensure_group(self) -> None:
        """Create the consumer group once; ``BUSYGROUP`` is a valid no-op."""

        try:
            self.client.xgroup_create(
                self.stream, self.consumer_group, id="0-0", mkstream=True
            )
        except ResponseError as exc:
            if "BUSYGROUP" not in str(exc).upper():
                raise StreamError(f"could not create consumer group: {exc}") from exc

    def stream_length(self) -> int:
        return int(self.client.xlen(self.stream))

    def pending_count(self) -> int:
        try:
            result = self.client.xpending(self.stream, self.consumer_group)
        except ResponseError as exc:
            if "NOGROUP" in str(exc).upper():
                return 0
            raise
        return _pending_count(result)

    def ensure_capacity(self) -> None:
        """Reject publishes when stream length or pending work is too high."""

        if self.stream_length() >= self.limits.maxlen:
            raise BackpressureError(
                f"stream {self.stream!r} reached maxlen={self.limits.maxlen}"
            )
        if self.pending_count() >= self.limits.max_pending:
            raise BackpressureError(
                f"consumer group {self.consumer_group!r} reached "
                f"max_pending={self.limits.max_pending}"
            )

    def publish(self, event: EventModel | Mapping[str, Any]) -> str:
        """Append one validated event and apply stream retention/backpressure."""

        self.ensure_capacity()
        if isinstance(event, EventModel):
            fields = event.to_stream_fields()
        else:
            fields = {"event": json.dumps(dict(event), sort_keys=True, default=str)}
        message_id = self.client.xadd(
            self.stream,
            fields,
            maxlen=self.limits.maxlen,
            approximate=True,
        )
        return _as_text(message_id)

    def _read(
        self, marker: str, count: int, block_ms: int | None
    ) -> list[StreamMessage]:
        kwargs: dict[str, Any] = {
            "streams": {self.stream: marker},
            "count": count,
        }
        if block_ms is not None:
            kwargs["block"] = block_ms
        result = (
            self.client.xreadgroup(self.consumer_group, self.consumer_name, **kwargs)
            or []
        )
        messages: list[StreamMessage] = []
        for _stream, entries in result:
            for message_id, fields in entries:
                decoded = {
                    _as_text(key): _as_text(value) for key, value in fields.items()
                }
                raw = decoded.get("event")
                if raw is None:
                    messages.append(
                        StreamMessage(_as_text(message_id), {"__decode_error__": True})
                    )
                    continue
                try:
                    payload = json.loads(raw)
                except json.JSONDecodeError:
                    payload = {"__decode_error__": raw}
                messages.append(StreamMessage(_as_text(message_id), payload))
        return messages

    def read_new(
        self, *, count: int | None = None, block_ms: int | None = None
    ) -> list[StreamMessage]:
        """Read undelivered entries with ``>``."""

        return self._read(
            ">",
            count or self.limits.batch_size,
            self.limits.block_ms if block_ms is None else block_ms,
        )

    def read_pending(self, *, count: int | None = None) -> list[StreamMessage]:
        """Re-read this consumer's pending entries with ``0``."""

        return self._read("0", count or self.limits.batch_size, None)

    def ack(self, message_id: str) -> int:
        return int(self.client.xack(self.stream, self.consumer_group, message_id))

    def dead_letter(
        self,
        message: StreamMessage,
        exc: BaseException,
        attempts: int,
    ) -> str:
        """Wrap a failed event in a dead-letter event and publish it."""

        payload = message.payload if isinstance(message.payload, dict) else {}
        tags = list(payload.get("tags") or [])
        if payload.get("source") == "simulation" and SIMULATION_TAG not in tags:
            tags.append(SIMULATION_TAG)
        dead_letter = DeadLetterEvent(
            event_id=new_event_id("dlq", seed=f"{self.stream}:{message.message_id}"),
            event_type="dead_letter",
            timestamp=utc_now(),
            source=str(payload.get("source", "live")),  # type: ignore[arg-type]
            tags=tags,
            original_event_id=str(
                payload.get("event_id", f"stream:{message.message_id}")
            ),
            original_event_type=str(payload.get("event_type", "unknown")),
            stream=self.stream,
            consumer_group=self.consumer_group,
            attempts=attempts,
            error=f"{type(exc).__name__}: {exc}"[:2000],
            payload=payload,
        )
        message_id = self.client.xadd(
            self.dead_letter_stream,
            dead_letter.to_stream_fields(),
            maxlen=self.limits.maxlen,
            approximate=True,
        )
        return _as_text(message_id)


class StreamConsumer(RedisStreamIO):
    """Consumer-group reader with retries and dead-letter escalation."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._attempts: dict[str, int] = {}

    def process(
        self,
        handler: Callable[[dict[str, Any], str], None],
        *,
        block_ms: int | None = None,
    ) -> ProcessingReport:
        """Process new and pending messages, acking successes only."""

        self.ensure_group()
        report = ProcessingReport()
        seen: set[str] = set()
        messages = [*self.read_new(block_ms=block_ms), *self.read_pending()]
        for message in messages:
            if message.message_id in seen:
                report.skipped += 1
                continue
            seen.add(message.message_id)
            try:
                handler(message.payload, message.message_id)
            except Exception as exc:  # noqa: BLE001 - dead-letter boundary
                attempts = self._attempts.get(message.message_id, 0) + 1
                self._attempts[message.message_id] = attempts
                if attempts >= self.limits.retry_limit:
                    self.dead_letter(message, exc, attempts)
                    self.ack(message.message_id)
                    self._attempts.pop(message.message_id, None)
                    report.dead_lettered += 1
                else:
                    report.retried += 1
            else:
                self.ack(message.message_id)
                self._attempts.pop(message.message_id, None)
                report.processed += 1
        return report


def consumer_from_settings(
    client: Any,
    *,
    stream: str,
    dead_letter_stream: str,
    consumer_name: str | None = None,
) -> StreamConsumer:
    """Build a consumer using Phase 1 stream settings."""

    from core.config import settings

    return StreamConsumer(
        client,
        stream,
        settings.STREAM_CONSUMER_GROUP,
        consumer_name or settings.STREAM_CONSUMER_NAME,
        dead_letter_stream=dead_letter_stream,
        limits=StreamLimits(
            maxlen=settings.STREAM_MAXLEN,
            max_pending=settings.STREAM_MAX_PENDING,
            retry_limit=settings.STREAM_MAX_ATTEMPTS,
            batch_size=settings.STREAM_BATCH_SIZE,
            block_ms=settings.STREAM_BLOCK_MS,
        ),
    )


def producer_from_settings(
    client: Any,
    *,
    stream: str,
    dead_letter_stream: str,
    consumer_name: str | None = None,
) -> RedisStreamIO:
    """Build a producer using Phase 1 stream settings."""

    from core.config import settings

    return RedisStreamIO(
        client,
        stream,
        settings.STREAM_CONSUMER_GROUP,
        consumer_name or settings.STREAM_CONSUMER_NAME,
        dead_letter_stream=dead_letter_stream,
        limits=StreamLimits(
            maxlen=settings.STREAM_MAXLEN,
            max_pending=settings.STREAM_MAX_PENDING,
            retry_limit=settings.STREAM_MAX_ATTEMPTS,
            batch_size=settings.STREAM_BATCH_SIZE,
            block_ms=settings.STREAM_BLOCK_MS,
        ),
    )

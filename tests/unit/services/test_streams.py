"""fakeredis-backed unit tests for the Redis stream helpers."""

from __future__ import annotations

import json
from typing import Any

import fakeredis
import pytest

from core.events import DeadLetterEvent, RawFlowEvent, utc_now
from core.streams import (
    BackpressureError,
    RedisStreamIO,
    StreamConsumer,
    StreamLimits,
)


@pytest.fixture
def client() -> Any:
    fake = fakeredis.FakeRedis(decode_responses=True)
    try:
        yield fake
    finally:
        fake.flushall()
        fake.close()


def _stream_io(
    client: Any,
    *,
    stream: str = "test-flows",
    limits: StreamLimits | None = None,
    consumer_group: str = "test-group",
    consumer_name: str = "test-consumer",
) -> RedisStreamIO:
    return RedisStreamIO(
        client,
        stream,
        consumer_group,
        consumer_name,
        dead_letter_stream=f"{stream}:dead-letter",
        limits=limits or StreamLimits(batch_size=4, block_ms=0),
    )


def _raw_event(event_id: str = "flow-1") -> RawFlowEvent:
    return RawFlowEvent(
        event_id=event_id,
        timestamp=utc_now(),
        source="live",
        flow_id=event_id,
        src_ip="198.51.100.10",
        src_port=49152,
        dst_ip="203.0.113.10",
        dst_port=443,
        protocol="TCP",
        features={"Flow Duration": 1.0, "Total Fwd Packets": 2.0},
    )


def test_ensure_group_is_idempotent(client: Any) -> None:
    io = _stream_io(client)

    io.ensure_group()
    io.ensure_group()

    groups = client.xinfo_groups(io.stream)
    assert len(groups) == 1
    assert groups[0]["name"] == io.consumer_group


def test_publish_adds_json_event_and_read_pending_ack_work(client: Any) -> None:
    io = _stream_io(client)
    event = _raw_event()

    message_id = io.publish(event)

    assert io.stream_length() == 1
    entries = client.xrange(io.stream)
    assert len(entries) == 1
    assert entries[0][0] == message_id
    assert json.loads(entries[0][1]["event"])["event_id"] == event.event_id

    io.ensure_group()
    new_messages = io.read_new(block_ms=0)
    assert [message.payload["event_id"] for message in new_messages] == [event.event_id]
    assert io.pending_count() == 1

    pending = io.read_pending()
    assert [message.message_id for message in pending] == [message_id]
    assert [message.payload["flow_id"] for message in pending] == [event.flow_id]

    assert io.ack(message_id) == 1
    assert io.pending_count() == 0


def test_consumer_acks_successfully_handled_messages(client: Any) -> None:
    consumer = StreamConsumer(
        client,
        "test-flows",
        "test-group",
        "test-consumer",
        dead_letter_stream="test-flows:dead-letter",
        limits=StreamLimits(batch_size=4, block_ms=0),
    )
    consumer.publish(_raw_event())
    handled: list[str] = []

    report = consumer.process(
        lambda payload, _message_id: handled.append(payload["event_id"]),
        block_ms=0,
    )

    assert report.processed == 1
    assert report.retried == 0
    assert report.dead_lettered == 0
    assert handled == ["flow-1"]
    assert consumer.pending_count() == 0


def test_consumer_process_batch_keeps_per_message_outcomes(client: Any) -> None:
    consumer = StreamConsumer(
        client,
        "test-flows",
        "test-group",
        "test-consumer",
        dead_letter_stream="test-flows:dead-letter",
        limits=StreamLimits(batch_size=4, block_ms=0),
    )
    for event_id in ("flow-1", "flow-2", "flow-3"):
        consumer.publish(_raw_event(event_id))

    def handler(
        items: list[tuple[dict[str, Any], str]],
    ) -> dict[str, BaseException | None]:
        return {
            message_id: (
                RuntimeError("bad flow") if payload["event_id"] == "flow-2" else None
            )
            for payload, message_id in items
        }

    report = consumer.process_batch(handler, block_ms=0)

    assert report.processed == 2
    assert report.retried == 1
    assert report.dead_lettered == 0
    assert consumer.pending_count() == 1


def test_consumer_retries_then_dead_letters_and_acks_original(client: Any) -> None:
    retry_limit = 3
    consumer = StreamConsumer(
        client,
        "test-flows",
        "test-group",
        "test-consumer",
        dead_letter_stream="test-flows:dead-letter",
        limits=StreamLimits(retry_limit=retry_limit, batch_size=4, block_ms=0),
    )
    event = _raw_event("flow-failing")

    consumer.publish(event)

    def failing_handler(_payload: dict[str, Any], _message_id: str) -> None:
        raise RuntimeError("boom")

    reports = [
        consumer.process(failing_handler, block_ms=0) for _ in range(retry_limit)
    ]

    assert [report.retried for report in reports] == [1, 1, 0]
    assert reports[-1].dead_lettered == 1
    assert consumer.pending_count() == 0

    dead_entries = client.xrange(consumer.dead_letter_stream)
    assert len(dead_entries) == 1
    dead_letter = DeadLetterEvent.model_validate(
        json.loads(dead_entries[0][1]["event"])
    )
    assert dead_letter.attempts == retry_limit
    assert "RuntimeError: boom" in dead_letter.error
    assert dead_letter.original_event_id == event.event_id
    assert dead_letter.stream == consumer.stream
    assert dead_letter.consumer_group == consumer.consumer_group


def test_backpressure_when_stream_length_reaches_maxlen(client: Any) -> None:
    io = _stream_io(
        client,
        limits=StreamLimits(maxlen=1, max_pending=10, batch_size=4, block_ms=0),
    )
    io.publish(_raw_event("flow-1"))

    with pytest.raises(BackpressureError, match="maxlen"):
        io.publish(_raw_event("flow-2"))


def test_backpressure_when_pending_reaches_max_pending(client: Any) -> None:
    io = _stream_io(
        client,
        limits=StreamLimits(maxlen=100, max_pending=1, batch_size=4, block_ms=0),
    )
    io.publish(_raw_event("flow-1"))
    io.ensure_group()
    assert len(io.read_new(block_ms=0)) == 1
    assert io.pending_count() == 1

    with pytest.raises(BackpressureError, match="max_pending"):
        io.publish(_raw_event("flow-2"))

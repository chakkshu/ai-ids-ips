"""Real Redis Stream integration tests for Phase 5 stream semantics.

Skipped unless ``AI_IDS_TEST_REDIS_URL`` is set and the server answers PING.
The test keys are fixed and deleted before/after each test; no Docker or Redis
process is started by the test suite.
"""

from __future__ import annotations

import os
from typing import Any

import pytest
from redis import Redis

from core.events import RawFlowEvent, utc_now
from core.streams import (
    BackpressureError,
    StreamConsumer,
    StreamLimits,
)

_TEST_REDIS_URL = os.environ.get("AI_IDS_TEST_REDIS_URL")
_STREAM = "integration:raw-flows"
_DEAD_LETTER = "integration:raw-flows:dead-letter"
_GROUP = "integration-group"
_CONSUMER = "integration-consumer"
_KEYS = (_STREAM, _DEAD_LETTER)


def _redis_available() -> bool:
    if not _TEST_REDIS_URL:
        return False
    client: Redis | None = None
    try:
        client = Redis.from_url(_TEST_REDIS_URL, socket_connect_timeout=0.5)
        client.ping()
    except Exception:  # noqa: BLE001 - skip on any connectivity failure
        return False
    finally:
        if client is not None:
            close = getattr(client, "close", None)
            if close is not None:
                close()
    return True


pytestmark = pytest.mark.skipif(
    not _redis_available(),
    reason="real Redis requires AI_IDS_TEST_REDIS_URL and a reachable server",
)


@pytest.fixture
def redis_client() -> Any:
    assert _TEST_REDIS_URL is not None
    client = Redis.from_url(_TEST_REDIS_URL, decode_responses=True)
    client.delete(*_KEYS)
    try:
        yield client
    finally:
        client.delete(*_KEYS)
        client.close()


def _consumer(client: Any) -> StreamConsumer:
    return StreamConsumer(
        client,
        _STREAM,
        _GROUP,
        _CONSUMER,
        dead_letter_stream=_DEAD_LETTER,
        limits=StreamLimits(retry_limit=3, batch_size=10, block_ms=0),
    )


def _event(event_id: str) -> RawFlowEvent:
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


def test_real_redis_consumer_group_and_batch_acks(redis_client: Any) -> None:
    consumer = _consumer(redis_client)
    for event_id in ("flow-1", "flow-2", "flow-3"):
        consumer.publish(_event(event_id))

    consumer.ensure_group()
    consumer.ensure_group()
    report = consumer.process_batch(
        lambda items: {message_id: None for _, message_id in items}, block_ms=0
    )

    assert report.processed == 3
    assert report.retried == 0
    assert consumer.pending_count() == 0
    groups = redis_client.xinfo_groups(_STREAM)
    assert [group["name"] for group in groups] == [_GROUP]


def test_real_redis_retries_then_dead_letters_one_event(redis_client: Any) -> None:
    consumer = _consumer(redis_client)
    consumer.publish(_event("bad-flow"))

    def always_fail(items: Any) -> dict[str, BaseException | None]:
        return {message_id: RuntimeError("boom") for _, message_id in items}

    reports = [consumer.process_batch(always_fail, block_ms=0) for _ in range(3)]

    assert [report.retried for report in reports] == [1, 1, 0]
    assert reports[-1].dead_lettered == 1
    assert consumer.pending_count() == 0
    assert redis_client.xlen(_DEAD_LETTER) == 1


def test_real_redis_backpressure_on_stream_length(redis_client: Any) -> None:
    consumer = _consumer(redis_client)
    consumer.limits = StreamLimits(
        maxlen=2, max_pending=10, retry_limit=3, batch_size=10, block_ms=0
    )
    consumer.publish(_event("flow-1"))
    consumer.publish(_event("flow-2"))

    with pytest.raises(BackpressureError, match="maxlen"):
        consumer.publish(_event("flow-3"))

"""Raw-flow Redis stream publisher used by the sensor service."""

from __future__ import annotations

from dataclasses import dataclass

from redis import Redis

from capture.flow_meter import FlowRecord
from core.config import settings
from core.events import RawFlowEvent, new_event_id, utc_now
from core.streams import BackpressureError, RedisStreamIO, producer_from_settings


@dataclass
class SensorCounters:
    """Observable sensor publish counters."""

    flows_published: int = 0
    flows_dropped: int = 0
    backpressure_events: int = 0


class RawFlowPublisher:
    """Publish completed flows to the ``raw-flows`` stream with limits."""

    def __init__(self, stream: RedisStreamIO | None = None) -> None:
        self.stream = stream or producer_from_settings(
            Redis.from_url(settings.get_redis_url()),
            stream=settings.STREAM_RAW_FLOWS,
            dead_letter_stream=settings.STREAM_DEAD_LETTER,
            consumer_name="sensor-publisher",
        )
        self.counters = SensorCounters()

    def publish_flow(
        self,
        record: FlowRecord,
        *,
        source_label: str | None = None,
        tags: list[str] | None = None,
    ) -> RawFlowEvent:
        """Convert one completed flow into a validated event and publish it."""

        event = RawFlowEvent(
            event_id=new_event_id("flow", seed=record.flow_id),
            timestamp=utc_now(),
            source="live",
            tags=list(tags or []),
            flow_id=record.flow_id,
            src_ip=record.src_ip,
            src_port=record.src_port,
            dst_ip=record.dst_ip,
            dst_port=record.dst_port,
            protocol=record.protocol,
            features=dict(record.features),
            source_label=source_label,
            expired_reason=record.expired_reason,
        )
        try:
            self.stream.publish(event)
        except BackpressureError:
            self.counters.backpressure_events += 1
            self.counters.flows_dropped += 1
            raise
        self.counters.flows_published += 1
        return event

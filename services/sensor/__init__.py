"""Sensor service: passive capture or held-out simulation into ``raw-flows``."""

from __future__ import annotations

import threading
from typing import Any

from core.config import settings
from core.logging import get_logger

logger = get_logger(__name__)

__all__ = ["RawFlowPublisher", "SensorCounters", "run_sensor"]


def run_sensor(
    interface: str = "auto",
    bpf_filter: str = "ip",
    *,
    stop_event: threading.Event | None = None,
    publisher: Any | None = None,
) -> dict[str, Any]:
    """Run the configured capture mode.

    ``simulation`` replays held-out test rows with ``SIMULATION`` tags;
    ``live`` performs passive Scapy/Npcap capture only and requires elevation.
    No packet injection or prevention action exists in this phase.
    """

    from capture.flow_meter import BidirectionalFlowMeter
    from capture.replay_simulator import run_simulator
    from capture.sniffer import run_sniffer
    from services.sensor.publisher import RawFlowPublisher

    mode = settings.get_capture_mode()
    if mode == "simulation":
        logger.info("Sensor capture mode=simulation; replaying held-out TEST rows only")
        published = run_simulator(
            speed=10.0,
            loop=False,
            publisher=publisher,
            stop_event=stop_event,
        )
        return {"mode": mode, "flows_published": published}

    active_publisher = publisher or RawFlowPublisher()
    meter = BidirectionalFlowMeter(
        active_timeout=settings.SENSOR_FLOW_TIMEOUT_ACTIVE,
        idle_timeout=settings.SENSOR_FLOW_TIMEOUT_IDLE,
    )

    def _handle_flows(packet: Any) -> None:
        for record in meter.add_packet(packet):
            try:
                active_publisher.publish_flow(record)
            except Exception as exc:  # noqa: BLE001 - backpressure boundary
                logger.warning("Dropping flow under backpressure: %s", exc)

    stats = run_sniffer(
        _handle_flows,
        interface=interface,
        bpf_filter=bpf_filter,
        stop_event=stop_event,
    )
    for record in meter.flush():
        try:
            active_publisher.publish_flow(record)
        except Exception as exc:  # noqa: BLE001 - backpressure boundary
            logger.warning("Dropping flushed flow under backpressure: %s", exc)
    return {
        "mode": mode,
        "capture_stats": stats.snapshot(),
        "flows_published": active_publisher.counters.flows_published,
        "flows_dropped": active_publisher.counters.flows_dropped,
    }

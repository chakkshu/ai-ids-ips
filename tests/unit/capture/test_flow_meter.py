"""Unit tests for the passive bidirectional flow meter.

Packets are built locally with Scapy; no capture socket, Redis, or model
artifact is used. The feature-order assertions pin the meter to the saved
active model contract in ``ml/registry/active``.
"""

from __future__ import annotations

import json
import math
from pathlib import Path

import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Packet, Raw

from capture.flow_meter import FEATURE_NAMES, BidirectionalFlowMeter, FlowRecord

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SAVED_FEATURES = (
    _REPO_ROOT / "ml" / "registry" / "active" / "cicids-80k-no-port" / "features.json"
)


def _saved_feature_names() -> list[str]:
    contract = json.loads(_SAVED_FEATURES.read_text(encoding="utf-8"))
    return [str(name) for name in contract["features"]]


def _tcp(
    src: str,
    dst: str,
    sport: int,
    dport: int,
    *,
    flags: str = "S",
    window: int = 1024,
    payload: bytes = b"x",
) -> Packet:
    return (
        Ether()
        / IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, flags=flags, window=window)
        / Raw(load=payload)
    )


def _udp(src: str, dst: str, sport: int, dport: int, payload: bytes = b"abc") -> Packet:
    return (
        Ether()
        / IP(src=src, dst=dst)
        / UDP(sport=sport, dport=dport)
        / Raw(load=payload)
    )


def test_bidirectional_flow_features_from_scapy_packets() -> None:
    meter = BidirectionalFlowMeter(active_timeout=120.0, idle_timeout=30.0)

    forward_first = _tcp(
        "10.0.0.1", "10.0.0.2", 12345, 443, flags="S", window=1000, payload=b"aaaa"
    )
    forward_second = _tcp(
        "10.0.0.1", "10.0.0.2", 12345, 443, flags="PA", window=2000, payload=b"bbbbbb"
    )
    backward_first = _tcp(
        "10.0.0.2", "10.0.0.1", 443, 12345, flags="PA", window=3000, payload=b"cc"
    )
    backward_second = _tcp(
        "10.0.0.2", "10.0.0.1", 443, 12345, flags="U", window=4000, payload=b"dddd"
    )
    packets = [forward_first, forward_second, backward_first, backward_second]

    for packet, timestamp in zip(packets, (0.0, 1.0, 2.0, 4.0)):
        assert meter.add_packet(packet, timestamp=timestamp) == []

    # Reverse packets share the same bidirectional key and are counted as bwd.
    assert len(meter.flows) == 1
    records: list[FlowRecord] = meter.flush()
    assert len(records) == 1
    record = records[0]

    assert record.protocol == "TCP"
    assert (record.src_ip, record.src_port) == ("10.0.0.1", 12345)
    assert (record.dst_ip, record.dst_port) == ("10.0.0.2", 443)
    assert record.started_at == 0.0
    assert record.ended_at == 4.0

    features = record.features
    fwd_bytes = len(forward_first[IP]) + len(forward_second[IP])
    bwd_bytes = len(backward_first[IP]) + len(backward_second[IP])

    assert features["Total Fwd Packets"] == 2.0
    assert features["Total Backward Packets"] == 2.0
    assert features["Total Length of Fwd Packets"] == float(fwd_bytes)
    assert features["Total Length of Bwd Packets"] == float(bwd_bytes)
    assert features["Flow Duration"] == 4.0
    assert record.duration == 4.0
    assert features["Flow Bytes/s"] == pytest.approx((fwd_bytes + bwd_bytes) / 4.0)
    assert features["Flow Packets/s"] == 1.0

    # TCP flag accounting, including directional PSH/URG counters.
    assert features["SYN Flag Count"] == 1.0
    assert features["ACK Flag Count"] == 2.0
    assert features["PSH Flag Count"] == 2.0
    assert features["URG Flag Count"] == 1.0
    assert features["FIN Flag Count"] == 0.0
    assert features["RST Flag Count"] == 0.0
    assert features["Fwd PSH Flags"] == 1.0
    assert features["Bwd PSH Flags"] == 1.0
    assert features["Fwd URG Flags"] == 0.0
    assert features["Bwd URG Flags"] == 1.0

    # Initial windows are taken from the first packet in each direction.
    assert features["Init_Win_bytes_forward"] == 1000.0
    assert features["Init_Win_bytes_backward"] == 3000.0

    # IATs: fwd [1], bwd [2], all [1, 1, 2].
    assert features["Fwd IAT Total"] == 1.0
    assert features["Fwd IAT Mean"] == 1.0
    assert features["Bwd IAT Total"] == 2.0
    assert features["Bwd IAT Max"] == 2.0
    assert features["Flow IAT Mean"] == pytest.approx(4.0 / 3.0)
    assert features["Flow IAT Max"] == 2.0
    assert features["Flow IAT Min"] == 1.0

    # Default TCP header is 20 bytes IP + 20 bytes TCP per packet.
    assert features["Fwd Header Length"] == 80.0
    assert features["Bwd Header Length"] == 80.0
    assert features["Fwd Header Length_Duplicate"] == 80.0
    assert features["min_seg_size_forward"] == float(
        min(len(forward_first[IP]), len(forward_second[IP]))
    )

    # No gap reaches the 30s idle threshold: one active period, no idle periods.
    assert features["Active Mean"] == 4.0
    assert features["Active Std"] == 0.0
    assert features["Active Max"] == 4.0
    assert features["Active Min"] == 4.0
    assert features["Idle Mean"] == 0.0
    assert features["Idle Std"] == 0.0
    assert features["Idle Max"] == 0.0
    assert features["Idle Min"] == 0.0

    assert all(math.isfinite(value) for value in features.values())


def test_udp_flow_header_lengths_and_non_ip_frames_ignored() -> None:
    meter = BidirectionalFlowMeter()
    udp = _udp("10.1.0.1", "10.1.0.2", 5000, 53, payload=b"12345")

    assert meter.add_packet(Ether() / Raw(load=b"not ip"), timestamp=0.0) == []
    assert meter.add_packet(udp, timestamp=1.0) == []
    assert len(meter.flows) == 1

    record = meter.flush()[0]
    assert record.protocol == "UDP"
    assert record.features["Total Fwd Packets"] == 1.0
    assert record.features["Total Length of Fwd Packets"] == float(len(udp[IP]))
    # 20 bytes IP + 8 bytes UDP.
    assert record.features["Fwd Header Length"] == 28.0
    assert record.features["Bwd Header Length"] == 0.0
    assert all(math.isfinite(value) for value in record.features.values())


def test_active_timeout_emits_completed_record_with_reason() -> None:
    meter = BidirectionalFlowMeter(active_timeout=5.0, idle_timeout=100.0)
    meter.add_packet(_tcp("10.2.0.1", "10.2.0.2", 1111, 80), timestamp=0.0)

    completed = meter.expire(5.0)

    assert len(completed) == 1
    assert completed[0].expired_reason == "active_timeout"
    assert completed[0].features["Flow Duration"] == 0.0
    assert meter.flows == {}


def test_idle_timeout_emits_completed_record_with_reason() -> None:
    meter = BidirectionalFlowMeter(active_timeout=100.0, idle_timeout=2.0)
    meter.add_packet(_tcp("10.3.0.1", "10.3.0.2", 2222, 80), timestamp=0.0)

    completed = meter.expire(3.0)

    assert len(completed) == 1
    assert completed[0].expired_reason == "idle_timeout"
    assert meter.flows == {}


def test_feature_order_parity_with_saved_active_model() -> None:
    saved = _saved_feature_names()
    assert len(saved) == 77
    assert "Destination Port" not in saved

    assert list(FEATURE_NAMES) == saved

    meter = BidirectionalFlowMeter()
    meter.add_packet(_tcp("10.4.0.1", "10.4.0.2", 3333, 443), timestamp=0.0)
    record = meter.flush()[0]
    assert list(record.features.keys()) == saved


def test_timeouts_must_be_positive() -> None:
    with pytest.raises(ValueError, match="timeouts must be positive"):
        BidirectionalFlowMeter(active_timeout=0.0)
    with pytest.raises(ValueError, match="timeouts must be positive"):
        BidirectionalFlowMeter(idle_timeout=-1.0)

"""Capture-side bidirectional flow aggregation and feature extraction.

This meter is a best-effort adapter from observed packet headers to the saved
77-feature ``cicids-80k-no-port`` contract. It is **not** a CICFlowMeter
reimplementation and does not claim feature parity with it: several features
are approximations or zero-filled defaults. See
``docs/phase5-feature-coverage.md`` for the full disclosure and accuracy impact.
"""

from __future__ import annotations

import hashlib
import itertools
import math
import statistics
import time
from dataclasses import dataclass, field
from typing import Any

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.packet import Packet

from ml.schema import DESTINATION_PORT, features_for_variant

NO_PORT_VARIANT = "no_destination_port"
FEATURE_NAMES: tuple[str, ...] = tuple(features_for_variant(NO_PORT_VARIANT))
if DESTINATION_PORT in FEATURE_NAMES:  # pragma: no cover - contract guard
    raise RuntimeError("flow meter must use the no-port model contract")


@dataclass(frozen=True)
class Endpoint:
    """Normalized IP/port endpoint used in the bidirectional flow key."""

    ip: str
    port: int

    def as_key(self) -> tuple[str, int]:
        return (self.ip, self.port)


@dataclass
class PacketMeta:
    """Header-derived packet facts; no payload inspection is performed."""

    timestamp: float
    endpoint: Endpoint
    peer: Endpoint
    protocol: str
    direction: int  # 0 = forward (first observed), 1 = backward
    packet_length: int
    payload_length: int
    header_length: int
    window: int
    flags: dict[str, int]


@dataclass
class FlowAccumulator:
    """Mutable state for one bidirectional flow."""

    key: tuple[str, tuple[str, int], tuple[str, int]]
    forward: Endpoint
    backward: Endpoint
    protocol: str
    started_at: float
    ended_at: float
    packets: list[PacketMeta] = field(default_factory=list)

    def direction_for(self, endpoint: Endpoint) -> int:
        return 0 if endpoint.as_key() == self.forward.as_key() else 1

    def add(self, meta: PacketMeta) -> None:
        self.packets.append(meta)
        self.ended_at = max(self.ended_at, meta.timestamp)

    def expired(
        self, now: float, active_timeout: float, idle_timeout: float
    ) -> str | None:
        if now - self.started_at >= active_timeout:
            return "active_timeout"
        if now - self.ended_at >= idle_timeout:
            return "idle_timeout"
        return None

    @property
    def flow_id(self) -> str:
        seed = (
            f"{self.protocol}|{self.forward.as_key()}|"
            f"{self.backward.as_key()}|{self.started_at:.6f}"
        )
        return "flow-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:20]


@dataclass(frozen=True)
class FlowRecord:
    """Completed flow with feature values ordered for the active model."""

    flow_id: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    started_at: float
    ended_at: float
    features: dict[str, float]
    expired_reason: str | None = None

    @property
    def duration(self) -> float:
        return float(self.features["Flow Duration"])


def _safe_div(numerator: float, denominator: float) -> float:
    value = numerator / denominator if denominator > 0 else 0.0
    return float(value) if math.isfinite(value) else 0.0


def _stats(values: list[float]) -> tuple[float, float, float, float]:
    if not values:
        return (0.0, 0.0, 0.0, 0.0)
    mean = float(statistics.fmean(values))
    std = float(statistics.pstdev(values)) if len(values) > 1 else 0.0
    return (mean, std, float(max(values)), float(min(values)))


def _deltas(timestamps: list[float]) -> list[float]:
    return [
        float(current - previous)
        for previous, current in itertools.pairwise(timestamps)
    ]


def _tcp_flags(tcp: TCP) -> dict[str, int]:
    bits = int(tcp.flags)
    return {
        "FIN": 1 if bits & 0x01 else 0,
        "SYN": 1 if bits & 0x02 else 0,
        "RST": 1 if bits & 0x04 else 0,
        "PSH": 1 if bits & 0x08 else 0,
        "ACK": 1 if bits & 0x10 else 0,
        "URG": 1 if bits & 0x20 else 0,
        "ECE": 1 if bits & 0x40 else 0,
        "CWE": 1 if bits & 0x80 else 0,
    }


def packet_metadata(
    packet: Packet, timestamp: float | None = None
) -> PacketMeta | None:
    """Extract header facts from a Scapy packet; return None for non-IP frames."""

    if not packet.haslayer(IP):
        return None
    ip = packet[IP]
    try:
        packet_length = int(ip.len or len(ip))
    except (TypeError, ValueError):  # pragma: no cover - malformed synthetic frame
        packet_length = len(ip)

    transport = ip.payload
    window = 0
    flags = {
        name: 0 for name in ("FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWE")
    }
    if isinstance(transport, TCP):
        protocol = "TCP"
        src_port, dst_port = int(transport.sport), int(transport.dport)
        header_length = int(ip.ihl or 5) * 4 + int(transport.dataofs or 5) * 4
        window = int(transport.window)
        flags = _tcp_flags(transport)
        payload_length = max(packet_length - header_length, 0)
    elif isinstance(transport, UDP):
        protocol = "UDP"
        src_port, dst_port = int(transport.sport), int(transport.dport)
        header_length = int(ip.ihl or 5) * 4 + 8
        payload_length = max(packet_length - header_length, 0)
    elif isinstance(transport, ICMP):
        protocol = "ICMP"
        src_port, dst_port = 0, 0
        header_length = int(ip.ihl or 5) * 4 + 4
        payload_length = max(packet_length - header_length, 0)
    else:
        protocol = str(ip.proto)
        src_port, dst_port = 0, 0
        header_length = int(ip.ihl or 5) * 4
        payload_length = max(packet_length - header_length, 0)

    return PacketMeta(
        timestamp=float(timestamp if timestamp is not None else time.time()),
        endpoint=Endpoint(str(ip.src), src_port),
        peer=Endpoint(str(ip.dst), dst_port),
        protocol=protocol,
        direction=0,
        packet_length=packet_length,
        payload_length=payload_length,
        header_length=header_length,
        window=window,
        flags=flags,
    )


def _flow_key(meta: PacketMeta) -> tuple[str, tuple[str, int], tuple[str, int]]:
    first, second = meta.endpoint.as_key(), meta.peer.as_key()
    left, right = sorted((first, second))
    return (meta.protocol, left, right)


def _bulk_stats(
    packets: list[PacketMeta], gap_threshold: float
) -> tuple[float, float, float]:
    """Approximate CIC bulk metrics using directional packets and a gap split."""

    if not packets:
        return (0.0, 0.0, 0.0)
    groups: list[list[PacketMeta]] = [[packets[0]]]
    for packet in packets[1:]:
        if packet.timestamp - groups[-1][-1].timestamp <= gap_threshold:
            groups[-1].append(packet)
        else:
            groups.append([packet])
    bytes_per_bulk = [
        float(sum(item.packet_length for item in group)) for group in groups
    ]
    packets_per_bulk = [float(len(group)) for group in groups]
    rates = []
    for group in groups:
        duration = group[-1].timestamp - group[0].timestamp
        rates.append(_safe_div(sum(item.packet_length for item in group), duration))
    return (
        float(statistics.fmean(bytes_per_bulk)),
        float(statistics.fmean(packets_per_bulk)),
        float(statistics.fmean(rates)),
    )


def _active_idle_stats(
    packets: list[PacketMeta], idle_threshold: float
) -> tuple[float, float, float, float, float, float, float, float]:
    """Approximate CIC active/idle periods with the configured idle timeout."""

    if not packets:
        return (0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
    active_start = packets[0].timestamp
    active_end = active_start
    active: list[float] = []
    idle: list[float] = []
    for previous, current in itertools.pairwise(packets):
        gap = current.timestamp - previous.timestamp
        if gap >= idle_threshold:
            active.append(max(active_end - active_start, 0.0))
            idle.append(gap)
            active_start = current.timestamp
        active_end = current.timestamp
    active.append(max(active_end - active_start, 0.0))
    return (*_stats(active), *_stats(idle))


def build_features(flow: FlowAccumulator, idle_timeout: float) -> dict[str, float]:
    """Build a finite feature mapping in the saved model's exact order."""

    fwd = [packet for packet in flow.packets if packet.direction == 0]
    bwd = [packet for packet in flow.packets if packet.direction == 1]
    all_packets = sorted(flow.packets, key=lambda packet: packet.timestamp)
    duration = max(flow.ended_at - flow.started_at, 0.0)

    fwd_lengths = [float(packet.packet_length) for packet in fwd]
    bwd_lengths = [float(packet.packet_length) for packet in bwd]
    all_lengths = [float(packet.packet_length) for packet in all_packets]
    fwd_bytes, bwd_bytes = sum(fwd_lengths), sum(bwd_lengths)
    total_bytes = fwd_bytes + bwd_bytes
    total_packets = len(fwd) + len(bwd)

    fwd_iat = _deltas([packet.timestamp for packet in fwd])
    bwd_iat = _deltas([packet.timestamp for packet in bwd])
    all_iat = _deltas([packet.timestamp for packet in all_packets])
    _, fwd_iat_std, fwd_iat_max, fwd_iat_min = _stats(fwd_iat)
    _, bwd_iat_std, bwd_iat_max, bwd_iat_min = _stats(bwd_iat)
    iat_mean, iat_std, iat_max, iat_min = _stats(all_iat)
    packet_mean, packet_std, packet_max, packet_min = _stats(all_lengths)

    fwd_bulk = _bulk_stats(fwd, idle_timeout)
    bwd_bulk = _bulk_stats(bwd, idle_timeout)
    active_stats = _active_idle_stats(all_packets, idle_timeout)
    active_mean, active_std, active_max, active_min = active_stats[:4]
    idle_mean, idle_std, idle_max, idle_min = active_stats[4:]

    fwd_header_length = float(sum(packet.header_length for packet in fwd))
    values: dict[str, float] = {
        "Flow Duration": duration,
        "Total Fwd Packets": float(len(fwd)),
        "Total Backward Packets": float(len(bwd)),
        "Total Length of Fwd Packets": fwd_bytes,
        "Total Length of Bwd Packets": bwd_bytes,
        "Fwd Packet Length Max": max(fwd_lengths, default=0.0),
        "Fwd Packet Length Min": min(fwd_lengths, default=0.0),
        "Fwd Packet Length Mean": _stats(fwd_lengths)[0],
        "Fwd Packet Length Std": _stats(fwd_lengths)[1],
        "Bwd Packet Length Max": max(bwd_lengths, default=0.0),
        "Bwd Packet Length Min": min(bwd_lengths, default=0.0),
        "Bwd Packet Length Mean": _stats(bwd_lengths)[0],
        "Bwd Packet Length Std": _stats(bwd_lengths)[1],
        "Flow Bytes/s": _safe_div(total_bytes, duration),
        "Flow Packets/s": _safe_div(float(total_packets), duration),
        "Flow IAT Mean": iat_mean,
        "Flow IAT Std": iat_std,
        "Flow IAT Max": iat_max,
        "Flow IAT Min": iat_min,
        "Fwd IAT Total": float(sum(fwd_iat)),
        "Fwd IAT Mean": _stats(fwd_iat)[0],
        "Fwd IAT Std": fwd_iat_std,
        "Fwd IAT Max": fwd_iat_max,
        "Fwd IAT Min": fwd_iat_min,
        "Bwd IAT Total": float(sum(bwd_iat)),
        "Bwd IAT Mean": _stats(bwd_iat)[0],
        "Bwd IAT Std": bwd_iat_std,
        "Bwd IAT Max": bwd_iat_max,
        "Bwd IAT Min": bwd_iat_min,
        "Fwd PSH Flags": float(sum(packet.flags["PSH"] for packet in fwd)),
        "Bwd PSH Flags": float(sum(packet.flags["PSH"] for packet in bwd)),
        "Fwd URG Flags": float(sum(packet.flags["URG"] for packet in fwd)),
        "Bwd URG Flags": float(sum(packet.flags["URG"] for packet in bwd)),
        "Fwd Header Length": fwd_header_length,
        "Bwd Header Length": float(sum(packet.header_length for packet in bwd)),
        "Fwd Packets/s": _safe_div(float(len(fwd)), duration),
        "Bwd Packets/s": _safe_div(float(len(bwd)), duration),
        "Min Packet Length": packet_min,
        "Max Packet Length": packet_max,
        "Packet Length Mean": packet_mean,
        "Packet Length Std": packet_std,
        "Packet Length Variance": packet_std**2,
        "FIN Flag Count": float(sum(packet.flags["FIN"] for packet in all_packets)),
        "SYN Flag Count": float(sum(packet.flags["SYN"] for packet in all_packets)),
        "RST Flag Count": float(sum(packet.flags["RST"] for packet in all_packets)),
        "PSH Flag Count": float(sum(packet.flags["PSH"] for packet in all_packets)),
        "ACK Flag Count": float(sum(packet.flags["ACK"] for packet in all_packets)),
        "URG Flag Count": float(sum(packet.flags["URG"] for packet in all_packets)),
        "CWE Flag Count": float(sum(packet.flags["CWE"] for packet in all_packets)),
        "ECE Flag Count": float(sum(packet.flags["ECE"] for packet in all_packets)),
        "Down/Up Ratio": _safe_div(float(len(bwd)), float(len(fwd))),
        "Average Packet Size": _safe_div(total_bytes, float(total_packets)),
        "Avg Fwd Segment Size": _safe_div(fwd_bytes, float(len(fwd))),
        "Avg Bwd Segment Size": _safe_div(bwd_bytes, float(len(bwd))),
        "Fwd Header Length_Duplicate": fwd_header_length,
        "Fwd Avg Bytes/Bulk": fwd_bulk[0],
        "Fwd Avg Packets/Bulk": fwd_bulk[1],
        "Fwd Avg Bulk Rate": fwd_bulk[2],
        "Bwd Avg Bytes/Bulk": bwd_bulk[0],
        "Bwd Avg Packets/Bulk": bwd_bulk[1],
        "Bwd Avg Bulk Rate": bwd_bulk[2],
        "Subflow Fwd Packets": float(len(fwd)),
        "Subflow Fwd Bytes": fwd_bytes,
        "Subflow Bwd Packets": float(len(bwd)),
        "Subflow Bwd Bytes": bwd_bytes,
        "Init_Win_bytes_forward": float(fwd[0].window) if fwd else 0.0,
        "Init_Win_bytes_backward": float(bwd[0].window) if bwd else 0.0,
        "act_data_pkt_fwd": float(
            sum(1 for packet in fwd if packet.payload_length > 0)
        ),
        "min_seg_size_forward": min(fwd_lengths, default=0.0),
        "Active Mean": active_mean,
        "Active Std": active_std,
        "Active Max": active_max,
        "Active Min": active_min,
        "Idle Mean": idle_mean,
        "Idle Std": idle_std,
        "Idle Max": idle_max,
        "Idle Min": idle_min,
    }
    ordered = {name: float(values[name]) for name in FEATURE_NAMES}
    if any(not math.isfinite(value) for value in ordered.values()):  # pragma: no cover
        raise ValueError("flow feature extraction produced a non-finite value")
    return ordered


class BidirectionalFlowMeter:
    """Aggregate packets into timed bidirectional flows."""

    def __init__(
        self,
        *,
        active_timeout: float = 120.0,
        idle_timeout: float = 30.0,
        now_fn: Any = time.time,
    ) -> None:
        if active_timeout <= 0 or idle_timeout <= 0:
            raise ValueError("flow timeouts must be positive")
        self.active_timeout = float(active_timeout)
        self.idle_timeout = float(idle_timeout)
        self._now = now_fn
        self.flows: dict[
            tuple[str, tuple[str, int], tuple[str, int]], FlowAccumulator
        ] = {}

    def add_packet(
        self, packet: Packet, timestamp: float | None = None
    ) -> list[FlowRecord]:
        """Add a packet and return flows that expired before or after it."""

        now = float(timestamp if timestamp is not None else self._now())
        completed = self.expire(now)
        meta = packet_metadata(packet, now)
        if meta is None:
            return completed

        key = _flow_key(meta)
        flow = self.flows.get(key)
        if flow is not None:
            reason = flow.expired(now, self.active_timeout, self.idle_timeout)
            if reason is not None:
                completed.append(self._finalize(flow, reason))
                flow = None
        if flow is None:
            flow = FlowAccumulator(
                key=key,
                forward=meta.endpoint,
                backward=meta.peer,
                protocol=meta.protocol,
                started_at=meta.timestamp,
                ended_at=meta.timestamp,
            )
            self.flows[key] = flow
        meta.direction = flow.direction_for(meta.endpoint)
        flow.add(meta)
        return completed

    def expire(self, now: float) -> list[FlowRecord]:
        """Emit flows whose active or idle timeout elapsed by ``now``."""

        completed: list[FlowRecord] = []
        for key, flow in list(self.flows.items()):
            reason = flow.expired(now, self.active_timeout, self.idle_timeout)
            if reason is not None:
                completed.append(self._finalize(flow, reason))
                del self.flows[key]
        return completed

    def flush(self, *, reason: str = "flush") -> list[FlowRecord]:
        """Emit all outstanding flows (used at shutdown)."""

        completed = [self._finalize(flow, reason) for flow in self.flows.values()]
        self.flows.clear()
        return completed

    def _finalize(self, flow: FlowAccumulator, reason: str) -> FlowRecord:
        return FlowRecord(
            flow_id=flow.flow_id,
            src_ip=flow.forward.ip,
            src_port=flow.forward.port,
            dst_ip=flow.backward.ip,
            dst_port=flow.backward.port,
            protocol=flow.protocol,
            started_at=flow.started_at,
            ended_at=flow.ended_at,
            features=build_features(flow, self.idle_timeout),
            expired_reason=reason,
        )

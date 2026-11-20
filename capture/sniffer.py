"""Passive packet capture wrapper around Scapy/Npcap.

This module is capture-only: it never sends, injects, spoofs, or modifies
packets. Windows captures require Npcap and administrator privileges because
raw socket access is needed to open the interface.
"""

from __future__ import annotations

import os
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

import psutil
from scapy.all import AsyncSniffer, get_if_list
from scapy.packet import Packet

PacketHandler = Callable[[Packet], None]


def is_admin() -> bool:
    """Return True when the process has Administrator/root privileges."""

    if os.name == "nt":
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):  # pragma: no cover - unusual Windows
            return False
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    return False  # pragma: no cover - unsupported platform


def require_admin() -> None:
    """Refuse to start capture unless privileges permit raw socket access."""

    if not is_admin():
        raise PermissionError(
            "Administrator/root privileges are required for packet capture: "
            "raw sockets (Npcap on Windows) cannot be opened by an "
            "unprivileged process. Start the sensor from an elevated terminal."
        )


def available_interfaces() -> list[str]:
    """List interfaces Scapy can see; Npcap names appear as NPF GUIDs."""

    interfaces: list[str] = []
    for name in get_if_list():
        if isinstance(name, bytes):
            interfaces.append(name.decode("utf-8", errors="replace"))
        else:
            interfaces.append(str(name))
    return interfaces


def select_interface(preferred: str = "auto") -> str:
    """Resolve ``auto`` to Scapy's working interface without changing state."""

    if preferred and preferred.lower() != "auto":
        return preferred
    interfaces = available_interfaces()
    if not interfaces:
        raise RuntimeError(
            "No capture interfaces were found. Install Npcap with WinPcap "
            "compatibility on Windows before starting the sensor."
        )
    try:
        from scapy.all import get_working_if

        working = str(get_working_if())
        if working in interfaces:
            return working
    except Exception:  # noqa: BLE001 - Scapy platform fallback
        return interfaces[0]
    return interfaces[0]


@dataclass
class CaptureStats:
    """Passive-capture counters and observed rates."""

    interface: str
    started_at: float
    packets_seen: int = 0
    bytes_seen: int = 0
    handler_failures: int = 0
    interface_drops: int = 0
    last_drop_snapshot: int | None = None

    def record_packet(self, packet: Packet) -> None:
        self.packets_seen += 1
        try:
            self.bytes_seen += len(bytes(packet))
        except (TypeError, ValueError):  # pragma: no cover - malformed frame
            pass

    def record_failure(self) -> None:
        self.handler_failures += 1

    def update_interface_drops(self, *, nic_name: str | None = None) -> None:
        """Record OS driver drops when a matching NIC counter is available.

        Npcap/Scapy do not expose reliable kernel drop counters per live
        capture handle, so this is best-effort and may legitimately remain 0.
        """

        counters = psutil.net_io_counters(pernic=True) or {}
        name = nic_name or self.interface
        entry = counters.get(name)
        if entry is None:
            for candidate, value in counters.items():
                if (
                    candidate.lower() in name.lower()
                    or name.lower() in candidate.lower()
                ):
                    entry = value
                    break
        if entry is None:
            return
        dropin = int(getattr(entry, "dropin", 0))
        if self.last_drop_snapshot is not None and dropin >= self.last_drop_snapshot:
            self.interface_drops += dropin - self.last_drop_snapshot
        self.last_drop_snapshot = dropin

    def snapshot(self, *, now: float | None = None) -> dict[str, float]:
        elapsed = max((now or time.time()) - self.started_at, 0.0)
        return {
            "elapsed_seconds": elapsed,
            "packets_seen": float(self.packets_seen),
            "bytes_seen": float(self.bytes_seen),
            "handler_failures": float(self.handler_failures),
            "interface_drops": float(self.interface_drops),
            "packets_per_second": self.packets_seen / elapsed if elapsed else 0.0,
            "bytes_per_second": self.bytes_seen / elapsed if elapsed else 0.0,
        }


def run_sniffer(
    packet_handler: PacketHandler,
    *,
    interface: str = "auto",
    bpf_filter: str = "ip",
    stop_event: threading.Event | None = None,
    poll_interval: float = 0.5,
    max_packets: int | None = None,
    nic_name: str | None = None,
) -> CaptureStats:
    """Capture packets until stopped or ``max_packets`` is reached.

    ``stop_event`` allows a supervisor to request graceful shutdown; the
    Scapy sniffer is always stopped and joined in the ``finally`` block.
    """

    require_admin()
    if not bpf_filter.strip():
        raise ValueError("a non-empty BPF filter is required")
    if max_packets is not None and max_packets <= 0:
        raise ValueError("max_packets must be positive when provided")

    resolved_interface = select_interface(interface)
    stats = CaptureStats(interface=resolved_interface, started_at=time.time())
    stop = stop_event or threading.Event()

    def _handle(packet: Packet) -> None:
        stats.record_packet(packet)
        try:
            packet_handler(packet)
        except Exception:  # noqa: BLE001 - one bad packet must not kill capture
            stats.record_failure()

    sniffer = AsyncSniffer(
        iface=resolved_interface,
        filter=bpf_filter,
        prn=_handle,
        store=False,
    )
    sniffer.start()
    try:
        while not stop.is_set():
            if max_packets is not None and stats.packets_seen >= max_packets:
                break
            stop.wait(poll_interval)
            stats.update_interface_drops(nic_name=nic_name)
    except KeyboardInterrupt:
        stop.set()
    finally:
        sniffer.stop()
        sniffer.join(timeout=5.0)
        stats.update_interface_drops(nic_name=nic_name)
    return stats

"""Unit tests for the passive capture wrapper.

No capture socket is opened: only privilege checks, interface selection, and
counter bookkeeping are exercised.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import scapy.all as scapy_all
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Packet, Raw

from capture import sniffer


def _packet(payload: bytes = b"hello") -> Packet:
    return (
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=1234, dport=80)
        / Raw(load=payload)
    )


def test_require_admin_enforces_privileges(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sniffer, "is_admin", lambda: False)
    with pytest.raises(PermissionError, match="Administrator/root privileges"):
        sniffer.require_admin()

    monkeypatch.setattr(sniffer, "is_admin", lambda: True)
    sniffer.require_admin()


def test_select_interface_preferred_skips_scapy_discovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _unexpected() -> Any:
        raise AssertionError(
            "interface discovery must not run for an explicit interface"
        )

    monkeypatch.setattr(sniffer, "available_interfaces", _unexpected)
    monkeypatch.setattr(scapy_all, "get_working_if", _unexpected)
    assert sniffer.select_interface("ethX") == "ethX"


def test_available_interfaces_and_auto_selection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sniffer, "get_if_list", lambda: ["lo", "eth0"])
    assert sniffer.available_interfaces() == ["lo", "eth0"]

    monkeypatch.setattr(sniffer, "available_interfaces", lambda: ["lo", "eth0"])
    monkeypatch.setattr(scapy_all, "get_working_if", lambda: "eth0")
    assert sniffer.select_interface("auto") == "eth0"

    def _no_working_if() -> str:
        raise RuntimeError("no working interface")

    monkeypatch.setattr(scapy_all, "get_working_if", _no_working_if)
    assert sniffer.select_interface() == "lo"

    monkeypatch.setattr(sniffer, "available_interfaces", list)
    with pytest.raises(RuntimeError, match="No capture interfaces"):
        sniffer.select_interface("auto")


def test_capture_stats_record_packet_and_snapshot() -> None:
    started_at = 100.0
    stats = sniffer.CaptureStats(interface="ethX", started_at=started_at)
    packets = [_packet(b"hello"), _packet(b"world!")]

    for packet in packets:
        stats.record_packet(packet)
    stats.record_failure()

    snapshot = stats.snapshot(now=started_at + 4.0)
    expected_bytes = sum(len(bytes(packet)) for packet in packets)

    assert snapshot["elapsed_seconds"] == 4.0
    assert snapshot["packets_seen"] == 2.0
    assert snapshot["bytes_seen"] == float(expected_bytes)
    assert snapshot["handler_failures"] == 1.0
    assert snapshot["interface_drops"] == 0.0
    assert snapshot["packets_per_second"] == pytest.approx(0.5)
    assert snapshot["bytes_per_second"] == pytest.approx(expected_bytes / 4.0)

    zero_elapsed = stats.snapshot(now=started_at)
    assert zero_elapsed["elapsed_seconds"] == 0.0
    assert zero_elapsed["packets_per_second"] == 0.0
    assert zero_elapsed["bytes_per_second"] == 0.0


def test_capture_stats_tracks_interface_drop_deltas(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stats = sniffer.CaptureStats(interface="Ethernet", started_at=0.0)
    counters: dict[str, SimpleNamespace] = {"Ethernet": SimpleNamespace(dropin=10)}

    def fake_counters(*, pernic: bool = False) -> dict[str, SimpleNamespace]:
        assert pernic is True
        return counters

    monkeypatch.setattr(sniffer.psutil, "net_io_counters", fake_counters)

    stats.update_interface_drops()
    assert stats.last_drop_snapshot == 10
    assert stats.interface_drops == 0

    counters["Ethernet"] = SimpleNamespace(dropin=13)
    stats.update_interface_drops()
    assert stats.interface_drops == 3

    # A counter reset/rollback must not produce negative drops.
    counters["Ethernet"] = SimpleNamespace(dropin=12)
    stats.update_interface_drops()
    assert stats.interface_drops == 3
    assert stats.last_drop_snapshot == 12

    # A matching substring NIC name is accepted when no exact key exists.
    counters.clear()
    counters["Intel Ethernet Adapter"] = SimpleNamespace(dropin=7)
    stats.update_interface_drops(nic_name="Ethernet")
    assert stats.last_drop_snapshot == 7
    assert stats.interface_drops == 3


def test_sniffer_source_is_capture_only() -> None:
    source = Path(sniffer.__file__).read_text(encoding="utf-8")
    assert "AsyncSniffer" in source
    assert "sendp(" not in source
    assert "send(" not in source
    assert "inject(" not in source

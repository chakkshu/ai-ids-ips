"""Simulation-mode prevention E2E test using only SQLite and fakeredis."""

from __future__ import annotations

from typing import Any

import fakeredis
import pytest
from sqlalchemy import select

from core.config import settings
from core.models.alert import Alert
from core.models.prevention import (
    BlockedIP,
    BlockStatus,
    PreventionAction,
    PreventionCandidate,
    PreventionDecision,
)
from core.models.threat import IPProfile
from core.streams import RedisStreamIO, StreamLimits
from prevention.firewall_windows import WindowsFirewallAdapter
from prevention.ip_blocker import real_enforcement_enabled
from services.prevention_engine import PreventionEngine

PUBLIC_IP = "45.33.32.156"


@pytest.fixture
def stream_client() -> Any:
    client = fakeredis.FakeRedis(decode_responses=True)
    try:
        yield client
    finally:
        client.flushall()
        client.close()


def test_simulation_candidates_force_dry_run_and_produce_full_decision_trail(
    db_session,
    make_detection,
    candidate_payload,
    stream_client,
    monkeypatch,
):
    """Even with live+active settings, tagged simulation events never touch a firewall."""

    monkeypatch.setattr(settings, "PREVENTION_MODE", "active")
    monkeypatch.setattr(settings, "PREVENTION_ALLOW_REAL_ENFORCEMENT", True)
    monkeypatch.setattr(settings, "CAPTURE_MODE", "live")
    assert real_enforcement_enabled() is True

    def _forbidden_subprocess(*args: Any, **kwargs: Any) -> None:
        pytest.fail("simulation event must never execute a firewall command")

    monkeypatch.setattr("prevention.ip_blocker.subprocess.run", _forbidden_subprocess)

    _flow, detection = make_detection(src_ip=PUBLIC_IP, label="PortScan")
    detection_id = int(detection.id)

    publisher = RedisStreamIO(
        stream_client,
        settings.STREAM_PREVENTION,
        "phase6-test-publisher",
        "phase6-test-publisher",
        dead_letter_stream=settings.STREAM_PREVENTION_DEAD_LETTER,
        limits=StreamLimits(
            maxlen=100,
            max_pending=50,
            retry_limit=3,
            batch_size=10,
            block_ms=0,
        ),
    )
    for index in range(2):
        publisher.publish(candidate_payload(detection_id=detection_id, confidence=0.96))

    engine = PreventionEngine(
        db_session,
        adapter=WindowsFirewallAdapter(),
        admin_ip="192.0.2.10",
    )
    report = engine.run_once(stream_client, block_ms=0)

    assert report.processed == 2
    assert report.dead_lettered == 0
    assert report.retried == 0
    assert engine.make_consumer(stream_client).pending_count() == 0
    assert stream_client.xlen(settings.STREAM_PREVENTION_DEAD_LETTER) == 0

    candidates = db_session.execute(select(PreventionCandidate)).scalars().all()
    assert len(candidates) == 2
    assert all(candidate.processed for candidate in candidates)

    decisions = (
        db_session.execute(select(PreventionDecision).order_by(PreventionDecision.id))
        .scalars()
        .all()
    )
    assert len(decisions) == 2
    assert [decision.action for decision in decisions] == ["no_action", "block"]
    assert decisions[1].repeat_count == 2
    assert decisions[1].block_id is not None

    blocks = db_session.execute(select(BlockedIP)).scalars().all()
    assert len(blocks) == 1
    block = blocks[0]
    assert block.ip_address == PUBLIC_IP
    assert block.status == BlockStatus.ACTIVE
    assert block.is_dry_run is True
    assert block.firewall_rule_name.startswith("AI-IDS-")

    actions = db_session.execute(select(PreventionAction)).scalars().all()
    assert len(actions) == 1
    assert actions[0].dry_run is True
    assert actions[0].result == "SIMULATED"
    assert actions[0].ip_address == PUBLIC_IP
    assert "netsh" in (actions[0].command_preview or "")

    alerts = db_session.execute(select(Alert)).scalars().all()
    assert len(alerts) == 1
    assert alerts[0].detection_id == detection_id
    assert alerts[0].src_ip == PUBLIC_IP

    profile = (
        db_session.execute(select(IPProfile).where(IPProfile.ip_address == PUBLIC_IP))
        .scalars()
        .one()
    )
    assert profile.detection_count == 2
    assert "PortScan" in (profile.attack_types_json or "")

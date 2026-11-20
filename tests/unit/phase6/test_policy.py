"""Policy-engine safety tests for Phase 6."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from core.config import settings
from core.models.audit import AuditLog
from core.models.prevention import DecisionAction, Whitelist
from prevention.policy import (
    PolicySettings,
    build_context,
    count_recent_candidates,
    evaluate,
    get_or_create_policy,
    is_protected_ip,
    persist_candidate,
    record_decision,
)

SRC_IP = "45.33.32.156"
LABEL = "PortScan"


def _settings(**overrides: object) -> PolicySettings:
    payload = PolicySettings().model_dump(mode="json")
    payload.update(overrides)
    return PolicySettings.model_validate(payload)


def _candidate(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "event_id": "candidate-event-1",
        "candidate_id": "candidate-1",
        "detection_event_id": "detection-event-1",
        "detection_id": None,
        "flow_id": "flow-1",
        "src_ip": SRC_IP,
        "dst_ip": "104.16.1.10",
        "dst_port": 443,
        "model_version": "cicids-80k-no-port",
        "predicted_label": LABEL,
        "verdict": "known attack",
        "confidence_score": 0.96,
        "rare_class_flag": False,
        "simulation": True,
    }
    payload.update(overrides)
    payload["event_id"] = f"candidate-event-{payload['candidate_id']}"
    return payload


class TestPolicyDecisionOrder:
    def test_single_high_confidence_prediction_never_blocks(
        self, db_session, monkeypatch
    ):
        monkeypatch.setattr("prevention.policy._local_addresses", lambda: frozenset())
        context = build_context(db_session, now=datetime.now(UTC))
        decision = evaluate(
            _candidate(),
            policy=_settings(),
            context=context,
            repeat_count=1,
        )
        assert decision.action == DecisionAction.NO_ACTION
        assert decision.reason == "single_or_insufficient_repeat_detections"
        assert decision.block_duration_minutes is None

    def test_repeated_detections_escalate_to_block(self, db_session, monkeypatch):
        monkeypatch.setattr("prevention.policy._local_addresses", lambda: frozenset())
        context = build_context(db_session, now=datetime.now(UTC))
        decision = evaluate(
            _candidate(), policy=_settings(), context=context, repeat_count=4
        )
        assert decision.action == DecisionAction.BLOCK
        assert decision.escalation_level == 2
        assert decision.block_duration_minutes == 240

    def test_escalation_ladder_is_configurable_and_bounded(
        self, db_session, monkeypatch
    ):
        monkeypatch.setattr("prevention.policy._local_addresses", lambda: frozenset())
        context = build_context(db_session, now=datetime.now(UTC))
        decision = evaluate(
            _candidate(),
            policy=_settings(escalation_ladder_minutes=[5, 10, 20], min_detections=2),
            context=context,
            repeat_count=99,
        )
        assert decision.block_duration_minutes == 20

    def test_whitelist_is_checked_first(self, db_session, monkeypatch):
        monkeypatch.setattr("prevention.policy._local_addresses", lambda: frozenset())
        db_session.add(
            Whitelist(
                cidr=f"{SRC_IP}/32", description="test allowlist", is_immutable=False
            )
        )
        db_session.flush()
        context = build_context(db_session, now=datetime.now(UTC))
        decision = evaluate(
            _candidate(), policy=_settings(), context=context, repeat_count=20
        )
        assert decision.action == DecisionAction.NO_ACTION
        assert decision.reason == "whitelisted_address"

    def test_loopback_and_admin_ip_are_never_blocked(self, db_session, monkeypatch):
        monkeypatch.setattr("prevention.policy._local_addresses", lambda: frozenset())
        context = build_context(db_session, admin_ip=SRC_IP, now=datetime.now(UTC))
        assert is_protected_ip("127.0.0.1", context)
        assert is_protected_ip(SRC_IP, context)
        assert (
            evaluate(
                _candidate(src_ip="127.0.0.1"),
                policy=_settings(),
                context=context,
                repeat_count=99,
            ).action
            == DecisionAction.NO_ACTION
        )

    def test_rare_classes_are_alert_only(self, db_session, monkeypatch):
        monkeypatch.setattr("prevention.policy._local_addresses", lambda: frozenset())
        context = build_context(db_session, now=datetime.now(UTC))
        decision = evaluate(
            _candidate(
                predicted_label="Heartbleed",
                confidence_score=0.99,
                rare_class_flag=True,
            ),
            policy=_settings(),
            context=context,
            repeat_count=50,
        )
        assert decision.action == DecisionAction.ALERT_ONLY
        assert decision.reason == "rare_or_low_support_class_alert_only"

    def test_confidence_gate_and_verdict_gate(self, db_session, monkeypatch):
        monkeypatch.setattr("prevention.policy._local_addresses", lambda: frozenset())
        context = build_context(db_session, now=datetime.now(UTC))
        low = evaluate(
            _candidate(confidence_score=0.72),
            policy=_settings(),
            context=context,
            repeat_count=10,
        )
        uncertain = evaluate(
            _candidate(verdict="uncertain"),
            policy=_settings(),
            context=context,
            repeat_count=10,
        )
        assert low.action == DecisionAction.NO_ACTION
        assert uncertain.action == DecisionAction.NO_ACTION

    def test_approval_mode_and_kill_switch(self, db_session, monkeypatch):
        monkeypatch.setattr("prevention.policy._local_addresses", lambda: frozenset())
        context = build_context(db_session, now=datetime.now(UTC))
        approval = evaluate(
            _candidate(),
            policy=_settings(approval_mode=True),
            context=context,
            repeat_count=3,
        )
        kill_switch = evaluate(
            _candidate(),
            policy=_settings(kill_switch=True),
            context=context,
            repeat_count=3,
        )
        assert approval.action == DecisionAction.PENDING_APPROVAL
        assert approval.requires_approval is True
        assert kill_switch.action == DecisionAction.ALERT_ONLY
        assert kill_switch.kill_switch_active is True


class TestDecisionPersistence:
    def test_repeat_window_counts_only_recent_candidates(self, db_session):
        now = datetime.now(UTC)
        persist_candidate(
            db_session,
            _candidate(candidate_id="old"),
            observed_at=now - timedelta(hours=1),
        )
        persist_candidate(
            db_session,
            _candidate(candidate_id="new"),
            observed_at=now - timedelta(seconds=5),
        )
        count = count_recent_candidates(
            db_session,
            src_ip=SRC_IP,
            predicted_label=LABEL,
            window_seconds=60,
            now=now,
        )
        assert count == 1
        assert (
            count_recent_candidates(
                db_session,
                src_ip=SRC_IP,
                predicted_label=LABEL,
                window_seconds=60,
                now=now,
                exclude_candidate_id="new",
            )
            == 0
        )

    def test_every_decision_is_recorded_and_privileged_ones_audited(self, db_session):
        config = get_or_create_policy(db_session)
        assert config.is_active is True
        policy = PolicySettings.from_config(config.config_json)
        context = build_context(db_session, now=datetime.now(UTC))
        no_action = evaluate(
            _candidate(), policy=policy, context=context, repeat_count=1
        )
        block = evaluate(_candidate(), policy=policy, context=context, repeat_count=5)
        record_decision(db_session, no_action, candidate=_candidate())
        decision = record_decision(db_session, block, candidate=_candidate())

        stored = db_session.execute(select(AuditLog)).scalars().all()
        actions = {row.action for row in stored}
        assert "PREVENTION_BLOCK" in actions
        assert "PREVENTION_NO_ACTION" not in actions
        assert decision.action == DecisionAction.BLOCK.value
        assert (
            AuditLog.verify_chain(
                settings.AUDIT_HMAC_SECRET, sorted(stored, key=lambda row: int(row.id))
            )
            == []
        )

"""Alert deduplication, lifecycle, escalation, and non-blocking delivery tests."""

from __future__ import annotations

from contextlib import nullcontext
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from core.config import settings
from core.models.alert import (
    AlertComment,
    AlertEscalationRule,
    AlertSeverity,
    AlertStatus,
    Notification,
    NotificationChannel,
    NotificationStatus,
)
from core.models.mlops import AnalystFeedback
from utils.alerts import (
    _deliver_with_retry,
    add_comment,
    apply_escalations,
    assign_alert,
    create_alert_from_detection,
    create_operational_notification,
    make_dedup_key,
    record_feedback,
    transition_alert,
)


class TestDeduplication:
    def test_dedup_key_is_stable_within_bucket_and_changes_across_buckets(self):
        first = datetime(2026, 11, 21, 12, 1, tzinfo=UTC)
        second = first + timedelta(seconds=60)
        third = first + timedelta(minutes=10)
        assert make_dedup_key("1.2.3.4", "Bot", at=first) == make_dedup_key(
            "1.2.3.4", "Bot", at=second
        )
        assert make_dedup_key("1.2.3.4", "Bot", at=first) != make_dedup_key(
            "1.2.3.4", "Bot", at=third
        )

    def test_repeated_detection_aggregates_alert(self, db_session, make_detection):
        _flow, detection = make_detection(label="PortScan")
        first = create_alert_from_detection(db_session, detection)
        second = create_alert_from_detection(db_session, detection)
        assert first.id == second.id
        assert second.occurrence_count == 2

    def test_severity_escalation_notifies_only_on_increase(
        self, db_session, make_detection, monkeypatch
    ):
        monkeypatch.setattr(settings, "SLACK_WEBHOOK_URL", None)
        monkeypatch.setattr(settings, "TEAMS_WEBHOOK_URL", None)

        def dashboard_count() -> int:
            return len(
                db_session.execute(
                    select(Notification).where(
                        Notification.channel == NotificationChannel.DASHBOARD
                    )
                )
                .scalars()
                .all()
            )

        _flow, detection = make_detection(label="PortScan")
        alert = create_alert_from_detection(db_session, detection, severity="medium")
        assert alert.severity == AlertSeverity.MEDIUM
        assert dashboard_count() == 1

        escalated = create_alert_from_detection(
            db_session, detection, severity="critical"
        )
        assert escalated.severity == AlertSeverity.CRITICAL
        assert dashboard_count() == 2

        again = create_alert_from_detection(db_session, detection, severity="high")
        assert again.severity == AlertSeverity.CRITICAL
        assert dashboard_count() == 2


class TestDeliveryIsNonBlocking:
    def test_external_delivery_is_queued_not_executed_inline(
        self, db_session, make_detection, monkeypatch
    ):
        monkeypatch.setattr(settings, "SLACK_WEBHOOK_URL", "https://example.test/hook")
        monkeypatch.setattr(settings, "TEAMS_WEBHOOK_URL", None)
        queued: list[dict[str, object]] = []
        monkeypatch.setattr(
            "utils.alerts.enqueue_notification",
            lambda notification_id, payload: queued.append(payload),
        )
        called: list[object] = []
        monkeypatch.setattr(
            "utils.alerts.requests.post",
            lambda *args, **kwargs: called.append((args, kwargs)),
        )

        _flow, detection = make_detection(label="Bot")
        create_alert_from_detection(db_session, detection)
        assert called == []
        assert len(queued) == 1
        assert queued[0]["channel"] == "webhook"
        rows = (
            db_session.execute(
                select(Notification).where(
                    Notification.channel == NotificationChannel.WEBHOOK
                )
            )
            .scalars()
            .all()
        )
        assert len(rows) == 1
        assert rows[0].status == NotificationStatus.PENDING

    def test_retry_marks_notification_sent_then_failed(self, db_session, monkeypatch):
        notification = create_operational_notification(
            title="test", message="test", severity="high", db_session=db_session
        )
        monkeypatch.setattr(
            "utils.alerts.get_db_session", lambda: nullcontext(db_session)
        )
        monkeypatch.setattr("utils.alerts.time.sleep", lambda seconds: None)
        monkeypatch.setattr(settings, "ALERT_NOTIFICATION_MAX_ATTEMPTS", 3)

        attempts = {"count": 0}

        def flaky(payload):
            attempts["count"] += 1
            if attempts["count"] < 3:
                raise RuntimeError("temporary")

        monkeypatch.setattr("utils.alerts._dispatch_webhook", flaky)
        _deliver_with_retry(
            int(notification.id), {"channel": "webhook", "subject": "s", "message": "m"}
        )
        assert attempts["count"] == 3
        assert notification.status == NotificationStatus.SENT
        assert notification.attempts == 3

        def always_fails(payload):
            raise RuntimeError("permanent")

        monkeypatch.setattr("utils.alerts._dispatch_webhook", always_fails)
        attempts["count"] = 0
        _deliver_with_retry(
            int(notification.id), {"channel": "webhook", "subject": "s", "message": "m"}
        )
        assert notification.status == NotificationStatus.FAILED
        assert notification.error == "RuntimeError"


class TestAlertWorkflow:
    def test_lifecycle_transitions_and_comments(self, db_session, make_detection):
        _flow, detection = make_detection(label="Bot")
        alert = create_alert_from_detection(db_session, detection)
        assert alert.status == AlertStatus.NEW

        transition_alert(alert, AlertStatus.ACKNOWLEDGED, db_session=db_session)
        assert alert.status == AlertStatus.ACKNOWLEDGED
        with pytest.raises(ValueError):
            transition_alert(alert, AlertStatus.NEW, db_session=db_session)

        comment = add_comment(
            alert,
            comment="investigating",
            user_id=None,
            username="analyst",
            db_session=db_session,
        )
        assert comment.alert_id == alert.id
        assert (
            db_session.execute(
                select(AlertComment).where(AlertComment.alert_id == alert.id)
            )
            .scalars()
            .first()
            is not None
        )

        transition_alert(
            alert,
            AlertStatus.RESOLVED,
            notes="closed",
            db_session=db_session,
        )
        assert alert.status == AlertStatus.RESOLVED
        assert alert.resolved_at is not None
        with pytest.raises(ValueError):
            add_comment(
                alert, comment="   ", user_id=None, username="a", db_session=db_session
            )

    def test_assignment_and_feedback_never_retrain(
        self, db_session, make_detection, make_user
    ):
        analyst_id = make_user("alert_analyst")
        _flow, detection = make_detection(label="Bot")
        alert = create_alert_from_detection(db_session, detection)
        assign_alert(
            alert, user_id=analyst_id, username="alert_analyst", db_session=db_session
        )
        assert alert.assigned_user_id == analyst_id

        feedback = record_feedback(
            db_session,
            detection_id=int(detection.id),
            user_id=analyst_id,
            is_false_positive=True,
            verified_label="benign",
            alert=alert,
        )
        assert feedback.used_in_retraining is False
        assert alert.status == AlertStatus.FALSE_POSITIVE
        assert db_session.execute(select(AnalystFeedback)).scalars().first() is not None

    def test_escalation_rules_assign_and_notify(
        self, db_session, make_detection, make_user
    ):
        analyst_id = make_user("escalation_target")
        _flow, detection = make_detection(label="Bot")
        alert = create_alert_from_detection(db_session, detection, severity="critical")
        alert.created_at = datetime.now(UTC) - timedelta(minutes=30)
        db_session.add(
            AlertEscalationRule(
                name="critical-15m",
                severity=AlertSeverity.CRITICAL,
                after_minutes=15,
                target_user_id=analyst_id,
                is_active=True,
            )
        )
        db_session.flush()

        applied = apply_escalations(db_session)
        assert applied == 1
        assert alert.assigned_user_id == analyst_id
        assert (
            db_session.execute(
                select(Notification).where(Notification.alert_id == alert.id)
            )
            .scalars()
            .all()
        )

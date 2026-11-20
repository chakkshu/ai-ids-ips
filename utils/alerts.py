"""Alert creation, deduplication, workflow, and non-blocking delivery.

External delivery is optional and off by default. Notifications are queued to a
daemon worker so detection and prevention processing never waits on SMTP or a
webhook. Credentials are read from settings and are never logged.
"""

from __future__ import annotations

import hashlib
import json
import queue
import smtplib
import threading
import time
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from typing import Any

import requests
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from core.config import settings
from core.db import get_db_session
from core.logging import get_logger
from core.models.alert import (
    Alert,
    AlertComment,
    AlertEscalationRule,
    AlertSeverity,
    AlertStatus,
    Notification,
    NotificationChannel,
    NotificationStatus,
)
from core.models.detection import Detection
from core.models.mlops import AnalystFeedback
from core.models.network import NetworkFlow
from core.models.user import User
from core.security import audit_details, log_security_event

logger = get_logger(__name__)

DEDUP_BUCKET_SECONDS = 300

VALID_TRANSITIONS: dict[AlertStatus, frozenset[AlertStatus]] = {
    AlertStatus.NEW: frozenset(
        {
            AlertStatus.ACKNOWLEDGED,
            AlertStatus.INVESTIGATING,
            AlertStatus.RESOLVED,
            AlertStatus.FALSE_POSITIVE,
        }
    ),
    AlertStatus.ACKNOWLEDGED: frozenset(
        {
            AlertStatus.INVESTIGATING,
            AlertStatus.RESOLVED,
            AlertStatus.FALSE_POSITIVE,
        }
    ),
    AlertStatus.INVESTIGATING: frozenset(
        {
            AlertStatus.ACKNOWLEDGED,
            AlertStatus.RESOLVED,
            AlertStatus.FALSE_POSITIVE,
        }
    ),
    AlertStatus.RESOLVED: frozenset(),
    AlertStatus.FALSE_POSITIVE: frozenset(),
}

_SEVERITY_ORDER = {
    AlertSeverity.LOW: 0,
    AlertSeverity.MEDIUM: 1,
    AlertSeverity.HIGH: 2,
    AlertSeverity.CRITICAL: 3,
}

_notification_queue: queue.Queue[tuple[int, dict[str, Any]]] = queue.Queue()
_worker_lock = threading.Lock()
_worker: threading.Thread | None = None


def _coerce_severity(value: str | AlertSeverity) -> AlertSeverity:
    if isinstance(value, AlertSeverity):
        return value
    try:
        return AlertSeverity(value.lower())
    except ValueError:
        return AlertSeverity.MEDIUM


def make_dedup_key(src_ip: str, attack_type: str, *, at: datetime | None = None) -> str:
    """Return the stable five-minute-bucket deduplication key."""

    moment = at or datetime.now(UTC)
    bucket = int(moment.timestamp()) // DEDUP_BUCKET_SECONDS
    material = f"{src_ip}|{attack_type}|{bucket}".encode()
    return hashlib.sha256(material).hexdigest()


def _create_notification_row(
    db_session: Session,
    *,
    alert_id: int | None,
    channel: NotificationChannel,
    subject: str,
    message: str,
    user_id: int | None = None,
) -> Notification:
    row = Notification(
        alert_id=alert_id,
        user_id=user_id,
        channel=channel,
        subject=subject[:128],
        message=message,
        status=(
            NotificationStatus.SENT
            if channel == NotificationChannel.DASHBOARD
            else NotificationStatus.PENDING
        ),
        sent_at=datetime.now(UTC) if channel == NotificationChannel.DASHBOARD else None,
    )
    db_session.add(row)
    db_session.flush()
    return row


def enqueue_notification(notification_id: int, payload: dict[str, Any]) -> None:
    """Queue external delivery without blocking the calling transaction."""

    _notification_queue.put((notification_id, payload))
    _ensure_worker()


def _ensure_worker() -> None:
    """Start one daemon delivery worker if none is alive."""

    global _worker
    with _worker_lock:
        if _worker is not None and _worker.is_alive():
            return
        _worker = threading.Thread(
            target=_delivery_loop, name="alert-notification-worker", daemon=True
        )
        _worker.start()


def _delivery_loop() -> None:
    while True:
        notification_id, payload = _notification_queue.get()
        try:
            _deliver_with_retry(notification_id, payload)
        except Exception:
            logger.exception("Notification worker failed for id=%s", notification_id)
        finally:
            _notification_queue.task_done()


def _dispatch_email(payload: dict[str, Any]) -> None:
    """Send one alert email using environment-configured SMTP credentials."""

    if not settings.SMTP_HOST or not settings.ALERT_NOTIFICATION_EMAIL:
        raise RuntimeError("email delivery is not configured")
    message = EmailMessage()
    message["Subject"] = payload["subject"]
    message["From"] = settings.ALERT_FROM_EMAIL
    message["To"] = settings.ALERT_NOTIFICATION_EMAIL
    message.set_content(payload["message"])
    with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=5) as client:
        if settings.SMTP_USE_TLS:
            client.starttls()
        if settings.SMTP_USER and settings.SMTP_PASSWORD:
            client.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
        client.send_message(message)


def _dispatch_webhook(payload: dict[str, Any]) -> None:
    """Post a Slack/Teams-compatible message to a configured webhook."""

    url = settings.SLACK_WEBHOOK_URL or settings.TEAMS_WEBHOOK_URL
    if not url:
        raise RuntimeError("webhook delivery is not configured")
    response = requests.post(
        url,
        json={"text": f"{payload['subject']}\n{payload['message']}"},
        timeout=settings.ALERT_WEBHOOK_TIMEOUT_SECONDS,
    )
    response.raise_for_status()


def _deliver_with_retry(notification_id: int, payload: dict[str, Any]) -> None:
    attempts = 0
    last_error = "delivery failed"
    while attempts < settings.ALERT_NOTIFICATION_MAX_ATTEMPTS:
        attempts += 1
        try:
            if payload["channel"] == NotificationChannel.EMAIL.value:
                _dispatch_email(payload)
            else:
                _dispatch_webhook(payload)
        except Exception as exc:  # noqa: BLE001 - delivery boundary
            last_error = type(exc).__name__
            if attempts < settings.ALERT_NOTIFICATION_MAX_ATTEMPTS:
                time.sleep(settings.ALERT_NOTIFICATION_RETRY_SECONDS * attempts)
            continue

        with get_db_session() as db_session:
            row = db_session.get(Notification, notification_id)
            if row is not None:
                row.status = NotificationStatus.SENT
                row.attempts = attempts
                row.sent_at = datetime.now(UTC)
                row.error = None
        return

    with get_db_session() as db_session:
        row = db_session.get(Notification, notification_id)
        if row is not None:
            row.status = NotificationStatus.FAILED
            row.attempts = attempts
            row.error = last_error[:500]


def _queue_external_notifications(
    db_session: Session,
    *,
    alert_id: int,
    subject: str,
    message: str,
    severity: AlertSeverity,
) -> None:
    """Create dashboard rows and queue optional external deliveries."""

    _create_notification_row(
        db_session,
        alert_id=alert_id,
        channel=NotificationChannel.DASHBOARD,
        subject=subject,
        message=message,
    )
    payload = {
        "alert_id": alert_id,
        "subject": subject,
        "message": message,
        "severity": severity.value,
    }
    if settings.SMTP_HOST and settings.ALERT_NOTIFICATION_EMAIL:
        email_row = _create_notification_row(
            db_session,
            alert_id=alert_id,
            channel=NotificationChannel.EMAIL,
            subject=subject,
            message=message,
        )
        enqueue_notification(
            int(email_row.id), {**payload, "channel": NotificationChannel.EMAIL.value}
        )
    if settings.SLACK_WEBHOOK_URL or settings.TEAMS_WEBHOOK_URL:
        webhook_row = _create_notification_row(
            db_session,
            alert_id=alert_id,
            channel=NotificationChannel.WEBHOOK,
            subject=subject,
            message=message,
        )
        enqueue_notification(
            int(webhook_row.id),
            {**payload, "channel": NotificationChannel.WEBHOOK.value},
        )


def create_alert_from_detection(
    db_session: Session,
    detection: Detection,
    *,
    flow: NetworkFlow | None = None,
    severity: str | AlertSeverity | None = None,
    detail: str | None = None,
) -> Alert:
    """Create or aggregate an alert for one detection."""

    if detection.id is None:
        raise ValueError("detection must be persisted")
    network_flow = flow or db_session.get(NetworkFlow, detection.flow_id)
    if network_flow is None:
        raise ValueError("detection flow is missing")
    default_severity = "high" if detection.is_malicious else "medium"
    resolved_severity = _coerce_severity(severity or default_severity)
    attack_type = detection.predicted_label
    dedup_key = make_dedup_key(network_flow.src_ip, attack_type)

    existing = (
        db_session.execute(select(Alert).where(Alert.dedup_key == dedup_key))
        .scalars()
        .first()
    )
    if existing is not None:
        existing.occurrence_count = int(existing.occurrence_count) + 1
        if _SEVERITY_ORDER[resolved_severity] > _SEVERITY_ORDER[existing.severity]:
            existing.severity = resolved_severity
            _queue_external_notifications(
                db_session,
                alert_id=int(existing.id),
                subject=f"Escalated: {attack_type}",
                message=detail or f"Escalated alert for {network_flow.src_ip}",
                severity=resolved_severity,
            )
        return existing

    title = f"{attack_type} from {network_flow.src_ip}"
    description = detail or (
        f"Detection {detection.id} at {detection.timestamp.isoformat()} "
        f"with confidence {detection.confidence_score:.3f}"
    )
    alert = Alert(
        detection_id=int(detection.id),
        dedup_key=dedup_key,
        occurrence_count=1,
        title=title[:128],
        description=description,
        severity=resolved_severity,
        status=AlertStatus.NEW,
        src_ip=network_flow.src_ip,
        dst_ip=network_flow.dst_ip,
        dst_port=network_flow.dst_port,
        attack_type=attack_type,
    )
    db_session.add(alert)
    db_session.flush()
    _queue_external_notifications(
        db_session,
        alert_id=int(alert.id),
        subject=title,
        message=description,
        severity=resolved_severity,
    )
    return alert


def create_alert_from_decision(
    db_session: Session,
    decision: Any,
    *,
    detection: Detection | None = None,
    severity: str | None = None,
) -> Alert | None:
    """Create an alert tied to a prevention decision when a detection exists."""

    if detection is None and decision.candidate_id:
        from core.models.prevention import PreventionCandidate

        candidate = (
            db_session.execute(
                select(PreventionCandidate).where(
                    PreventionCandidate.candidate_id == decision.candidate_id
                )
            )
            .scalars()
            .first()
        )
        if candidate is not None and candidate.detection_id is not None:
            detection = db_session.get(Detection, int(candidate.detection_id))
    if detection is None:
        return None
    return create_alert_from_detection(
        db_session,
        detection,
        severity=severity or decision.severity,
        detail=f"Prevention decision {decision.id}: {decision.reason}",
    )


def create_operational_notification(
    *,
    title: str,
    message: str,
    severity: str,
    db_session: Session,
) -> Notification:
    """Create an in-app notification for a failed security operation."""

    row = _create_notification_row(
        db_session,
        alert_id=None,
        channel=NotificationChannel.DASHBOARD,
        subject=f"[{severity.upper()}] {title}",
        message=message[:4000],
    )
    return row


def transition_alert(
    alert: Alert,
    target: AlertStatus | str,
    *,
    user_id: int | None = None,
    username: str | None = None,
    notes: str | None = None,
    db_session: Session,
) -> Alert:
    """Apply a validated lifecycle transition."""

    target_enum = target if isinstance(target, AlertStatus) else AlertStatus(target)
    previous_status = alert.status
    if target_enum not in VALID_TRANSITIONS[previous_status]:
        raise ValueError(
            f"invalid alert transition: {previous_status.value}->{target_enum.value}"
        )
    alert.status = target_enum
    if notes:
        alert.resolution_notes = notes[:4000]
    if target_enum in {AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE}:
        alert.resolved_at = datetime.now(UTC)
    if user_id is not None:
        alert.assigned_user_id = user_id
        alert.assigned_username = (username or "analyst")[:64]
    log_security_event(
        action="ALERT_STATUS_CHANGED",
        resource_type="ALERT",
        resource_id=str(alert.id),
        user_id=user_id,
        username=username or "system",
        details=audit_details(
            from_status=previous_status.value,
            to_status=target_enum.value,
            notes=notes,
        ),
        db_session=db_session,
    )
    return alert


def assign_alert(
    alert: Alert,
    *,
    user_id: int,
    username: str,
    db_session: Session,
) -> Alert:
    """Assign an alert to an analyst and audit the action."""

    alert.assigned_user_id = user_id
    alert.assigned_username = username[:64]
    log_security_event(
        action="ALERT_ASSIGNED",
        resource_type="ALERT",
        resource_id=str(alert.id),
        user_id=user_id,
        username=username,
        details=audit_details(assigned_user_id=user_id),
        db_session=db_session,
    )
    return alert


def add_comment(
    alert: Alert,
    *,
    comment: str,
    user_id: int | None,
    username: str,
    db_session: Session,
) -> AlertComment:
    """Add an analyst comment to an alert."""

    if not comment.strip():
        raise ValueError("comment must not be empty")
    row = AlertComment(
        alert_id=int(alert.id),
        user_id=user_id,
        username=username[:64],
        comment=comment[:4000],
    )
    db_session.add(row)
    db_session.flush()
    return row


def record_feedback(
    db_session: Session,
    *,
    detection_id: int,
    user_id: int,
    is_false_positive: bool,
    verified_label: str,
    notes: str | None = None,
    alert: Alert | None = None,
) -> AnalystFeedback:
    """Store analyst ground truth for future retraining only; never retrain here."""

    if not verified_label.strip():
        raise ValueError("verified_label is required")
    row = AnalystFeedback(
        detection_id=detection_id,
        user_id=user_id,
        is_false_positive=is_false_positive,
        verified_label=verified_label[:64],
        analyst_notes=notes[:4000] if notes else None,
        used_in_retraining=False,
    )
    db_session.add(row)
    if alert is not None:
        target = (
            AlertStatus.FALSE_POSITIVE if is_false_positive else AlertStatus.RESOLVED
        )
        if target in VALID_TRANSITIONS[alert.status]:
            alert.status = target
            alert.resolved_at = datetime.now(UTC)
    log_security_event(
        action="ANALYST_FEEDBACK_RECORDED",
        resource_type="ANALYST_FEEDBACK",
        resource_id=f"detection:{detection_id}",
        user_id=user_id,
        status="SUCCESS",
        details=audit_details(
            is_false_positive=is_false_positive,
            verified_label=verified_label[:64],
            used_in_retraining=False,
        ),
        db_session=db_session,
    )
    db_session.flush()
    return row


def apply_escalations(db_session: Session, *, now: datetime | None = None) -> int:
    """Apply due severity escalation rules and return the number applied."""

    moment = now or datetime.now(UTC)
    rules = (
        db_session.execute(
            select(AlertEscalationRule).where(AlertEscalationRule.is_active.is_(True))
        )
        .scalars()
        .all()
    )
    applied = 0
    for rule in rules:
        due = (
            db_session.execute(
                select(Alert).where(
                    Alert.severity == rule.severity,
                    Alert.status.in_(
                        [
                            AlertStatus.NEW,
                            AlertStatus.ACKNOWLEDGED,
                            AlertStatus.INVESTIGATING,
                        ]
                    ),
                    Alert.created_at <= moment - timedelta(minutes=rule.after_minutes),
                )
            )
            .scalars()
            .all()
        )
        for alert in due:
            if rule.target_user_id is not None:
                target = db_session.get(User, rule.target_user_id)
                assign_alert(
                    alert,
                    user_id=rule.target_user_id,
                    username=getattr(target, "username", "escalation") or "escalation",
                    db_session=db_session,
                )
            _create_notification_row(
                db_session,
                alert_id=int(alert.id),
                channel=NotificationChannel.DASHBOARD,
                subject=f"Escalation: {alert.title}",
                message=f"Rule {rule.name} triggered for alert {alert.id}",
            )
            applied += 1
    return applied


def alert_counts(db_session: Session) -> dict[str, int]:
    """Return alert counts grouped by status for dashboard hooks."""

    rows = db_session.execute(
        select(Alert.status, func.count(Alert.id)).group_by(Alert.status)
    ).all()
    return {status.value: int(count) for status, count in rows}


def notification_payload_example() -> str:
    """Return a non-secret sample payload shape for documentation/tests."""

    return json.dumps(
        {"alert_id": 1, "subject": "example", "severity": "high"}, sort_keys=True
    )

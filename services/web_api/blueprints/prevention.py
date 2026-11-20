"""REST hooks for Phase 6 prevention, alerts, threat intel, and key management."""

from __future__ import annotations

import json
from typing import Any, TypeVar

from flask import Blueprint, jsonify, request
from flask_login import current_user
from pydantic import BaseModel, ValidationError
from sqlalchemy import select

from core.db import get_db_session
from core.logging import get_logger
from core.models.alert import Alert, AlertComment, Notification
from core.models.prevention import (
    BlockedIP,
    BlockStatus,
    Whitelist,
)
from core.models.threat import IPProfile
from core.models.user import User
from core.rbac import Permission
from core.schemas_prevention import (
    AlertAssign,
    AlertCommentCreate,
    AlertFeedbackCreate,
    AlertStatusUpdate,
    BlockCreate,
    BlockExtend,
    BlocklistImport,
    KeyRewrapRequest,
    KeyRotateRequest,
    PolicyUpdate,
    ThreatIntelRequest,
    WhitelistCreate,
    _validate_ip,
)
from core.security import audit_details, log_security_event, permission_required
from prevention.ip_blocker import BlockManager, PreventionError
from prevention.policy import PolicySettings, get_or_create_policy
from utils.alerts import (
    add_comment,
    assign_alert,
    record_feedback,
    transition_alert,
)
from utils.crypto import rewrap_sensitive_fields, rotate_kek
from utils.threat_intel import enrich_ip, export_blocklist, import_blocklist

logger = get_logger(__name__)

prevention_bp = Blueprint("prevention_api", __name__, url_prefix="/api/v1")

ModelT = TypeVar("ModelT", bound=BaseModel)


def _bad_request(message: str, status: int = 400):
    return jsonify({"error": message, "status": status}), status


def _payload(model: type[ModelT]) -> tuple[ModelT | None, Any | None]:
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return None, _bad_request("invalid_json")
    try:
        return model.model_validate(data), None
    except ValidationError as exc:
        return None, (
            jsonify(
                {
                    "error": "invalid_payload",
                    "status": 400,
                    "fields": [item["loc"][0] for item in exc.errors()],
                }
            ),
            400,
        )


def _actor() -> tuple[int | None, str]:
    if not current_user.is_authenticated:
        return None, "system"
    return int(current_user.id), str(current_user.username)


def _audit(action: str, resource_type: str, resource_id: str, **details: Any) -> None:
    user_id, username = _actor()
    log_security_event(
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        user_id=user_id,
        username=username,
        status="SUCCESS",
        details=audit_details(**details),
    )


def _block_view(block: BlockedIP) -> dict[str, Any]:
    return {
        "id": block.id,
        "ip_address": block.ip_address,
        "reason": block.reason,
        "status": block.status.value,
        "escalation_level": block.escalation_level,
        "blocked_at": block.blocked_at.isoformat() if block.blocked_at else None,
        "expires_at": block.expires_at.isoformat() if block.expires_at else None,
        "is_dry_run": block.is_dry_run,
        "firewall_rule_name": block.firewall_rule_name,
    }


def _alert_view(alert: Alert) -> dict[str, Any]:
    return {
        "id": alert.id,
        "title": alert.title,
        "description": alert.description,
        "severity": alert.severity.value,
        "status": alert.status.value,
        "src_ip": alert.src_ip,
        "dst_ip": alert.dst_ip,
        "dst_port": alert.dst_port,
        "attack_type": alert.attack_type,
        "occurrence_count": alert.occurrence_count,
        "assigned_username": alert.assigned_username,
        "detection_id": alert.detection_id,
        "created_at": alert.created_at.isoformat() if alert.created_at else None,
    }


@prevention_bp.get("/prevention/blocked-ips")
@permission_required(Permission.PREVENTION_VIEW)
def list_blocks():
    """List current and historical blocks."""

    with get_db_session() as db_session:
        blocks = (
            db_session.execute(select(BlockedIP).order_by(BlockedIP.blocked_at.desc()))
            .scalars()
            .all()
        )
        return jsonify({"blocks": [_block_view(block) for block in blocks]})


@prevention_bp.post("/prevention/blocked-ips")
@permission_required(Permission.PREVENTION_MANAGE)
def create_block():
    """Create an administrator-initiated temporary block."""

    payload, error = _payload(BlockCreate)
    if error is not None:
        return error
    if payload is None:
        return _bad_request("invalid_payload")
    actor_id, _username = _actor()
    with get_db_session() as db_session:
        manager = BlockManager(db_session, actor_user_id=actor_id)
        try:
            block = manager.block_ip(
                payload.ip_address,
                reason=payload.reason,
                duration_minutes=payload.duration_minutes,
                manual=True,
                actor_user_id=actor_id,
                admin_ip=request.remote_addr,
            )
        except PreventionError as exc:
            return _bad_request(str(exc), 422)
        return jsonify({"block": _block_view(block)}), 201


@prevention_bp.post("/prevention/blocked-ips/<int:block_id>/unblock")
@permission_required(Permission.PREVENTION_MANAGE)
def unblock(block_id: int):
    """Release an active or pending block."""

    reason = (request.get_json(silent=True) or {}).get("reason", "manual release")
    if not isinstance(reason, str) or not reason.strip():
        return _bad_request("invalid_reason")
    actor_id, _username = _actor()
    with get_db_session() as db_session:
        block = db_session.get(BlockedIP, block_id)
        if block is None:
            return _bad_request("block_not_found", 404)
        manager = BlockManager(db_session, actor_user_id=actor_id)
        try:
            released = manager.unblock_ip(
                block.ip_address,
                reason=reason,
                manual=True,
                actor_user_id=actor_id,
            )
        except PreventionError as exc:
            return _bad_request(str(exc), 422)
        return jsonify({"released": [_block_view(row) for row in released]})


@prevention_bp.post("/prevention/blocked-ips/<int:block_id>/extend")
@permission_required(Permission.PREVENTION_MANAGE)
def extend_block(block_id: int):
    """Extend an active block duration."""

    payload, error = _payload(BlockExtend)
    if error is not None:
        return error
    if payload is None:
        return _bad_request("invalid_payload")
    actor_id, _username = _actor()
    with get_db_session() as db_session:
        block = db_session.get(BlockedIP, block_id)
        if block is None:
            return _bad_request("block_not_found", 404)
        manager = BlockManager(db_session, actor_user_id=actor_id)
        try:
            updated = manager.extend_block(
                block_id,
                additional_minutes=payload.additional_minutes,
                actor_user_id=actor_id,
            )
        except PreventionError as exc:
            return _bad_request(str(exc), 422)
        return jsonify({"block": _block_view(updated)})


@prevention_bp.get("/prevention/whitelist")
@permission_required(Permission.PREVENTION_VIEW)
def list_whitelist():
    """List protected CIDRs."""

    with get_db_session() as db_session:
        rows = (
            db_session.execute(select(Whitelist).order_by(Whitelist.cidr))
            .scalars()
            .all()
        )
        return jsonify(
            {
                "whitelist": [
                    {
                        "id": row.id,
                        "cidr": row.cidr,
                        "description": row.description,
                        "is_immutable": row.is_immutable,
                    }
                    for row in rows
                ]
            }
        )


@prevention_bp.post("/prevention/whitelist")
@permission_required(Permission.PREVENTION_MANAGE)
def add_whitelist():
    """Add a validated protected CIDR."""

    payload, error = _payload(WhitelistCreate)
    if error is not None:
        return error
    if payload is None:
        return _bad_request("invalid_payload")
    actor_id, _username = _actor()
    with get_db_session() as db_session:
        manager = BlockManager(db_session, actor_user_id=actor_id)
        try:
            row = manager.add_whitelist(
                payload.cidr,
                payload.description,
                actor_user_id=actor_id,
            )
        except PreventionError as exc:
            return _bad_request(str(exc), 422)
        return jsonify({"cidr": row.cidr, "id": row.id}), 201


@prevention_bp.get("/prevention/policy")
@permission_required(Permission.PREVENTION_VIEW)
def get_policy():
    """Return the active prevention policy (no secrets)."""

    with get_db_session() as db_session:
        config = get_or_create_policy(db_session)
        return jsonify(
            {
                "name": config.name,
                "version": config.version,
                "policy": PolicySettings.from_config(config.config_json).model_dump(
                    mode="json"
                ),
            }
        )


@prevention_bp.put("/prevention/policy")
@permission_required(Permission.PREVENTION_MANAGE)
def update_policy():
    """Apply a strict partial update to the active policy."""

    payload, error = _payload(PolicyUpdate)
    if error is not None:
        return error
    if payload is None:
        return _bad_request("invalid_payload")
    updates = payload.model_dump(exclude_unset=True, mode="json")
    actor_id, username = _actor()
    with get_db_session() as db_session:
        config = get_or_create_policy(db_session, actor_user_id=actor_id)
        current = PolicySettings.from_config(config.config_json).model_dump(mode="json")
        if "rare_classes" in updates:
            updates["rare_classes"] = list(set(updates["rare_classes"]))
        merged = PolicySettings.model_validate({**current, **updates})
        config.config_json = json.dumps(merged.model_dump(mode="json"), sort_keys=True)
        config.updated_by_user_id = actor_id
        config.version = f"phase6-{config.id}-r{(config.version.rsplit('r', 1)[-1] if 'r' in config.version else '0')}"
        db_session.flush()
        _audit(
            "PREVENTION_POLICY_UPDATED",
            "PREVENTION_POLICY",
            str(config.id),
            actor=username,
            fields=sorted(updates),
        )
        return jsonify({"policy": merged.model_dump(mode="json")})


@prevention_bp.get("/prevention/approvals")
@permission_required(Permission.PREVENTION_MANAGE)
def list_approvals():
    """List blocks awaiting administrator approval."""

    with get_db_session() as db_session:
        rows = (
            db_session.execute(
                select(BlockedIP).where(
                    BlockedIP.status == BlockStatus.PENDING_APPROVAL
                )
            )
            .scalars()
            .all()
        )
        return jsonify({"approvals": [_block_view(row) for row in rows]})


@prevention_bp.post("/prevention/approvals/<int:block_id>/approve")
@permission_required(Permission.PREVENTION_MANAGE)
def approve_block(block_id: int):
    """Approve a pending block after explicit human review."""

    actor_id, _username = _actor()
    with get_db_session() as db_session:
        manager = BlockManager(db_session, actor_user_id=actor_id)
        try:
            block = manager.approve_block(block_id, actor_user_id=actor_id)
        except PreventionError as exc:
            return _bad_request(str(exc), 422)
        return jsonify({"block": _block_view(block)})


@prevention_bp.post("/prevention/approvals/<int:block_id>/reject")
@permission_required(Permission.PREVENTION_MANAGE)
def reject_block(block_id: int):
    """Reject a pending block without changing firewall state."""

    actor_id, _username = _actor()
    with get_db_session() as db_session:
        manager = BlockManager(db_session, actor_user_id=actor_id)
        try:
            block = manager.reject_block(block_id, actor_user_id=actor_id)
        except PreventionError as exc:
            return _bad_request(str(exc), 422)
        return jsonify({"block": _block_view(block)})


@prevention_bp.get("/alerts")
@permission_required(Permission.ALERT_VIEW)
def list_alerts():
    """List alerts for SOC dashboards."""

    with get_db_session() as db_session:
        rows = (
            db_session.execute(select(Alert).order_by(Alert.created_at.desc()))
            .scalars()
            .all()
        )
        return jsonify({"alerts": [_alert_view(alert) for alert in rows]})


@prevention_bp.get("/alerts/<int:alert_id>")
@permission_required(Permission.ALERT_VIEW)
def get_alert(alert_id: int):
    """Return one alert with comments and notifications."""

    with get_db_session() as db_session:
        alert = db_session.get(Alert, alert_id)
        if alert is None:
            return _bad_request("alert_not_found", 404)
        comments = (
            db_session.execute(
                select(AlertComment)
                .where(AlertComment.alert_id == alert_id)
                .order_by(AlertComment.created_at)
            )
            .scalars()
            .all()
        )
        notifications = (
            db_session.execute(
                select(Notification)
                .where(Notification.alert_id == alert_id)
                .order_by(Notification.created_at)
            )
            .scalars()
            .all()
        )
        return jsonify(
            {
                "alert": _alert_view(alert),
                "comments": [
                    {
                        "id": row.id,
                        "username": row.username,
                        "comment": row.comment,
                        "created_at": row.created_at.isoformat(),
                    }
                    for row in comments
                ],
                "notifications": [
                    {
                        "id": row.id,
                        "channel": row.channel.value,
                        "status": row.status.value,
                    }
                    for row in notifications
                ],
            }
        )


@prevention_bp.post("/alerts/<int:alert_id>/status")
@permission_required(Permission.ALERT_MANAGE)
def change_alert_status(alert_id: int):
    """Apply a validated alert lifecycle transition."""

    payload, error = _payload(AlertStatusUpdate)
    if error is not None:
        return error
    if payload is None:
        return _bad_request("invalid_payload")
    actor_id, username = _actor()
    with get_db_session() as db_session:
        alert = db_session.get(Alert, alert_id)
        if alert is None:
            return _bad_request("alert_not_found", 404)
        try:
            transition_alert(
                alert,
                payload.status,
                user_id=actor_id,
                username=username,
                notes=payload.notes,
                db_session=db_session,
            )
        except ValueError as exc:
            return _bad_request(str(exc), 422)
        return jsonify({"alert": _alert_view(alert)})


@prevention_bp.post("/alerts/<int:alert_id>/assign")
@permission_required(Permission.ALERT_MANAGE)
def assign_alert_route(alert_id: int):
    """Assign an alert to an analyst."""

    payload, error = _payload(AlertAssign)
    if error is not None:
        return error
    if payload is None:
        return _bad_request("invalid_payload")
    with get_db_session() as db_session:
        alert = db_session.get(Alert, alert_id)
        if alert is None:
            return _bad_request("alert_not_found", 404)
        target = db_session.get(User, payload.user_id)
        if target is None:
            return _bad_request("analyst_not_found", 404)
        assign_alert(
            alert,
            user_id=payload.user_id,
            username=target.username,
            db_session=db_session,
        )
        return jsonify({"alert": _alert_view(alert)})


@prevention_bp.post("/alerts/<int:alert_id>/comments")
@permission_required(Permission.ALERT_MANAGE)
def comment_alert(alert_id: int):
    """Add an analyst comment."""

    payload, error = _payload(AlertCommentCreate)
    if error is not None:
        return error
    if payload is None:
        return _bad_request("invalid_payload")
    actor_id, username = _actor()
    with get_db_session() as db_session:
        alert = db_session.get(Alert, alert_id)
        if alert is None:
            return _bad_request("alert_not_found", 404)
        add_comment(
            alert,
            comment=payload.comment,
            user_id=actor_id,
            username=username,
            db_session=db_session,
        )
        return jsonify({"comment": payload.comment}), 201


@prevention_bp.post("/alerts/<int:alert_id>/feedback")
@permission_required(Permission.ALERT_MANAGE)
def feedback_alert(alert_id: int):
    """Record analyst ground truth for future retraining only."""

    payload, error = _payload(AlertFeedbackCreate)
    if error is not None:
        return error
    if payload is None:
        return _bad_request("invalid_payload")
    actor_id, _username = _actor()
    if actor_id is None:
        return _bad_request("authentication_required", 401)
    with get_db_session() as db_session:
        alert = db_session.get(Alert, alert_id)
        if alert is None:
            return _bad_request("alert_not_found", 404)
        feedback = record_feedback(
            db_session,
            detection_id=int(alert.detection_id),
            user_id=actor_id,
            is_false_positive=payload.is_false_positive,
            verified_label=payload.verified_label,
            notes=payload.notes,
            alert=alert,
        )
        return jsonify({"feedback_id": feedback.id}), 201


@prevention_bp.get("/threat-intel/ips/<path:ip_address>")
@permission_required(Permission.THREAT_INTEL_VIEW)
def get_ip_profile(ip_address: str):
    """Return a stored IP profile and cached enrichment status."""

    try:
        normalized = _validate_ip(ip_address)
    except ValueError:
        return _bad_request("invalid_ip")
    with get_db_session() as db_session:
        profile = (
            db_session.execute(
                select(IPProfile).where(IPProfile.ip_address == normalized)
            )
            .scalars()
            .first()
        )
        if profile is None:
            return _bad_request("profile_not_found", 404)
        return jsonify(
            {
                "ip_address": profile.ip_address,
                "first_seen": profile.first_seen.isoformat(),
                "last_seen": profile.last_seen.isoformat(),
                "detection_count": profile.detection_count,
                "attack_types": json.loads(profile.attack_types_json or "[]"),
                "max_severity": profile.max_severity,
                "reverse_dns": profile.reverse_dns,
                "last_enriched_at": (
                    profile.last_enriched_at.isoformat()
                    if profile.last_enriched_at
                    else None
                ),
            }
        )


@prevention_bp.post("/threat-intel/enrich")
@permission_required(Permission.THREAT_INTEL_VIEW)
def enrich_ip_route():
    """Enrich a public IP via a fixed external provider."""

    payload, error = _payload(ThreatIntelRequest)
    if error is not None:
        return error
    if payload is None:
        return _bad_request("invalid_payload")
    with get_db_session() as db_session:
        try:
            result = enrich_ip(
                db_session, payload.ip_address, provider=payload.provider
            )
        except ValueError as exc:
            return _bad_request(str(exc), 422)
        return jsonify(result)


@prevention_bp.post("/threat-intel/blocklist/import")
@permission_required(Permission.THREAT_INTEL_MANAGE)
def import_blocklist_route():
    """Import a validated local blocklist."""

    payload, error = _payload(BlocklistImport)
    if error is not None:
        return error
    if payload is None:
        return _bad_request("invalid_payload")
    actor_id, _username = _actor()
    with get_db_session() as db_session:
        try:
            result = import_blocklist(
                db_session,
                payload.payload,
                format=payload.format,
                source=payload.source,
                actor_user_id=actor_id,
            )
        except (ValueError, PermissionError) as exc:
            return _bad_request(str(exc), 422)
        _audit(
            "THREAT_BLOCKLIST_IMPORTED",
            "THREAT_BLOCKLIST",
            "bulk",
            **result,
        )
        return jsonify(result)


@prevention_bp.get("/threat-intel/blocklist/export")
@permission_required(Permission.THREAT_INTEL_VIEW)
def export_blocklist_route():
    """Export the local blocklist."""

    export_format = request.args.get("format", "json")
    if export_format not in {"json", "csv"}:
        return _bad_request("invalid_format")
    with get_db_session() as db_session:
        payload = export_blocklist(db_session, format=export_format)  # type: ignore[arg-type]
        if export_format == "csv":
            return (
                payload,
                200,
                {"Content-Type": "text/csv; charset=utf-8"},
            )
        return jsonify(json.loads(payload))


@prevention_bp.post("/keys/rotate")
@permission_required(Permission.KEYS_MANAGE)
def rotate_key_route():
    """Register/activate a KEK whose material is supplied via environment."""

    payload, error = _payload(KeyRotateRequest)
    if error is not None:
        return error
    if payload is None:
        return _bad_request("invalid_payload")
    import os

    from core.crypto import CryptoError

    material = os.environ.get(payload.kek_env_var)
    if not material:
        return _bad_request("kek_environment_variable_missing", 422)
    try:
        result = rotate_kek(
            key_id=payload.key_id, kek_hex=material, activate=payload.activate
        )
    except CryptoError as exc:
        return _bad_request(str(exc), 422)
    _audit(
        "ENCRYPTION_KEY_ROTATED",
        "ENCRYPTION_KEY",
        result["active_key_id"],
        previous_key_id=result["previous_key_id"],
    )
    return jsonify(result)


@prevention_bp.post("/keys/rewrap")
@permission_required(Permission.KEYS_MANAGE)
def rewrap_keys_route():
    """Start an audited, resumable re-encryption of sensitive fields."""

    payload, error = _payload(KeyRewrapRequest)
    if error is not None:
        return error
    if payload is None:
        return _bad_request("invalid_payload")
    actor_id, _username = _actor()
    with get_db_session() as db_session:
        try:
            result = rewrap_sensitive_fields(
                db_session,
                target_key_id=payload.target_key_id,
                actor_user_id=actor_id,
                batch_size=payload.batch_size,
            )
        except Exception as exc:  # noqa: BLE001
            return _bad_request(type(exc).__name__, 422)
        return jsonify(result)


__all__ = ["prevention_bp"]

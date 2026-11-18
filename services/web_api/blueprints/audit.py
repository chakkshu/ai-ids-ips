"""Audit Ledger & Forensic Integrity Blueprint.

Provides read-only access to hash-chained audit trails and triggers
cryptographic verification. Viewers can read; Analysts and Admins can verify.
"""

from __future__ import annotations

from flask import Blueprint, flash, redirect, render_template, url_for
from flask_login import current_user

from core.config import settings
from core.db import get_db_session
from core.models.audit import AuditLog
from core.rbac import Permission
from core.security import audit_details, log_security_event, permission_required

audit_bp = Blueprint("audit", __name__, url_prefix="/audit")


@audit_bp.route("")
@permission_required(Permission.AUDIT_VIEW)
def index():
    """Display the tamper-evident audit ledger entries."""
    with get_db_session() as db_session:
        logs = db_session.query(AuditLog).order_by(AuditLog.id.desc()).limit(100).all()
        return render_template("audit/index.html", logs=logs)


@audit_bp.route("/verify", methods=["POST"])
@permission_required(Permission.AUDIT_VERIFY)
def verify():
    """Cryptographically verify the HMAC-SHA256 hash chain from genesis."""
    with get_db_session() as db_session:
        logs = db_session.query(AuditLog).order_by(AuditLog.id.asc()).all()
        if not logs:
            flash("Audit ledger is empty. Chain is pristine.", "info")
            return redirect(url_for("audit.index"))

        broken_ids = AuditLog.verify_chain(settings.AUDIT_HMAC_SECRET, logs)
        if not broken_ids:
            log_security_event(
                action="AUDIT_CHAIN_VERIFIED",
                resource_type="AUDIT_LEDGER",
                user_id=current_user.id,
                username=current_user.username,
                status="SUCCESS",
                details=audit_details(entries=len(logs)),
                db_session=db_session,
            )
            flash(
                f"Cryptographic Audit Passed: All {len(logs)} entries in the "
                f"ledger chain are valid.",
                "success",
            )
        else:
            log_security_event(
                action="AUDIT_CHAIN_TAMPER_DETECTED",
                resource_type="AUDIT_LEDGER",
                resource_id=str(broken_ids[0]),
                user_id=current_user.id,
                username=current_user.username,
                status="FAILED",
                details=audit_details(first_broken_entry=broken_ids[0]),
                db_session=db_session,
            )
            flash(
                f"CRITICAL WARNING: Ledger integrity breach detected starting at "
                f"Record #{broken_ids[0]}!",
                "error",
            )

        return redirect(url_for("audit.index"))

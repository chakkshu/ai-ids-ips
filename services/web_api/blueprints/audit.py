"""Audit Ledger & Forensic Integrity Blueprint.

Provides read-only access to hash-chained audit trails and triggers verification.
"""

from __future__ import annotations

from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    url_for,
)
from flask_login import login_required

from core.config import settings
from core.db import get_db_session
from core.models.audit import GENESIS_HASH, AuditLog
from core.models.user import UserRole
from core.security import role_required

audit_bp = Blueprint("audit", __name__, url_prefix="/audit")


@audit_bp.route("")
@login_required
@role_required(UserRole.VIEWER)  # Viewers, Analysts, and Admins can audit
def index():
    """Display the tamper-evident audit ledger entries."""
    with get_db_session() as db_session:
        logs = (
            db_session.query(AuditLog)
            .order_by(AuditLog.id.desc())
            .limit(100)
            .all()
        )
        return render_template("audit/index.html", logs=logs)


@audit_bp.route("/verify", methods=["POST"])
@login_required
@role_required(UserRole.ANALYST)
def verify():
    """Cryptographically audit the HMAC-SHA256 hash chain from genesis."""
    with get_db_session() as db_session:
        logs = db_session.query(AuditLog).order_by(AuditLog.id.asc()).all()
        
        if not logs:
            flash("Audit ledger is empty. Chain is pristine.", "info")
            return redirect(url_for("audit.index"))

        expected_prev_hash = GENESIS_HASH
        tampered_entries = []

        for entry in logs:
            if entry.previous_hash != expected_prev_hash:
                tampered_entries.append((entry.id, "previous_hash_mismatch"))
                break

            recomputed = AuditLog.compute_hash(
                hmac_key=settings.AUDIT_HMAC_SECRET,
                prev_hash=entry.previous_hash,
                timestamp=entry.timestamp,
                user_id=entry.user_id,
                action=entry.action,
                resource_type=entry.resource_type,
                resource_id=entry.resource_id,
                status=entry.status,
                details_json=entry.details,
            )

            if recomputed != entry.entry_hash:
                tampered_entries.append((entry.id, "entry_hash_mismatch"))
                break

            expected_prev_hash = entry.entry_hash

        if not tampered_entries:
            flash(f"Cryptographic Audit Passed: All {len(logs)} entries in the ledger chain are valid.", "success")
        else:
            first_corrupted_id = tampered_entries[0][0]
            flash(f"CRITICAL WARNING: Ledger integrity breach detected starting at Record #{first_corrupted_id}!", "error")

        return redirect(url_for("audit.index"))

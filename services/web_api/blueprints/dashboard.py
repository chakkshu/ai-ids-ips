"""SOC Operations Dashboard Blueprint.

Renders real-time overview metrics, sensor statuses, and recent detection feeds.
Access is governed by the explicit permission matrix (``dashboard:view``).
"""

from __future__ import annotations

from flask import Blueprint, redirect, render_template, url_for

from core.db import get_db_session
from core.models.alert import Alert
from core.models.detection import Detection
from core.models.network import NetworkFlow
from core.models.prevention import BlockedIP, BlockStatus
from core.rbac import Permission
from core.security import permission_required

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
def root():
    """Redirect root to dashboard."""
    return redirect(url_for("dashboard.index"))


@dashboard_bp.route("/dashboard")
@permission_required(Permission.DASHBOARD_VIEW)
def index():
    """Render the central SOC operations dashboard."""
    with get_db_session() as db_session:
        total_flows = db_session.query(NetworkFlow).count()
        malicious_count = (
            db_session.query(Detection).filter_by(is_malicious=True).count()
        )
        active_alerts = (
            db_session.query(Alert).filter(Alert.status != "resolved").count()
        )
        blocked_ips_count = (
            db_session.query(BlockedIP).filter_by(status=BlockStatus.ACTIVE).count()
        )

        recent_alerts = (
            db_session.query(Alert).order_by(Alert.created_at.desc()).limit(10).all()
        )

        stats = {
            "total_flows": total_flows,
            "malicious_detections": malicious_count,
            "active_alerts": active_alerts,
            "blocked_ips": blocked_ips_count,
        }

        return render_template(
            "dashboard/index.html",
            stats=stats,
            recent_alerts=recent_alerts,
        )

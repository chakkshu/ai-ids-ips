"""Health and Readiness Diagnostics Blueprint."""

from __future__ import annotations

from flask import Blueprint, jsonify
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from core.db import get_engine
from core.logging import get_logger

logger = get_logger(__name__)

health_bp = Blueprint("health", __name__, url_prefix="/api/v1/health")


@health_bp.route("/live")
def liveness():
    """Liveness probe returning 200 OK if web server is responsive."""
    return jsonify({"status": "healthy", "service": "web-api"}), 200


@health_bp.route("/ready")
def readiness():
    """Readiness probe checking database connectivity."""
    db_ok = False
    try:
        engine = get_engine()
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
            db_ok = True
    except (SQLAlchemyError, OSError) as exc:
        logger.warning(f"Readiness DB probe failed: {exc}")

    if db_ok:
        return jsonify({"status": "ready", "database": "connected"}), 200
    return jsonify({"status": "degraded", "database": "disconnected"}), 503

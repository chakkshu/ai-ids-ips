"""AI-IDS/IPS Flask Application Factory.

Configures authentication, CSRF defenses, rate limiting, WebSockets,
security response headers, and correlation tracking.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from flask import Flask, g, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager
from flask_socketio import SocketIO
from flask_wtf.csrf import CSRFProtect

from core.config import settings
from core.db import get_db_session
from core.logging import set_correlation_id
from core.models.user import User

# Global extension singletons
login_manager = LoginManager()
csrf = CSRFProtect()
socketio = SocketIO()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["1000 per hour", "100 per minute"],
)


@login_manager.user_loader
def load_user(user_id: str) -> User | None:
    """Load user by ID for Flask-Login session management."""
    try:
        user_int_id = int(user_id)
    except (ValueError, TypeError):
        return None

    try:
        with get_db_session() as db_session:
            user = db_session.query(User).filter_by(id=user_int_id).first()
            if user and user.is_active:
                # Expunge object so it can be detached safely across request lifecycle
                db_session.expunge(user)
                return user
    except (ValueError, TypeError, KeyError):
        return None
    return None


def create_app(config_overrides: dict[str, Any] | None = None) -> tuple[Flask, SocketIO]:
    """Flask Application Factory."""
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )

    # 1. Base Configuration & Session Hardening
    app.config.update(
        SECRET_KEY=settings.APP_SECRET_KEY,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=(settings.APP_ENV == "production"),
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
        WTF_CSRF_TIME_LIMIT=3600,
    )

    if config_overrides:
        app.config.update(config_overrides)

    # 2. Initialize Extensions
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message_category = "warning"
    login_manager.session_protection = "strong"

    csrf.init_app(app)
    limiter.init_app(app)
    socketio.init_app(app, cors_allowed_origins="*")

    # 3. Correlation ID & Context Middleware
    @app.before_request
    def before_request_hook():
        incoming_cid = request.headers.get("X-Correlation-ID")
        g.correlation_id = set_correlation_id(incoming_cid)

    # 4. Enterprise Defensive Security Headers Middleware
    @app.after_request
    def apply_security_headers(response):
        # Prevent MIME-sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        # Prevent Clickjacking
        response.headers["X-Frame-Options"] = "DENY"
        # HSTS enforcement
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        # Referrer Policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        # Content Security Policy (OWASP ASVS compliant)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "font-src 'self' https://cdn.jsdelivr.net; "
            "img-src 'self' data:; "
            "connect-src 'self' ws: wss:; "
            "frame-ancestors 'none';"
        )
        # Propagate Correlation ID to response
        if hasattr(g, "correlation_id"):
            response.headers["X-Correlation-ID"] = g.correlation_id
        return response

    # 5. Register Blueprints
    from services.web_api.blueprints.audit import audit_bp
    from services.web_api.blueprints.auth import auth_bp
    from services.web_api.blueprints.dashboard import dashboard_bp
    from services.web_api.blueprints.health import health_bp
    from services.web_api.blueprints.users import users_bp

    app.register_blueprint(dashboard_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(audit_bp)
    app.register_blueprint(health_bp)

    return app, socketio

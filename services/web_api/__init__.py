"""AI-IDS/IPS Flask Application Factory.

Configures authentication, server-side session enforcement, CSRF defenses,
rate limiting, trusted-proxy handling, WebSockets, nonce-based security headers,
and correlation tracking.
"""

from __future__ import annotations

import secrets
from datetime import timedelta
from typing import Any

from flask import (
    Flask,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager, current_user, logout_user
from flask_socketio import SocketIO
from flask_wtf.csrf import CSRFError, CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix

from core.config import settings
from core.db import get_db_session
from core.logging import get_correlation_id, get_logger, set_correlation_id
from core.models.user import User
from core.rbac import Permission, has_permission
from core.security import validate_user_session

logger = get_logger(__name__)

# Global extension singletons
login_manager = LoginManager()
csrf = CSRFProtect()
socketio = SocketIO()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["1000 per hour", "100 per minute"],
    headers_enabled=True,
)


@login_manager.user_loader
def load_user(user_id: str) -> User | None:
    """Load an active user by ID for Flask-Login session management."""
    try:
        user_int_id = int(user_id)
    except (ValueError, TypeError):
        return None

    try:
        with get_db_session() as db_session:
            user = db_session.query(User).filter_by(id=user_int_id).first()
            if user and user.is_active:
                db_session.expunge(user)
                return user
    except (ValueError, TypeError, KeyError):
        return None
    return None


def _is_public_endpoint(endpoint: str | None) -> bool:
    """Endpoints that must remain reachable without an authenticated session."""
    return endpoint in {
        "static",
        "auth.login",
        "auth.login_2fa",
        "auth.logout",
        "health.liveness",
        "health.readiness",
    }


def _wants_json() -> bool:
    """Return True when the caller expects a JSON response."""
    if request.path.startswith("/api/") or request.is_json:
        return True
    accept = request.accept_mimetypes
    # HTML wins ties (e.g. browsers sending ``*/*``); JSON needs a strict
    # preference so regular browser navigation keeps receiving HTML responses.
    return bool(accept["application/json"] > accept["text/html"])


def create_app(
    config_overrides: dict[str, Any] | None = None,
) -> tuple[Flask, SocketIO]:
    """Flask Application Factory."""
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )

    # 1. Base configuration and hardened cookies.
    app.config.update(
        SECRET_KEY=settings.APP_SECRET_KEY,
        SESSION_COOKIE_NAME="ai_ids_session",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE=settings.SESSION_COOKIE_SAMESITE,
        SESSION_COOKIE_SECURE=(settings.APP_ENV == "production"),
        PERMANENT_SESSION_LIFETIME=timedelta(
            hours=settings.SESSION_ABSOLUTE_TIMEOUT_HOURS
        ),
        WTF_CSRF_TIME_LIMIT=3600,
        WTF_CSRF_HEADERS=["X-CSRFToken", "X-CSRF-Token"],
        WTF_CSRF_SSL_STRICT=(settings.APP_ENV == "production"),
        RATELIMIT_STORAGE_URI=settings.get_rate_limit_storage_uri(),
        RATELIMIT_HEADERS_ENABLED=True,
        RATELIMIT_SWALLOW_ERRORS=False,
        TRUSTED_PROXY_HOPS=settings.TRUSTED_PROXY_HOPS,
    )

    if config_overrides:
        app.config.update(config_overrides)

    # 2. Initialize extensions.
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message_category = "warning"
    login_manager.session_protection = "strong"

    csrf.init_app(app)
    limiter.init_app(app)
    socketio.init_app(
        app,
        cors_allowed_origins=settings.get_socketio_origins(),
        manage_session=False,
    )

    # 3. Trust X-Forwarded-* only from a configured, exact proxy hop count.
    # Applied last so ProxyFix is the outermost WSGI layer and both HTTP and
    # WebSocket traffic observe the corrected scheme/host/client address.
    proxy_hops = int(app.config.get("TRUSTED_PROXY_HOPS", 0) or 0)
    if proxy_hops > 0:
        app.wsgi_app = ProxyFix(  # type: ignore[method-assign]
            app.wsgi_app,
            x_for=proxy_hops,
            x_proto=proxy_hops,
            x_host=proxy_hops,
            x_port=proxy_hops,
            x_prefix=0,
        )

    # 4. Correlation ID, CSP nonce, and global session enforcement.
    @app.before_request
    def before_request_hook() -> Any:
        if request.endpoint == "static":
            return None

        g.csp_nonce = secrets.token_urlsafe(16)
        incoming_cid = request.headers.get("X-Correlation-ID")
        g.correlation_id = set_correlation_id(incoming_cid)

        # Enforce server-side session validity for authenticated requests.
        if current_user.is_authenticated:
            sid = session.get("sid")
            if not isinstance(sid, str) or not sid:
                logout_user()
                session.clear()
                if _is_public_endpoint(request.endpoint):
                    return None
                if _wants_json():
                    return jsonify({"error": "session_invalid", "status": 401}), 401
                return redirect(url_for("auth.login"))

            with get_db_session() as db_session:
                record = validate_user_session(sid, db_session)
                if record is None or record.user_id != current_user.id:
                    logout_user()
                    session.clear()
                    if _is_public_endpoint(request.endpoint):
                        return None
                    if _wants_json():
                        return (
                            jsonify({"error": "session_expired", "status": 401}),
                            401,
                        )
                    return redirect(url_for("auth.login"))

            if current_user.must_change_password:
                allowed = {
                    "auth.change_password",
                    "auth.logout",
                    "health.liveness",
                    "health.readiness",
                }
                if request.endpoint not in allowed:
                    if _wants_json():
                        return (
                            jsonify(
                                {"error": "password_change_required", "status": 403}
                            ),
                            403,
                        )
                    return redirect(url_for("auth.change_password"))

            if (
                current_user.is_totp_enabled
                and not session.get("is_2fa_verified", False)
                and request.endpoint not in {"auth.logout", "static"}
            ):
                logout_user()
                session.clear()
                if _wants_json():
                    return jsonify({"error": "two_factor_required", "status": 401}), 401
                return redirect(url_for("auth.login"))
        else:
            # Remove stale server-side session markers from anonymous cookies.
            session.pop("sid", None)
            session.pop("is_2fa_verified", None)

        return None

    # 5. Defensive response headers with a nonce-based CSP.
    @app.after_request
    def apply_security_headers(response):
        nonce = getattr(g, "csp_nonce", "")
        script_src = (
            f"script-src 'self' 'nonce-{nonce}'" if nonce else "script-src 'self'"
        )
        directives = [
            "default-src 'self'",
            script_src,
            "style-src 'self'",
            "font-src 'self'",
            "img-src 'self' data:",
            "connect-src 'self' ws: wss:",
            "object-src 'none'",
            "base-uri 'self'",
            "form-action 'self'",
            "frame-ancestors 'none'",
        ]
        if settings.APP_ENV == "production":
            directives.append("upgrade-insecure-requests")

        response.headers["Content-Security-Policy"] = "; ".join(directives)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), payment=()"
        )
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        if settings.APP_ENV == "production":
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )
        if response.mimetype == "text/html":
            response.headers.setdefault("Cache-Control", "no-store")
        if hasattr(g, "correlation_id"):
            response.headers["X-Correlation-ID"] = g.correlation_id
        return response

    # 6. Template helpers.
    @app.context_processor
    def inject_security_context() -> dict[str, Any]:
        def can(permission: Permission | str) -> bool:
            return bool(
                current_user.is_authenticated
                and has_permission(current_user.role, permission)
            )

        return {
            "csp_nonce": getattr(g, "csp_nonce", ""),
            "can": can,
            "Permission": Permission,
            "correlation_id": getattr(g, "correlation_id", get_correlation_id()),
        }

    # 7. Error handlers.
    @app.errorhandler(CSRFError)
    def handle_csrf_error(error: CSRFError):
        logger.warning("CSRF validation failed: %s", error.description)
        return render_template("errors/400.html", reason=error.description), 400

    @app.errorhandler(401)
    def handle_401(error):
        if _wants_json():
            return jsonify({"error": "authentication_required", "status": 401}), 401
        return render_template("errors/401.html"), 401

    @app.errorhandler(403)
    def handle_403(error):
        if _wants_json():
            return jsonify({"error": "forbidden", "status": 403}), 403
        return render_template("errors/403.html"), 403

    @app.errorhandler(404)
    def handle_404(error):
        if _wants_json():
            return jsonify({"error": "not_found", "status": 404}), 404
        return render_template("errors/404.html"), 404

    @app.errorhandler(500)
    def handle_500(error):
        logger.exception("Unhandled server error")
        if _wants_json():
            return jsonify({"error": "internal_error", "status": 500}), 500
        return render_template("errors/500.html"), 500

    # 8. Register blueprints.
    from services.web_api.blueprints.audit import audit_bp
    from services.web_api.blueprints.auth import auth_bp
    from services.web_api.blueprints.dashboard import dashboard_bp
    from services.web_api.blueprints.health import health_bp
    from services.web_api.blueprints.prevention import prevention_bp
    from services.web_api.blueprints.users import users_bp

    app.register_blueprint(prevention_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(audit_bp)
    app.register_blueprint(health_bp)

    return app, socketio

"""Web API & Dashboard Service Package."""

from typing import Tuple, Any

def create_app() -> Tuple[Any, Any]:
    """Application factory for Flask API and Flask-SocketIO (Detailed in Phase 2)."""
    from flask import Flask
    from flask_socketio import SocketIO
    from core.config import settings

    app = Flask(__name__)
    app.config["SECRET_KEY"] = settings.APP_SECRET_KEY
    socketio = SocketIO(app, cors_allowed_origins="*")

    @app.route("/api/v1/health/live")
    def liveness():
        return {"status": "ok", "service": "web-api"}, 200

    @app.route("/api/v1/health/ready")
    def readiness():
        return {"status": "ready", "service": "web-api"}, 200

    return app, socketio

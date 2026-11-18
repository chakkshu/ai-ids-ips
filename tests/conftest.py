"""Shared pytest fixtures for the AI-IDS/IPS test suite.

The application settings and the SQLAlchemy engine are created at import time,
so the test environment must be configured *before* any ``core.*`` module is
imported. This module therefore sets the environment first and only then
imports the application factory, models, and security helpers.

Tests run against an isolated, temporary SQLite database. PostgreSQL-specific
behaviour is exercised separately through Alembic and the docker-compose stack.
"""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Environment configuration (must happen before importing the application)
# ---------------------------------------------------------------------------

_EXTERNAL_DB_URL = os.environ.get("AI_IDS_TEST_DATABASE_URL")
_DB_PATH: str | None = None
if _EXTERNAL_DB_URL:
    # Opt-in: run the same suite against a real PostgreSQL instance, e.g.
    # AI_IDS_TEST_DATABASE_URL=postgresql+psycopg2://...@127.0.0.1:55432/ai_ids_ips
    os.environ["DATABASE_URL"] = _EXTERNAL_DB_URL
else:
    _DB_FD, _DB_PATH = tempfile.mkstemp(prefix="ai_ids_test_", suffix=".sqlite3")
    os.close(_DB_FD)
    os.environ["DATABASE_URL"] = f"sqlite:///{Path(_DB_PATH).as_posix()}"

os.environ["APP_ENV"] = "testing"
os.environ["APP_DEBUG"] = "False"
os.environ["APP_SECRET_KEY"] = "test-secret-key-" + ("a" * 48)
os.environ["APP_MASTER_KEK"] = "ab" * 32
os.environ["AUDIT_HMAC_SECRET"] = "cd" * 32

# Keep Argon2id deliberately cheap in tests while exercising the same code path.
os.environ["ARGON2_TIME_COST"] = "1"
os.environ["ARGON2_MEMORY_COST"] = "8192"
os.environ["ARGON2_PARALLELISM"] = "1"
os.environ["ARGON2_HASH_LEN"] = "32"
os.environ["ARGON2_SALT_LEN"] = "16"

os.environ["PASSWORD_MIN_LENGTH"] = "12"
os.environ["PASSWORD_HISTORY_DEPTH"] = "5"
os.environ["LOGIN_MAX_ATTEMPTS"] = "5"
os.environ["LOGIN_LOCKOUT_MINUTES"] = "15"
os.environ["SESSION_IDLE_TIMEOUT_MINUTES"] = "30"
os.environ["SESSION_ABSOLUTE_TIMEOUT_HOURS"] = "8"
os.environ["SESSION_COOKIE_SAMESITE"] = "Strict"
os.environ["TRUSTED_PROXY_HOPS"] = "0"
os.environ["RATELIMIT_STORAGE_URI"] = "memory://"
os.environ["RECOVERY_CODE_COUNT"] = "10"

# Imported only after the environment is in place.
import core.models  # noqa: F401  (registers all ORM tables)
from core.db import Base, ScopedSession, engine, get_db_session
from core.models.user import User, UserRole
from core.security import hash_password, record_password_history
from services.web_api import create_app, limiter

DEFAULT_PASSWORD = "ValidPassw0rd!2026"
SECOND_PASSWORD = "An0ther-Str0ng-Passphrase!"

_CSRF_INPUT_RE = re.compile(r'name="csrf_token"[^>]*value="([^"]+)"')
_CSRF_META_RE = re.compile(r'<meta name="csrf-token" content="([^"]+)"')


# ---------------------------------------------------------------------------
# Application / database lifecycle
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def app():
    """Session-scoped Flask application with CSRF and rate limiting enabled."""
    application, _socketio = create_app(
        {
            "TESTING": True,
            "WTF_CSRF_ENABLED": True,
            "RATELIMIT_ENABLED": True,
            "RATELIMIT_STORAGE_URI": "memory://",
            "PROPAGATE_EXCEPTIONS": False,
        }
    )
    yield application


@pytest.fixture(autouse=True)
def _fresh_state(app):
    """Reset tables and rate-limit counters before every test."""
    ScopedSession.remove()
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    limiter.reset()
    yield
    ScopedSession.remove()


@pytest.fixture
def client(app):
    """Flask test client bound to the session-scoped application."""
    test_client = app.test_client()
    yield test_client
    test_client.__exit__(None, None, None)


@pytest.fixture
def db_session():
    """Short-lived SQLAlchemy session for direct test assertions."""
    session = ScopedSession()
    try:
        yield session
    finally:
        session.rollback()
        session.close()
        ScopedSession.remove()


# ---------------------------------------------------------------------------
# Domain helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def make_user():
    """Factory that provisions an active, policy-compliant console user."""

    def _make(
        username: str = "analyst",
        role: UserRole = UserRole.VIEWER,
        password: str = DEFAULT_PASSWORD,
        *,
        email: str | None = None,
        must_change_password: bool = False,
        is_active: bool = True,
        is_totp_enabled: bool = False,
        totp_secret: str | None = None,
        totp_last_step: int | None = None,
        failed_login_attempts: int = 0,
        locked_until=None,
    ) -> int:
        with get_db_session() as session:
            user = User(
                username=username,
                email=email or f"{username}@example.test",
                password_hash=hash_password(password),
                role=role,
                is_active=is_active,
                must_change_password=must_change_password,
                is_totp_enabled=is_totp_enabled,
                totp_secret=totp_secret,
                totp_last_step=totp_last_step,
                failed_login_attempts=failed_login_attempts,
                locked_until=locked_until,
            )
            session.add(user)
            session.flush()
            record_password_history(user, user.password_hash, session)
            return int(user.id)

    return _make


@pytest.fixture
def csrf_token(client):
    """Return a callable that extracts a valid CSRF token from a page."""

    def _token(path: str = "/login") -> str:
        response = client.get(path)
        body = response.get_data(as_text=True)
        match = _CSRF_INPUT_RE.search(body) or _CSRF_META_RE.search(body)
        assert match is not None, f"No CSRF token rendered on {path!r}"
        return match.group(1)

    return _token


@pytest.fixture
def login(client, csrf_token):
    """Sign a user in through the real login form."""

    def _login(username: str, password: str = DEFAULT_PASSWORD):
        token = csrf_token("/login")
        return client.post(
            "/login",
            data={
                "username": username,
                "password": password,
                "csrf_token": token,
            },
        )

    return _login


@pytest.fixture
def auth_client(app, make_user, login):
    """Return ``(client, user_id)`` for a signed-in user of a given role."""

    def _auth(
        username: str = "admin",
        role: UserRole = UserRole.ADMIN,
        password: str = DEFAULT_PASSWORD,
    ):
        user_id = make_user(username=username, role=role, password=password)
        test_client = app.test_client()
        token_response = test_client.get("/login")
        token_match = _CSRF_INPUT_RE.search(token_response.get_data(as_text=True))
        assert token_match is not None
        test_client.post(
            "/login",
            data={
                "username": username,
                "password": password,
                "csrf_token": token_match.group(1),
            },
        )
        return test_client, user_id

    return _auth


def pytest_sessionfinish(session, exitstatus):
    """Dispose the engine and delete the temporary SQLite database."""
    try:
        engine.dispose()
    finally:
        if _DB_PATH is not None:
            try:
                os.remove(_DB_PATH)
            except OSError:
                pass

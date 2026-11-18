"""Phase 2 web tests: RBAC matrix, user administration, headers, and UI.

These tests drive the real Flask application through its HTTP interface. The
security core (hashing, lockout, TOTP, sessions) is covered by
``test_phase2_auth_security.py``.
"""

from __future__ import annotations

import json
import re

import pytest

from core.config import Settings, settings
from core.crypto import CryptoError  # noqa: F401  (exposed by security helpers)
from core.db import get_db_session
from core.models.audit import AuditLog
from core.models.user import RecoveryCode, User, UserRole, UserSession  # noqa: F401
from core.rbac import ROLE_PERMISSIONS, Permission, has_permission, permissions_for
from core.security import (
    create_user_session,
    encrypt_totp_secret,
    generate_totp_secret,
    get_session_by_token,
    hash_password,
    verify_password,
)
from services.web_api.blueprints.users import _is_last_active_admin

PASSWORD = "ValidPassw0rd!2026"
CSRF_INPUT_RE = re.compile(r'name="csrf_token"[^>]*value="([^"]+)"')
CSRF_META_RE = re.compile(r'<meta name="csrf-token" content="([^"]+)"')


def _csrf_from(client, path: str = "/login") -> str:
    response = client.get(path)
    body = response.get_data(as_text=True)
    match = CSRF_INPUT_RE.search(body) or CSRF_META_RE.search(body)
    assert match is not None, f"No CSRF token on {path}"
    return match.group(1)


def _login_client(app, username: str, password: str = PASSWORD):
    client = app.test_client()
    token = _csrf_from(client, "/login")
    response = client.post(
        "/login",
        data={"username": username, "password": password, "csrf_token": token},
    )
    assert response.status_code == 302, response.get_data(as_text=True)[:500]
    return client


def _request(client, method: str, path: str, token: str):
    if method == "POST":
        return client.post(path, data={"csrf_token": token})
    return client.get(path)


def _admin_client(app, make_user, username: str = "admin"):
    user_id = make_user(username=username, role=UserRole.ADMIN)
    return _login_client(app, username), user_id


ROUTE_MATRIX = [
    ("GET", "/dashboard", 401, 200, 200, 200),
    ("GET", "/audit", 401, 200, 200, 200),
    ("POST", "/audit/verify", 401, 403, 302, 302),
    ("GET", "/users", 401, 403, 403, 200),
    ("POST", "/users/create", 401, 403, 403, 302),
    ("POST", "/users/999999/role", 401, 403, 403, 302),
    ("POST", "/users/999999/activate", 401, 403, 403, 302),
    ("POST", "/users/999999/deactivate", 401, 403, 403, 302),
    ("POST", "/users/999999/lock", 401, 403, 403, 302),
    ("POST", "/users/999999/unlock", 401, 403, 403, 302),
    ("POST", "/users/999999/reset-2fa", 401, 403, 403, 302),
    ("POST", "/users/999999/force-password-change", 401, 403, 403, 302),
    ("POST", "/users/999999/delete", 401, 403, 403, 302),
]


class TestPermissionPolicy:
    def test_permission_matrix_is_explicit_and_default_deny(self):
        assert has_permission(UserRole.ADMIN, Permission.USERS_MANAGE) is True
        assert has_permission(UserRole.ANALYST, Permission.USERS_MANAGE) is False
        assert has_permission(UserRole.VIEWER, Permission.USERS_MANAGE) is False

        assert has_permission(UserRole.VIEWER, Permission.AUDIT_VIEW) is True
        assert has_permission(UserRole.VIEWER, Permission.AUDIT_VERIFY) is False
        assert has_permission(UserRole.ANALYST, Permission.AUDIT_VERIFY) is True

        assert has_permission(None, Permission.DASHBOARD_VIEW) is False
        assert has_permission("not-a-role", Permission.DASHBOARD_VIEW) is False
        assert has_permission(UserRole.ADMIN, "not-a-permission") is False

        assert permissions_for(UserRole.VIEWER) == ROLE_PERMISSIONS[UserRole.VIEWER]
        assert permissions_for(None) == frozenset()

    def test_every_role_can_be_explained_by_the_matrix(self):
        for role in UserRole:
            for permission in Permission:
                expected = permission in ROLE_PERMISSIONS[role]
                assert has_permission(role, permission) is expected


class TestRoutePermissionMatrix:
    @pytest.mark.parametrize("method,path,anonymous,viewer,analyst,admin", ROUTE_MATRIX)
    def test_route_x_role_matrix(
        self, app, make_user, method, path, anonymous, viewer, analyst, admin
    ):
        anonymous_client = app.test_client()
        anon_token = _csrf_from(anonymous_client, "/login")
        anon_response = _request(anonymous_client, method, path, anon_token)
        assert anon_response.status_code == anonymous

        for role, expected in (
            (UserRole.VIEWER, viewer),
            (UserRole.ANALYST, analyst),
            (UserRole.ADMIN, admin),
        ):
            username = f"matrix_{role.value}"
            make_user(username=username, role=role)
            client = _login_client(app, username)
            token = _csrf_from(client, "/dashboard")
            response = _request(client, method, path, token)
            assert response.status_code == expected, (
                f"{method} {path} as {role.value} returned "
                f"{response.status_code}, expected {expected}"
            )

    def test_health_endpoints_remain_public(self, client):
        live = client.get("/api/v1/health/live")
        assert live.status_code == 200
        assert live.get_json()["status"] == "healthy"
        ready = client.get("/api/v1/health/ready")
        assert ready.status_code == 200
        assert ready.get_json()["database"] == "connected"


class TestUserAdministration:
    def _create(self, admin_client, token, username="new_analyst", **overrides):
        data = {
            "username": username,
            "email": f"{username}@example.test",
            "role": "analyst",
            "password": "N3w-Us3r-Str0ng!Pass",
            "csrf_token": token,
        }
        data.update(overrides)
        return admin_client.post("/users/create", data=data)

    def test_admin_can_create_user_with_safe_fields(self, app, make_user):
        client, _admin_id = _admin_client(app, make_user)
        token = _csrf_from(client, "/users")
        response = self._create(client, token)
        assert response.status_code == 302

        with get_db_session() as session:
            user = session.query(User).filter_by(username="new_analyst").one()
            assert user.role == UserRole.ANALYST
            assert user.is_active is True
            assert user.must_change_password is True
            assert verify_password(user.password_hash, "N3w-Us3r-Str0ng!Pass")
            entry = (
                session.query(AuditLog)
                .filter_by(action="USER_CREATED")
                .order_by(AuditLog.id.desc())
                .first()
            )
            assert entry is not None
            details = json.loads(entry.details or "{}")
            assert details["actor"] == "admin"
            assert details["target"] == "new_analyst"

            history = session.query(User).filter_by(id=user.id).one()
            assert history.password_history

    def test_mass_assignment_fields_are_ignored(self, app, make_user):
        client, _admin_id = _admin_client(app, make_user)
        token = _csrf_from(client, "/users")
        response = self._create(
            client,
            token,
            username="massassign",
            role="viewer",
            is_active="false",
            must_change_password="false",
            password_hash="attacker-controlled",
            totp_secret="attacker-secret",
        )
        assert response.status_code == 302

        with get_db_session() as session:
            user = session.query(User).filter_by(username="massassign").one()
            assert user.is_active is True
            assert user.must_change_password is True
            assert user.password_hash != "attacker-controlled"
            assert user.totp_secret is None
            assert verify_password(user.password_hash, "N3w-Us3r-Str0ng!Pass")

    def test_invalid_payloads_create_no_user(self, app, make_user):
        client, _admin_id = _admin_client(app, make_user)
        token = _csrf_from(client, "/users")

        self._create(client, token, username="weak", password="short")
        self._create(client, token, username="bad role", role="viewer")
        self._create(client, token, username="badrole", role="superuser")
        self._create(client, token, username="badmail", email="not-an-email")

        with get_db_session() as session:
            assert session.query(User).count() == 1  # only the admin

    def test_duplicate_username_is_rejected(self, app, make_user):
        client, _admin_id = _admin_client(app, make_user)
        token = _csrf_from(client, "/users")
        assert self._create(client, token, username="dupe").status_code == 302
        assert self._create(client, token, username="dupe").status_code == 302
        with get_db_session() as session:
            assert session.query(User).filter_by(username="dupe").count() == 1

    def test_audit_entry_records_correlation_id(self, app, make_user):
        client, _admin_id = _admin_client(app, make_user)
        token = _csrf_from(client, "/users")
        response = client.post(
            "/users/create",
            data={
                "username": "correlated",
                "email": "correlated@example.test",
                "role": "viewer",
                "password": "C0rrelated-Str0ng!Pass",
                "csrf_token": token,
            },
            headers={"X-Correlation-ID": "test-correlation-42"},
        )
        assert response.status_code == 302
        with get_db_session() as session:
            entry = (
                session.query(AuditLog)
                .filter_by(action="USER_CREATED")
                .order_by(AuditLog.id.desc())
                .first()
            )
            assert entry is not None
            assert entry.correlation_id == "test-correlation-42"

    def test_list_never_exposes_hashes_or_totp_secrets(self, app, make_user):
        secret = generate_totp_secret()
        make_user(
            username="secretuser",
            is_totp_enabled=True,
            totp_secret=encrypt_totp_secret(secret),
        )
        client, _admin_id = _admin_client(app, make_user)
        body = client.get("/users").get_data(as_text=True)
        with get_db_session() as session:
            user = session.query(User).filter_by(username="secretuser").one()
            assert user.password_hash not in body
        assert secret not in body
        assert "totp_secret" not in body

    def test_output_is_escaped(self, app, make_user):
        client, _admin_id = _admin_client(app, make_user)
        with get_db_session() as session:
            session.add(
                User(
                    username="<b>bad</b>",
                    email="bad@example.test",
                    password_hash=hash_password(PASSWORD),
                    role=UserRole.VIEWER,
                )
            )
            session.commit()

        body = client.get("/users").get_data(as_text=True)
        assert "&lt;b&gt;bad&lt;/b&gt;" in body
        assert "<b>bad</b>" not in body

    def test_role_change_revokes_target_sessions_and_audits(self, app, make_user):
        target_id = make_user(username="role_target", role=UserRole.VIEWER)
        client, _admin_id = _admin_client(app, make_user)
        with get_db_session() as session:
            target = session.query(User).filter_by(id=target_id).one()
            target_token = create_user_session(target, session)

        token = _csrf_from(client, "/users")
        response = client.post(
            f"/users/{target_id}/role",
            data={"role": "analyst", "csrf_token": token},
        )
        assert response.status_code == 302

        with get_db_session() as session:
            target = session.query(User).filter_by(id=target_id).one()
            assert target.role == UserRole.ANALYST
            record = get_session_by_token(target_token, session)
            assert record is not None
            assert record.is_revoked is True
            assert record.revoke_reason == "role_change"
            entry = (
                session.query(AuditLog)
                .filter_by(action="USER_ROLE_CHANGED")
                .order_by(AuditLog.id.desc())
                .first()
            )
            assert entry is not None
            details = json.loads(entry.details or "{}")
            assert details["previous_role"] == "viewer"
            assert details["new_role"] == "analyst"

    def test_invalid_role_change_is_rejected(self, app, make_user):
        target_id = make_user(username="bad_role_target", role=UserRole.VIEWER)
        client, _admin_id = _admin_client(app, make_user)
        token = _csrf_from(client, "/users")
        response = client.post(
            f"/users/{target_id}/role",
            data={"role": "superuser", "csrf_token": token},
        )
        assert response.status_code == 302
        with get_db_session() as session:
            assert (
                session.query(User).filter_by(id=target_id).one().role
                == UserRole.VIEWER
            )

    def test_last_active_admin_is_protected(self, app, make_user):
        admin_id = make_user(username="solo_admin", role=UserRole.ADMIN)
        client = _login_client(app, "solo_admin")

        with get_db_session() as session:
            admin = session.query(User).filter_by(id=admin_id).one()
            assert _is_last_active_admin(session, admin) is True

        token = _csrf_from(client, "/users")
        demote = client.post(
            f"/users/{admin_id}/role",
            data={"role": "viewer", "csrf_token": token},
        )
        assert demote.status_code == 302

        with get_db_session() as session:
            admin = session.query(User).filter_by(id=admin_id).one()
            assert admin.role == UserRole.ADMIN
            entry = (
                session.query(AuditLog)
                .filter_by(action="USER_ROLE_CHANGE_DENIED")
                .order_by(AuditLog.id.desc())
                .first()
            )
            assert entry is not None
            assert entry.status == "DENIED"
            assert json.loads(entry.details or "{}")["reason"] == "last_active_admin"

    def test_second_admin_allows_demotion(self, app, make_user):
        first_id = make_user(username="first_admin", role=UserRole.ADMIN)
        second_id = make_user(username="second_admin", role=UserRole.ADMIN)
        client = _login_client(app, "first_admin")
        with get_db_session() as session:
            second = session.query(User).filter_by(id=second_id).one()
            assert _is_last_active_admin(session, second) is False

        token = _csrf_from(client, "/users")
        response = client.post(
            f"/users/{second_id}/role",
            data={"role": "analyst", "csrf_token": token},
        )
        assert response.status_code == 302
        with get_db_session() as session:
            assert (
                session.query(User).filter_by(id=second_id).one().role
                == UserRole.ANALYST
            )
            first = session.query(User).filter_by(id=first_id).one()
            assert _is_last_active_admin(session, first) is True

    def test_self_actions_are_denied(self, app, make_user):
        admin_id = make_user(username="self_admin", role=UserRole.ADMIN)
        client = _login_client(app, "self_admin")
        token = _csrf_from(client, "/users")

        for action in ("deactivate", "lock", "delete"):
            response = client.post(
                f"/users/{admin_id}/{action}", data={"csrf_token": token}
            )
            assert response.status_code == 302

        with get_db_session() as session:
            admin = session.query(User).filter_by(id=admin_id).one()
            assert admin.is_active is True
            assert admin.locked_until is None
            assert session.query(User).filter_by(id=admin_id).count() == 1

    def test_deactivate_activate_revoke_and_audit(self, app, make_user):
        target_id = make_user(username="toggle_target")
        client, _admin_id = _admin_client(app, make_user)
        with get_db_session() as session:
            target = session.query(User).filter_by(id=target_id).one()
            token_value = create_user_session(target, session)

        token = _csrf_from(client, "/users")
        assert (
            client.post(
                f"/users/{target_id}/deactivate", data={"csrf_token": token}
            ).status_code
            == 302
        )
        with get_db_session() as session:
            target = session.query(User).filter_by(id=target_id).one()
            assert target.is_active is False
            assert get_session_by_token(token_value, session).is_revoked is True
            assert (
                session.query(AuditLog).filter_by(action="USER_DEACTIVATED").count()
                == 1
            )

        assert (
            client.post(
                f"/users/{target_id}/activate", data={"csrf_token": token}
            ).status_code
            == 302
        )
        with get_db_session() as session:
            assert session.query(User).filter_by(id=target_id).one().is_active is True
            assert (
                session.query(AuditLog).filter_by(action="USER_ACTIVATED").count() == 1
            )

    def test_admin_lock_and_unlock(self, app, make_user):
        target_id = make_user(username="lock_target")
        client, _admin_id = _admin_client(app, make_user)
        with get_db_session() as session:
            target = session.query(User).filter_by(id=target_id).one()
            token_value = create_user_session(target, session)

        token = _csrf_from(client, "/users")
        assert (
            client.post(
                f"/users/{target_id}/lock", data={"csrf_token": token}
            ).status_code
            == 302
        )
        with get_db_session() as session:
            target = session.query(User).filter_by(id=target_id).one()
            assert target.failed_login_attempts == settings.LOGIN_MAX_ATTEMPTS
            assert target.locked_until is not None
            record = get_session_by_token(token_value, session)
            assert record is not None and record.is_revoked is True
            assert record.revoke_reason == "admin_lockout"
            assert session.query(AuditLog).filter_by(action="USER_LOCKED").count() == 1

        assert (
            client.post(
                f"/users/{target_id}/unlock", data={"csrf_token": token}
            ).status_code
            == 302
        )
        with get_db_session() as session:
            target = session.query(User).filter_by(id=target_id).one()
            assert target.failed_login_attempts == 0
            assert target.locked_until is None
            assert (
                session.query(AuditLog).filter_by(action="USER_UNLOCKED").count() == 1
            )

    def test_admin_2fa_reset_clears_secret_codes_and_sessions(self, app, make_user):
        secret = generate_totp_secret()
        target_id = make_user(
            username="totp_target",
            is_totp_enabled=True,
            totp_secret=encrypt_totp_secret(secret),
        )
        client, _admin_id = _admin_client(app, make_user)
        with get_db_session() as session:
            target = session.query(User).filter_by(id=target_id).one()
            session.add(
                RecoveryCode(user_id=target.id, code_hash=hash_password("AAAAA-BBBBB"))
            )
            token_value = create_user_session(target, session)

        token = _csrf_from(client, "/users")
        assert (
            client.post(
                f"/users/{target_id}/reset-2fa", data={"csrf_token": token}
            ).status_code
            == 302
        )
        with get_db_session() as session:
            target = session.query(User).filter_by(id=target_id).one()
            assert target.is_totp_enabled is False
            assert target.totp_secret is None
            assert target.totp_last_step is None
            assert session.query(RecoveryCode).filter_by(user_id=target_id).count() == 0
            record = get_session_by_token(token_value, session)
            assert record is not None and record.is_revoked is True
            assert record.revoke_reason == "admin_2fa_reset"
            assert session.query(AuditLog).filter_by(action="2FA_RESET").count() == 1

    def test_force_password_change_revokes_sessions(self, app, make_user):
        target_id = make_user(username="force_target")
        client, _admin_id = _admin_client(app, make_user)
        with get_db_session() as session:
            target = session.query(User).filter_by(id=target_id).one()
            token_value = create_user_session(target, session)

        token = _csrf_from(client, "/users")
        assert (
            client.post(
                f"/users/{target_id}/force-password-change",
                data={"csrf_token": token},
            ).status_code
            == 302
        )
        with get_db_session() as session:
            target = session.query(User).filter_by(id=target_id).one()
            assert target.must_change_password is True
            record = get_session_by_token(token_value, session)
            assert record is not None and record.is_revoked is True
            assert record.revoke_reason == "forced_password_change"
            assert (
                session.query(AuditLog)
                .filter_by(action="PASSWORD_CHANGE_REQUIRED")
                .count()
                == 1
            )

    def test_delete_user_audits_and_removes(self, app, make_user):
        target_id = make_user(username="delete_target")
        client, _admin_id = _admin_client(app, make_user)
        token = _csrf_from(client, "/users")
        assert (
            client.post(
                f"/users/{target_id}/delete", data={"csrf_token": token}
            ).status_code
            == 302
        )
        with get_db_session() as session:
            assert session.query(User).filter_by(id=target_id).first() is None
            assert session.query(AuditLog).filter_by(action="USER_DELETED").count() == 1


class TestAuditRoutes:
    def test_audit_ledger_readable_and_verifiable(self, app, make_user):
        client, _admin_id = _admin_client(app, make_user)
        assert client.get("/audit").status_code == 200

        token = _csrf_from(client, "/audit")
        response = client.post("/audit/verify", data={"csrf_token": token})
        assert response.status_code == 302
        with get_db_session() as session:
            entry = (
                session.query(AuditLog)
                .filter_by(action="AUDIT_CHAIN_VERIFIED")
                .order_by(AuditLog.id.desc())
                .first()
            )
            assert entry is not None
            assert entry.status == "SUCCESS"

    def test_audit_tamper_is_reported(self, app, make_user):
        client, _admin_id = _admin_client(app, make_user)
        with get_db_session() as session:
            entry = session.query(AuditLog).order_by(AuditLog.id.asc()).first()
            entry.action = "TAMPERED_BY_TEST"
            session.commit()

        token = _csrf_from(client, "/audit")
        response = client.post("/audit/verify", data={"csrf_token": token})
        assert response.status_code == 302
        with get_db_session() as session:
            assert (
                session.query(AuditLog)
                .filter_by(action="AUDIT_CHAIN_TAMPER_DETECTED")
                .count()
                == 1
            )


class TestHeadersCookiesAndUi:
    def test_security_headers_and_nonce_csp(self, client):
        response = client.get("/login")
        assert response.status_code == 200
        headers = response.headers

        assert headers["X-Content-Type-Options"] == "nosniff"
        assert headers["X-Frame-Options"] == "DENY"
        assert headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
        assert "Strict-Transport-Security" not in headers

        csp = headers["Content-Security-Policy"]
        assert "default-src 'self'" in csp
        assert "frame-ancestors 'none'" in csp
        assert "object-src 'none'" in csp
        assert "'unsafe-inline'" not in csp
        assert "'unsafe-eval'" not in csp

        match = re.search(r"'nonce-([^']+)'", csp)
        assert match is not None
        nonce = match.group(1)
        assert f'nonce="{nonce}"' in response.get_data(as_text=True)

    def test_hsts_and_upgrade_directive_in_production(self, client, monkeypatch):
        monkeypatch.setattr(settings, "APP_ENV", "production")
        response = client.get("/login")
        assert response.headers["Strict-Transport-Security"].startswith(
            "max-age=31536000"
        )
        assert (
            "upgrade-insecure-requests" in response.headers["Content-Security-Policy"]
        )

    def test_cookie_flags_in_testing_and_production(self, app, client, monkeypatch):
        testing_response = client.get("/login")
        testing_cookie = testing_response.headers.get("Set-Cookie", "")
        assert "HttpOnly" in testing_cookie
        assert "SameSite=Strict" in testing_cookie
        assert "Secure" not in testing_cookie

        monkeypatch.setattr(settings, "APP_ENV", "production")
        from services.web_api import create_app

        production_app, _socketio = create_app(
            {"TESTING": True, "PROPAGATE_EXCEPTIONS": False}
        )
        production_client = production_app.test_client()
        production_cookie = production_client.get("/login").headers.get(
            "Set-Cookie", ""
        )
        assert "HttpOnly" in production_cookie
        assert "SameSite=Strict" in production_cookie
        assert "Secure" in production_cookie
        assert production_app.config["SESSION_COOKIE_SECURE"] is True

    def test_limiter_storage_selection(self, app):
        assert app.config["RATELIMIT_STORAGE_URI"] == "memory://"
        production = Settings(APP_ENV="production", RATELIMIT_STORAGE_URI=None)
        assert production.get_rate_limit_storage_uri().startswith("redis://")
        override = Settings(RATELIMIT_STORAGE_URI="redis://cache:6379/9")
        assert override.get_rate_limit_storage_uri() == "redis://cache:6379/9"

    def test_proxyfix_only_when_hops_configured(self, app, monkeypatch):
        from werkzeug.middleware.proxy_fix import ProxyFix

        from services.web_api import create_app

        monkeypatch.setattr(settings, "TRUSTED_PROXY_HOPS", 2)
        proxied_app, _socketio = create_app({"TESTING": True})
        assert isinstance(proxied_app.wsgi_app, ProxyFix)
        assert proxied_app.wsgi_app.x_for == 2  # type: ignore[attr-defined]

        monkeypatch.setattr(settings, "TRUSTED_PROXY_HOPS", 0)
        direct_app, _socketio = create_app({"TESTING": True})
        assert not isinstance(direct_app.wsgi_app, ProxyFix)

    def test_sidebar_is_role_aware(self, app, make_user):
        make_user(username="ui_admin", role=UserRole.ADMIN)
        make_user(username="ui_analyst", role=UserRole.ANALYST)
        make_user(username="ui_viewer", role=UserRole.VIEWER)

        admin_body = (
            _login_client(app, "ui_admin").get("/dashboard").get_data(as_text=True)
        )
        analyst_body = (
            _login_client(app, "ui_analyst").get("/dashboard").get_data(as_text=True)
        )
        viewer_body = (
            _login_client(app, "ui_viewer").get("/dashboard").get_data(as_text=True)
        )

        assert "User Management" in admin_body
        assert "User Management" not in analyst_body
        assert "User Management" not in viewer_body
        for body in (admin_body, analyst_body, viewer_body):
            assert "Tamper-Evident Audit" in body

    def test_templates_have_no_inline_scripts_or_styles(self, app, make_user):
        make_user(username="inline_admin", role=UserRole.ADMIN)
        client = _login_client(app, "inline_admin")

        for path in ("/dashboard", "/users", "/audit", "/setup-2fa"):
            body = client.get(path).get_data(as_text=True)
            assert "style=" not in body, f"inline style in {path}"
            assert "onclick=" not in body, f"inline handler in {path}"
            for script_tag in re.findall(r"<script[^>]*>", body):
                assert "nonce=" in script_tag, f"script without nonce in {path}"

        anonymous_body = app.test_client().get("/login").get_data(as_text=True)
        assert "style=" not in anonymous_body
        assert "onclick=" not in anonymous_body

    def test_error_pages_negotiate_html_and_json(self, client):
        html = client.get("/does-not-exist")
        assert html.status_code == 404
        assert b"Resource not found" in html.data

        json_response = client.get(
            "/does-not-exist", headers={"Accept": "application/json"}
        )
        assert json_response.status_code == 404
        assert json_response.is_json
        assert json_response.get_json()["error"] == "not_found"

    def test_static_assets_exist(self, client):
        css = client.get("/static/css/soc-theme.css")
        js = client.get("/static/js/app.js")
        assert css.status_code == 200
        assert js.status_code == 200
        assert b"--bg-dark" in css.data
        assert b"apiFetch" in js.data

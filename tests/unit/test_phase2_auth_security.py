"""Phase 2 Verification Tests: Authentication, RBAC, 2FA, Audit Logging, and Security Middleware.

Tests:
1. Argon2id password hashing and verification.
2. Enterprise password complexity validation.
3. Account lockout after 5 consecutive failed attempts with 15-minute cooldown.
4. TOTP 2FA secret generation, QR encoding, and time-step verification.
5. Role-Based Access Control (Admin, Analyst, Viewer) backend enforcement.
6. Mandatory password change enforcement on first login.
7. Defensive security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options).
8. Automatic audit logging on security-sensitive actions.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pyotp
import pytest
from flask import Flask
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from core.db import Base
from core.models.audit import AuditLog
from core.models.user import User, UserRole
from core.security import (
    generate_qr_code_svg,
    generate_totp_secret,
    get_totp_uri,
    hash_password,
    is_account_locked,
    record_failed_login,
    reset_failed_login_attempts,
    validate_password_complexity,
    verify_password,
    verify_totp_code,
)
from services.web_api import create_app


class TestPasswordSecurity:
    """Verifies Argon2id hashing and complexity rule validation."""

    def test_argon2id_hashing_and_verification(self):
        pwd = "EnterprisePassword2026!#"
        hashed = hash_password(pwd)
        assert hashed.startswith("$argon2id$")
        assert verify_password(hashed, pwd) is True
        assert verify_password(hashed, "WrongPassword123!") is False

    def test_password_complexity_policy(self):
        # Valid password (>= 12 chars, upper, lower, digit, symbol)
        valid, errors = validate_password_complexity("StrongSecurePass123!")
        assert valid is True
        assert len(errors) == 0

        # Too short (< 12 chars)
        valid, errors = validate_password_complexity("Short1!")
        assert valid is False
        assert any("at least 12 characters" in err for err in errors)

        # Missing uppercase
        valid, errors = validate_password_complexity("lowercase_only_123!")
        assert valid is False
        assert any("uppercase" in err for err in errors)

        # Missing lowercase
        valid, errors = validate_password_complexity("UPPERCASE_ONLY_123!")
        assert valid is False
        assert any("lowercase" in err for err in errors)

        # Missing digit
        valid, errors = validate_password_complexity("NoDigitsHereAtAll!#")
        assert valid is False
        assert any("number" in err for err in errors)

        # Missing special character
        valid, errors = validate_password_complexity("NoSpecialChars12345")
        assert valid is False
        assert any("special character" in err for err in errors)


class TestAccountLockout:
    """Verifies brute-force protection and lockout counters."""

    def test_lockout_trigger_and_duration(self):
        # Mock database session
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        SessionLocal = sessionmaker(bind=engine)
        session = SessionLocal()

        user = User(
            username="analyst_test",
            email="analyst@test.local",
            password_hash=hash_password("ValidPassword123!"),
            role=UserRole.ANALYST,
        )
        session.add(user)
        session.commit()

        # Simulate 4 failed attempts (should not lock yet)
        for i in range(4):
            newly_locked = record_failed_login(user, session)
            assert newly_locked is False
            assert is_account_locked(user) is False

        # 5th failed attempt triggers lockout
        newly_locked = record_failed_login(user, session)
        assert newly_locked is True
        assert user.failed_login_attempts == 5
        assert user.locked_until is not None
        assert is_account_locked(user) is True

        # Successful login resets lockout
        reset_failed_login_attempts(user)
        assert user.failed_login_attempts == 0
        assert user.locked_until is None
        assert is_account_locked(user) is False
        session.close()


class TestTwoFactorAuthentication:
    """Verifies RFC 6238 TOTP operations."""

    def test_totp_generation_and_validation(self):
        secret = generate_totp_secret()
        assert len(secret) == 32  # Base32 standard random secret

        # Generate current valid code using pyotp
        totp = pyotp.TOTP(secret)
        current_code = totp.now()

        # Validate code passes
        assert verify_totp_code(secret, current_code) is True

        # Invalid code fails
        assert verify_totp_code(secret, "000000") is False
        assert verify_totp_code(secret, "abc") is False
        assert verify_totp_code(secret, "") is False

    def test_totp_uri_and_qr_code(self):
        secret = generate_totp_secret()
        uri = get_totp_uri(secret, "admin_user")
        assert "otpauth://totp/AI-IDS-IPS-SOC:admin_user" in uri
        assert f"secret={secret}" in uri

        qr_data = generate_qr_code_svg(uri)
        assert qr_data.startswith("data:image/png;base64,")


class TestWebApplicationAndSecurityMiddleware:
    """Verifies Flask security headers, CSRF, and RBAC endpoint protection."""

    @pytest.fixture
    def test_app(self):
        app, _ = create_app({
            "TESTING": True,
            "WTF_CSRF_ENABLED": False,  # Disabled for programmatic test client requests
        })
        return app

    def test_defensive_security_headers(self, test_app: Flask):
        client = test_app.test_client()
        response = client.get("/api/v1/health/live")
        assert response.status_code == 200

        headers = response.headers
        assert headers.get("X-Content-Type-Options") == "nosniff"
        assert headers.get("X-Frame-Options") == "DENY"
        assert "max-age=31536000" in headers.get("Strict-Transport-Security", "")
        assert "default-src 'self'" in headers.get("Content-Security-Policy", "")
        assert "X-Correlation-ID" in headers

    def test_correlation_id_propagation(self, test_app: Flask):
        client = test_app.test_client()
        custom_cid = "soc-trace-999-abc"
        response = client.get("/api/v1/health/live", headers={"X-Correlation-ID": custom_cid})
        assert response.headers.get("X-Correlation-ID") == custom_cid

    def test_unauthenticated_access_redirects_to_login(self, test_app: Flask):
        client = test_app.test_client()
        response = client.get("/dashboard", follow_redirects=False)
        assert response.status_code == 302
        assert "/login" in response.headers.get("Location", "")

    def test_authenticated_admin_flow_and_rbac(self, test_app: Flask):
        # 1. Setup test database with an Admin and a Viewer user
        from core.db import engine, get_db_session
        Base.metadata.create_all(engine)

        with get_db_session() as session:
            admin = session.query(User).filter_by(username="admin_rbac").first()
            if not admin:
                admin = User(
                    username="admin_rbac",
                    email="admin_rbac@test.local",
                    password_hash=hash_password("AdminPass12345!#"),
                    role=UserRole.ADMIN,
                    must_change_password=False,
                )
                session.add(admin)

            viewer = session.query(User).filter_by(username="viewer_rbac").first()
            if not viewer:
                viewer = User(
                    username="viewer_rbac",
                    email="viewer_rbac@test.local",
                    password_hash=hash_password("ViewerPass12345!#"),
                    role=UserRole.VIEWER,
                    must_change_password=False,
                )
                session.add(viewer)

        # 2. Test Admin Login and access to /users
        client_admin = test_app.test_client()
        login_res = client_admin.post(
            "/login",
            data={"username": "admin_rbac", "password": "AdminPass12345!#"},
            follow_redirects=True,
        )
        assert login_res.status_code == 200
        assert b"Authenticated successfully" in login_res.data or b"Dashboard" in login_res.data

        # Admin can access user management
        users_res = client_admin.get("/users")
        assert users_res.status_code == 200
        assert b"Registered Console Users" in users_res.data

        # 3. Test Viewer Login and unauthorized access to /users
        client_viewer = test_app.test_client()
        client_viewer.post(
            "/login",
            data={"username": "viewer_rbac", "password": "ViewerPass12345!#"},
            follow_redirects=True,
        )
        viewer_users_res = client_viewer.get("/users", follow_redirects=True)
        assert b"Access denied" in viewer_users_res.data

    def test_must_change_password_redirect(self, test_app: Flask):
        from core.db import engine, get_db_session
        Base.metadata.create_all(engine)

        with get_db_session() as session:
            newbie = session.query(User).filter_by(username="new_analyst").first()
            if not newbie:
                newbie = User(
                    username="new_analyst",
                    email="newbie@test.local",
                    password_hash=hash_password("TempPass12345!#"),
                    role=UserRole.ANALYST,
                    must_change_password=True,
                )
                session.add(newbie)

        client = test_app.test_client()
        client.post(
            "/login",
            data={"username": "new_analyst", "password": "TempPass12345!#"},
            follow_redirects=True,
        )

        # Attempting to access /dashboard should redirect to /change-password
        dash_res = client.get("/dashboard", follow_redirects=False)
        assert dash_res.status_code == 302
        assert "/change-password" in dash_res.headers.get("Location", "")

    def test_audit_log_recorded_on_auth_events(self, test_app: Flask):
        from core.db import engine, get_db_session
        Base.metadata.create_all(engine)

        client = test_app.test_client()
        # Invalid login attempts record audit events
        client.post(
            "/login",
            data={"username": "non_existent_user", "password": "AnyPassword123!"},
        )

        with get_db_session() as session:
            failed_audit = (
                session.query(AuditLog)
                .filter_by(action="USER_LOGIN_FAILED")
                .first()
            )
            assert failed_audit is not None
            assert failed_audit.status == "FAILED"

    def test_user_management_crud_endpoints(self, test_app: Flask):
        from core.db import engine, get_db_session
        Base.metadata.create_all(engine)

        admin_name = f"admin_{uuid.uuid4().hex[:6]}"
        with get_db_session() as session:
            admin = User(
                username=admin_name,
                email=f"{admin_name}@test.local",
                password_hash=hash_password("AdminPass12345!#"),
                role=UserRole.ADMIN,
                must_change_password=False,
            )
            session.add(admin)

        client = test_app.test_client()
        client.post(
            "/login",
            data={"username": admin_name, "password": "AdminPass12345!#"},
            follow_redirects=True,
        )

        target_name = f"analyst_{uuid.uuid4().hex[:6]}"
        target_email = f"{target_name}@test.local"

        # 1. Create User with weak password (should fail)
        weak_res = client.post(
            "/users/create",
            data={
                "username": target_name,
                "email": target_email,
                "role": "analyst",
                "password": "short",
            },
            follow_redirects=True,
        )
        assert b"at least 12 characters" in weak_res.data

        # 2. Create User with strong password (should succeed)
        create_res = client.post(
            "/users/create",
            data={
                "username": target_name,
                "email": target_email,
                "role": "analyst",
                "password": "ValidStrongPass123!#",
            },
            follow_redirects=True,
        )
        assert b"created successfully" in create_res.data

        # 3. Toggle user active/inactive
        with get_db_session() as session:
            target = session.query(User).filter_by(username=target_name).first()
            target_id = target.id

        toggle_res = client.post(f"/users/{target_id}/toggle-active", follow_redirects=True)
        assert b"deactivated" in toggle_res.data

        toggle_res_2 = client.post(f"/users/{target_id}/toggle-active", follow_redirects=True)
        assert b"activated" in toggle_res_2.data

        # 4. Unlock locked user
        with get_db_session() as session:
            target = session.query(User).filter_by(id=target_id).first()
            target.failed_login_attempts = 5
            target.locked_until = datetime.now(UTC) + timedelta(minutes=15)

        unlock_res = client.post(f"/users/{target_id}/unlock", follow_redirects=True)
        assert b"has been unlocked" in unlock_res.data

    def test_audit_verification_endpoint(self, test_app: Flask):
        from core.db import engine, get_db_session
        Base.metadata.create_all(engine)

        analyst_name = f"analyst_{uuid.uuid4().hex[:6]}"
        with get_db_session() as session:
            analyst = User(
                username=analyst_name,
                email=f"{analyst_name}@test.local",
                password_hash=hash_password("AuditorPass12345!#"),
                role=UserRole.ANALYST,
                must_change_password=False,
            )
            session.add(analyst)

        client = test_app.test_client()
        client.post(
            "/login",
            data={"username": analyst_name, "password": "AuditorPass12345!#"},
            follow_redirects=True,
        )

        # GET /audit view
        audit_view_res = client.get("/audit")
        assert audit_view_res.status_code == 200
        assert b"Tamper-Evident Audit Ledger" in audit_view_res.data

        # POST /audit/verify
        verify_res = client.post("/audit/verify", follow_redirects=True)
        assert b"Audit" in verify_res.data

    def test_2fa_workflow(self, test_app: Flask):
        from core.db import engine, get_db_session
        Base.metadata.create_all(engine)

        u2fa_name = f"user2fa_{uuid.uuid4().hex[:6]}"
        with get_db_session() as session:
            u2fa = User(
                username=u2fa_name,
                email=f"{u2fa_name}@test.local",
                password_hash=hash_password("User2FAPass12345!#"),
                role=UserRole.ANALYST,
                must_change_password=False,
                is_totp_enabled=False,
            )
            session.add(u2fa)

        client = test_app.test_client()
        client.post(
            "/login",
            data={"username": u2fa_name, "password": "User2FAPass12345!#"},
            follow_redirects=True,
        )

        # 1. GET /setup-2fa
        setup_page = client.get("/setup-2fa")
        assert setup_page.status_code == 200
        assert b"Two-Factor Authentication Setup" in setup_page.data

        # 2. Activate 2FA with valid TOTP code
        test_secret = generate_totp_secret()
        valid_totp = pyotp.TOTP(test_secret).now()

        activate_res = client.post(
            "/setup-2fa",
            data={"secret": test_secret, "code": valid_totp},
            follow_redirects=True,
        )
        assert b"Two-Factor Authentication is now active" in activate_res.data

        # Sign out
        client.get("/logout")

        # 3. Log in with 2FA enabled: step 1 password
        step1_res = client.post(
            "/login",
            data={"username": u2fa_name, "password": "User2FAPass12345!#"},
            follow_redirects=False,
        )
        assert step1_res.status_code == 302
        assert "/login/2fa" in step1_res.headers.get("Location", "")

        # 4. Log in step 2: invalid TOTP code
        step2_invalid = client.post(
            "/login/2fa",
            data={"code": "000000"},
            follow_redirects=True,
        )
        assert b"Invalid two-factor authentication code" in step2_invalid.data

        # 5. Log in step 2: valid TOTP code
        fresh_totp = pyotp.TOTP(test_secret).now()
        step2_valid = client.post(
            "/login/2fa",
            data={"code": fresh_totp},
            follow_redirects=True,
        )
        assert b"Two-factor authentication verified" in step2_valid.data

    def test_password_change_endpoint(self, test_app: Flask):
        from core.db import engine, get_db_session
        Base.metadata.create_all(engine)

        changer_name = f"changer_{uuid.uuid4().hex[:6]}"
        with get_db_session() as session:
            user_pwd = User(
                username=changer_name,
                email=f"{changer_name}@test.local",
                password_hash=hash_password("OldPassword12345!#"),
                role=UserRole.VIEWER,
                must_change_password=True,
            )
            session.add(user_pwd)

        client = test_app.test_client()
        client.post(
            "/login",
            data={"username": changer_name, "password": "OldPassword12345!#"},
            follow_redirects=False,
        )

        # GET /change-password
        get_res = client.get("/change-password")
        assert get_res.status_code == 200
        assert b"Update Account Password" in get_res.data

        # Post invalid current password
        fail_res = client.post(
            "/change-password",
            data={
                "current_password": "WrongOldPassword123!",
                "new_password": "NewStrongPass12345!#",
                "confirm_password": "NewStrongPass12345!#",
            },
            follow_redirects=True,
        )
        assert b"Current password provided is incorrect" in fail_res.data

        # Post valid password change
        success_res = client.post(
            "/change-password",
            data={
                "current_password": "OldPassword12345!#",
                "new_password": "NewStrongPass12345!#",
                "confirm_password": "NewStrongPass12345!#",
            },
            follow_redirects=True,
        )
        assert b"Password updated successfully" in success_res.data

    def test_health_readiness_endpoint(self, test_app: Flask):
        client = test_app.test_client()
        res = client.get("/api/v1/health/ready")
        assert res.status_code in (200, 503)

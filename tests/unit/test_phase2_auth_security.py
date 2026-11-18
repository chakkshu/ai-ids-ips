"""Phase 2 security tests: hashing, password policy, lockout, TOTP, sessions.

These tests exercise the security core directly and through the real Flask
authentication routes. The web/RBAC/UI matrix lives in
``test_phase2_rbac_web.py``.
"""

from __future__ import annotations

import json
import re
import time
from datetime import UTC, datetime, timedelta

import pyotp
import pytest
from argon2 import PasswordHasher
from freezegun import freeze_time

from core.config import settings
from core.crypto import CryptoError
from core.db import get_db_session
from core.models.audit import AuditLog
from core.models.user import PasswordHistory, RecoveryCode, User, UserRole, UserSession
from core.security import (
    GENERIC_AUTH_ERROR,
    clear_expired_lockout,
    create_user_session,
    decrypt_totp_secret,
    dummy_verify_password,
    encrypt_totp_secret,
    generate_totp_secret,
    get_session_by_token,
    hash_password,
    hash_session_token,
    is_account_locked,
    is_password_reused,
    is_safe_next_url,
    issue_recovery_codes,
    password_needs_rehash,
    record_password_history,
    rehash_password_if_needed,
    revoke_all_user_sessions,
    safe_next_url,
    validate_password_policy,
    validate_user_session,
    verify_password,
    verify_recovery_code,
    verify_totp_code,
    verify_totp_code_with_step,
)

PASSWORD = "ValidPassw0rd!2026"
SECOND_PASSWORD = "An0ther-Str0ng-Passphrase!"
CSRF_INPUT_RE = re.compile(r'name="csrf_token"[^>]*value="([^"]+)"')


def _csrf_from(client, path: str = "/login") -> str:
    response = client.get(path)
    match = CSRF_INPUT_RE.search(response.get_data(as_text=True))
    assert match is not None, f"No CSRF token on {path}"
    return match.group(1)


def _login(client, username: str, password: str = PASSWORD):
    return client.post(
        "/login",
        data={
            "username": username,
            "password": password,
            "csrf_token": _csrf_from(client, "/login"),
        },
    )


def _code_for(secret: str, at_time: float | None = None) -> str:
    totp = pyotp.TOTP(secret)
    if at_time is not None:
        return totp.at(at_time)
    return totp.now()


_ENROLLMENT_SECRET_RE = re.compile(r'class="mono">\s*([A-Z2-7]{16,})\s*<')
_ENROLLMENT_QR_RE = re.compile(r'<img src="(data:image/png;base64,[^"]+)"')


def _setup_page_values(response) -> tuple[str, str, str]:
    """Return (secret, QR data URI, CSRF token) from a rendered enrollment page."""
    body = response.get_data(as_text=True)
    secret_match = _ENROLLMENT_SECRET_RE.search(body)
    qr_match = _ENROLLMENT_QR_RE.search(body)
    csrf_match = CSRF_INPUT_RE.search(body)
    assert secret_match is not None, "Enrollment page did not render a secret"
    assert qr_match is not None, "Enrollment page did not render a QR code"
    assert csrf_match is not None, "Enrollment page did not render a CSRF token"
    return secret_match.group(1), qr_match.group(1), csrf_match.group(1)


# ---------------------------------------------------------------------------
# Argon2id and password policy
# ---------------------------------------------------------------------------


class TestArgon2AndPasswordPolicy:
    def test_argon2id_roundtrip(self):
        hashed = hash_password(PASSWORD)
        assert hashed.startswith("$argon2id$")
        assert verify_password(hashed, PASSWORD) is True
        assert verify_password(hashed, "wrong-password") is False
        assert verify_password("not-a-hash", PASSWORD) is False

    def test_password_needs_rehash_and_upgrade(self, make_user):
        legacy_hasher = PasswordHasher(
            time_cost=2, memory_cost=8192, parallelism=1, hash_len=32, salt_len=16
        )
        legacy_hash = legacy_hasher.hash(PASSWORD)
        assert password_needs_rehash(legacy_hash) is True

        user = User(
            username="rehash_user",
            email="rehash@example.test",
            password_hash=legacy_hash,
            role=UserRole.VIEWER,
        )
        with get_db_session() as session:
            session.add(user)
            session.flush()
            assert rehash_password_if_needed(user, PASSWORD) is True
            assert user.password_hash != legacy_hash
            assert verify_password(user.password_hash, PASSWORD) is True
            assert password_needs_rehash(user.password_hash) is False
            assert rehash_password_if_needed(user, PASSWORD) is False

    def test_dummy_verification_returns_false(self):
        assert dummy_verify_password("anything") is False

    def test_strong_password_accepted(self):
        valid, errors = validate_password_policy(
            "A-perfectly-Fine-Passphrase-9!",
            username="alice",
            email="alice@example.test",
        )
        assert valid is True
        assert errors == []

    @pytest.mark.parametrize(
        "password,expected_fragment",
        [
            ("Short1!", "at least"),
            ("alllowercase123!", "uppercase"),
            ("ALLUPPERCASE123!", "lowercase"),
            ("NoNumbersHere!!", "number"),
            ("NoSpecialChar12345", "special"),
        ],
    )
    def test_complexity_rules(self, password, expected_fragment):
        valid, errors = validate_password_policy(password)
        assert valid is False
        assert any(expected_fragment in error.lower() for error in errors)

    def test_common_password_rejected(self):
        valid, errors = validate_password_policy("Password123!")
        assert valid is False
        assert any("common" in error.lower() for error in errors)

    def test_username_substring_rejected(self):
        valid, errors = validate_password_policy("Alice-Strong!234", username="alice")
        assert valid is False
        assert any("username" in error.lower() for error in errors)

    def test_email_substring_rejected(self):
        valid, errors = validate_password_policy(
            "Bobby-Strong!234", email="bob@example.test"
        )
        assert valid is False
        assert any("email" in error.lower() for error in errors)

    def test_history_match_rejected(self):
        old_hash = hash_password("Old-Passphrase!234")
        valid, errors = validate_password_policy(
            "Old-Passphrase!234", history_hashes=[old_hash]
        )
        assert valid is False
        assert any("last 5 passwords" in error.lower() for error in errors)

    def test_password_reuse_depth_limits_history(self, db_session):
        with get_db_session() as session:
            user = User(
                username="history_user",
                email="history@example.test",
                password_hash=hash_password("Current!Passphrase9"),
                role=UserRole.VIEWER,
            )
            session.add(user)
            session.flush()

            previous_passwords = [f"Historic-Pass!{index:03d}" for index in range(1, 8)]
            for previous in previous_passwords:
                record_password_history(user, hash_password(previous), session)

            history = (
                session.query(PasswordHistory)
                .filter_by(user_id=user.id)
                .order_by(PasswordHistory.created_at.desc())
                .all()
            )
            assert len(history) == settings.PASSWORD_HISTORY_DEPTH == 5

            # The two oldest entries have rolled out of the retention window.
            assert is_password_reused(user, previous_passwords[0], session) is False
            assert is_password_reused(user, previous_passwords[1], session) is False
            # A recent password and the current password remain blocked.
            assert is_password_reused(user, previous_passwords[-1], session) is True
            assert is_password_reused(user, "Current!Passphrase9", session) is True


# ---------------------------------------------------------------------------
# Account lockout
# ---------------------------------------------------------------------------


class TestAccountLockout:
    def test_five_failures_lock_account_and_audit(self, client, make_user):
        make_user(username="lockme")
        start = "2026-03-01 09:00:00"
        with freeze_time(start):
            token = _csrf_from(client, "/login")
            for _ in range(settings.LOGIN_MAX_ATTEMPTS):
                response = client.post(
                    "/login",
                    data={
                        "username": "lockme",
                        "password": "Definitely-Wrong!1",
                        "csrf_token": token,
                    },
                )
                assert response.status_code == 200

            with get_db_session() as session:
                user = session.query(User).filter_by(username="lockme").one()
                assert user.failed_login_attempts == settings.LOGIN_MAX_ATTEMPTS
                assert is_account_locked(user) is True
                assert user.locked_until is not None

            with get_db_session() as session:
                actions = [entry.action for entry in session.query(AuditLog).all()]
                assert "USER_LOCKED" in actions

    def test_locked_account_rejects_correct_password_until_expiry(
        self, client, make_user
    ):
        make_user(username="expiring")
        start = "2026-03-01 10:00:00"
        with freeze_time(start):
            token = _csrf_from(client, "/login")
            for _ in range(settings.LOGIN_MAX_ATTEMPTS):
                client.post(
                    "/login",
                    data={
                        "username": "expiring",
                        "password": "Wrong-Password!1",
                        "csrf_token": token,
                    },
                )
            blocked = client.post(
                "/login",
                data={
                    "username": "expiring",
                    "password": PASSWORD,
                    "csrf_token": token,
                },
            )
            assert blocked.status_code == 200
            assert b"/dashboard" not in blocked.headers.get("Location", "").encode()

        with freeze_time("2026-03-01 10:16:00"):
            unlocked = client.post(
                "/login",
                data={
                    "username": "expiring",
                    "password": PASSWORD,
                    "csrf_token": token,
                },
            )
            assert unlocked.status_code == 302
            assert unlocked.headers["Location"].endswith("/dashboard")

            with get_db_session() as session:
                user = session.query(User).filter_by(username="expiring").one()
                assert user.failed_login_attempts == 0
                assert user.locked_until is None
                actions = [entry.action for entry in session.query(AuditLog).all()]
                assert "USER_UNLOCKED" in actions

    def test_success_resets_failure_counter(self, client, make_user):
        make_user(username="resetter")
        with freeze_time("2026-03-01 11:00:00"):
            token = _csrf_from(client, "/login")
            for _ in range(3):
                client.post(
                    "/login",
                    data={
                        "username": "resetter",
                        "password": "Nope-Nope-Nope!1",
                        "csrf_token": token,
                    },
                )
            success = client.post(
                "/login",
                data={
                    "username": "resetter",
                    "password": PASSWORD,
                    "csrf_token": token,
                },
            )
            assert success.status_code == 302

            with get_db_session() as session:
                user = session.query(User).filter_by(username="resetter").one()
                assert user.failed_login_attempts == 0
                assert user.locked_until is None

    def test_expired_lockout_clears_locally(self, db_session):
        with get_db_session() as session:
            user = User(
                username="expired",
                email="expired@example.test",
                password_hash=hash_password(PASSWORD),
                role=UserRole.VIEWER,
                failed_login_attempts=settings.LOGIN_MAX_ATTEMPTS,
                locked_until=datetime(2026, 3, 1, 12, 0, tzinfo=UTC),
            )
            session.add(user)
            session.flush()

            with freeze_time("2026-03-01 11:59:00"):
                assert is_account_locked(user) is True
                assert clear_expired_lockout(user) is False

            with freeze_time("2026-03-01 12:01:00"):
                assert is_account_locked(user) is False
                assert clear_expired_lockout(user) is True
                assert user.failed_login_attempts == 0
                assert user.locked_until is None


# ---------------------------------------------------------------------------
# Enumeration resistance and generic failures
# ---------------------------------------------------------------------------


class TestEnumerationResistance:
    def test_unknown_user_and_wrong_password_are_indistinguishable(
        self, client, make_user
    ):
        make_user(username="realuser")
        token = _csrf_from(client, "/login")

        wrong_password = client.post(
            "/login",
            data={
                "username": "realuser",
                "password": "Wrong-Password!1",
                "csrf_token": token,
            },
        )
        unknown_user = client.post(
            "/login",
            data={
                "username": "ghostuser",
                "password": "Wrong-Password!1",
                "csrf_token": token,
            },
        )

        assert wrong_password.status_code == unknown_user.status_code == 200
        wrong_body = wrong_password.get_data(as_text=True)
        unknown_body = unknown_user.get_data(as_text=True)
        assert GENERIC_AUTH_ERROR in wrong_body
        assert GENERIC_AUTH_ERROR in unknown_body
        # The per-request CSP nonce is the only legitimate difference.
        normalise = lambda value: re.sub(r'nonce="[^"]+"', 'nonce="TEST"', value)
        assert normalise(wrong_body) == normalise(unknown_body)

        for leaked in (
            "does not exist",
            "no such user",
            "invalid username",
            "incorrect password",
        ):
            assert leaked not in wrong_body.lower()

    def test_dummy_hash_runs_for_unknown_users(self, client, monkeypatch):
        from services.web_api.blueprints import auth as auth_module

        calls = {"count": 0}
        original = auth_module.dummy_verify_password

        def counting(plaintext: str) -> bool:
            calls["count"] += 1
            return original(plaintext)

        monkeypatch.setattr(auth_module, "dummy_verify_password", counting)
        token = _csrf_from(client, "/login")
        client.post(
            "/login",
            data={
                "username": "unknown-person",
                "password": "Irrelevant!12345",
                "csrf_token": token,
            },
        )
        assert calls["count"] == 1

    def test_dummy_hash_not_used_for_existing_user(
        self, client, make_user, monkeypatch
    ):
        from services.web_api.blueprints import auth as auth_module

        make_user(username="knownuser")
        calls = {"count": 0}

        def counting(plaintext: str) -> bool:
            calls["count"] += 1
            return False

        monkeypatch.setattr(auth_module, "dummy_verify_password", counting)
        token = _csrf_from(client, "/login")
        client.post(
            "/login",
            data={
                "username": "knownuser",
                "password": "Wrong-Password!1",
                "csrf_token": token,
            },
        )
        assert calls["count"] == 0


# ---------------------------------------------------------------------------
# TOTP and recovery codes
# ---------------------------------------------------------------------------


class TestTotpAndRecoveryCodes:
    def test_totp_validity_and_replay_protection(self):
        secret = generate_totp_secret()
        now = 1_800_000_000.0
        code = _code_for(secret, now)

        with freeze_time(datetime.fromtimestamp(now, UTC)):
            assert verify_totp_code(secret, code) is True
        verified, step = verify_totp_code_with_step(secret, code, at_time=now)
        assert verified is True
        assert step == int(now // 30)

        replayed, replay_step = verify_totp_code_with_step(
            secret, code, last_step=step, at_time=now
        )
        assert replayed is False
        assert replay_step is None

        assert verify_totp_code_with_step(secret, "abcdef", at_time=now) == (
            False,
            None,
        )
        assert verify_totp_code_with_step(secret, "000000", at_time=now)[0] is False

    def test_secret_encryption_envelope(self):
        secret = generate_totp_secret()
        envelope = encrypt_totp_secret(secret)
        assert secret not in envelope
        assert decrypt_totp_secret(envelope) == secret

        tampered = envelope[:-2] + ("AA" if not envelope.endswith("AA") else "BB")
        with pytest.raises(CryptoError):
            decrypt_totp_secret(tampered)

    def test_recovery_codes_are_hashed_one_time_and_regenerable(self, db_session):
        secret = generate_totp_secret()
        with get_db_session() as session:
            user = User(
                username="recovery_user",
                email="recovery@example.test",
                password_hash=hash_password(PASSWORD),
                role=UserRole.VIEWER,
                is_totp_enabled=True,
                totp_secret=encrypt_totp_secret(secret),
            )
            session.add(user)
            session.flush()

            codes = issue_recovery_codes(user, session)
            assert len(codes) == settings.RECOVERY_CODE_COUNT == 10
            assert len(set(codes)) == 10

            stored = session.query(RecoveryCode).filter_by(user_id=user.id).all()
            assert len(stored) == 10
            for row in stored:
                assert row.code_hash.startswith("$argon2id$")
                assert row.code_hash not in codes

            first = codes[0]
            assert verify_recovery_code(user, first.lower(), session) is True
            assert verify_recovery_code(user, first, session) is False
            assert (
                session.query(RecoveryCode)
                .filter_by(user_id=user.id)
                .filter(RecoveryCode.used_at.isnot(None))
                .count()
                == 1
            )

            replacement_codes = issue_recovery_codes(user, session)
            assert verify_recovery_code(user, codes[1], session) is False
            assert verify_recovery_code(user, replacement_codes[0], session) is True

    def test_recovery_codes_are_regenerable_from_the_ui(self, app, make_user):
        secret = generate_totp_secret()
        user_id = make_user(
            username="regenuser",
            is_totp_enabled=True,
            totp_secret=encrypt_totp_secret(secret),
        )
        with get_db_session() as session:
            user = session.query(User).filter_by(id=user_id).one()
            old_codes = issue_recovery_codes(user, session)

        client = app.test_client()
        with freeze_time("2026-04-02 10:00:00"):
            assert _login(client, "regenuser").status_code == 302
            token = _csrf_from(client, "/login/2fa")
            verified = client.post(
                "/login/2fa", data={"code": _code_for(secret), "csrf_token": token}
            )
            assert verified.status_code == 302

            token = _csrf_from(client, "/setup-2fa")
            wrong = client.post(
                "/setup-2fa/recovery-codes",
                data={"current_password": "Wrong-Password!1", "csrf_token": token},
            )
            assert wrong.status_code == 302

            regenerated = client.post(
                "/setup-2fa/recovery-codes",
                data={"current_password": PASSWORD, "csrf_token": token},
            )
            assert regenerated.status_code == 200
            body = regenerated.get_data(as_text=True)
            displayed = set(re.findall(r"[A-Z0-9]{5}-[A-Z0-9]{5}", body))
            assert len(displayed) == settings.RECOVERY_CODE_COUNT
            assert displayed.isdisjoint(old_codes)

        with get_db_session() as session:
            user = session.query(User).filter_by(id=user_id).one()
            # Replaced codes are invalid; a newly displayed code works once.
            assert verify_recovery_code(user, old_codes[0], session) is False
            assert verify_recovery_code(user, min(displayed), session) is True
            assert verify_recovery_code(user, min(displayed), session) is False

    def test_two_factor_login_requires_code_then_blocks_replay(self, app, make_user):
        secret = generate_totp_secret()
        make_user(
            username="totpuser",
            role=UserRole.ANALYST,
            is_totp_enabled=True,
            totp_secret=encrypt_totp_secret(secret),
        )
        client = app.test_client()
        with freeze_time("2026-04-01 12:00:00"):
            staged = _login(client, "totpuser")
            assert staged.status_code == 302
            assert staged.headers["Location"].endswith("/login/2fa")

            # No authenticated session exists before the second factor.
            assert client.get("/dashboard").status_code == 401

            token = _csrf_from(client, "/login/2fa")
            code = _code_for(secret)

            failed = client.post(
                "/login/2fa", data={"code": "abcdef", "csrf_token": token}
            )
            assert failed.status_code == 200

            verified = client.post(
                "/login/2fa", data={"code": code, "csrf_token": token}
            )
            assert verified.status_code == 302
            assert verified.headers["Location"].endswith("/dashboard")

            with client.session_transaction() as sess:
                assert sess.get("is_2fa_verified") is True
                assert "pre_2fa_user_id" not in sess

            client.get("/logout")

            # A new password stage followed by the previously accepted code is
            # rejected by the last-accepted-step replay guard.
            assert _login(client, "totpuser").status_code == 302
            replay_token = _csrf_from(client, "/login/2fa")
            replayed = client.post(
                "/login/2fa", data={"code": code, "csrf_token": replay_token}
            )
            assert replayed.status_code == 200
            assert b"/dashboard" not in replayed.headers.get("Location", "").encode()

    def test_recovery_code_can_replace_totp_once(self, app, make_user):
        secret = generate_totp_secret()
        user_id = make_user(
            username="recoverylogin",
            is_totp_enabled=True,
            totp_secret=encrypt_totp_secret(secret),
        )
        with get_db_session() as session:
            user = session.query(User).filter_by(id=user_id).one()
            codes = issue_recovery_codes(user, session)

        client = app.test_client()
        assert _login(client, "recoverylogin").status_code == 302
        token = _csrf_from(client, "/login/2fa")
        success = client.post(
            "/login/2fa", data={"code": codes[0], "csrf_token": token}
        )
        assert success.status_code == 302
        assert success.headers["Location"].endswith("/dashboard")
        client.get("/logout")

        assert _login(client, "recoverylogin").status_code == 302
        token = _csrf_from(client, "/login/2fa")
        reused = client.post("/login/2fa", data={"code": codes[0], "csrf_token": token})
        assert reused.status_code == 200
        assert b"/dashboard" not in reused.headers.get("Location", "").encode()

    def test_too_many_bad_codes_clears_pending_state(self, app, make_user):
        secret = generate_totp_secret()
        make_user(
            username="bruteforce",
            is_totp_enabled=True,
            totp_secret=encrypt_totp_secret(secret),
        )
        client = app.test_client()
        with freeze_time("2026-04-01 13:00:00"):
            assert _login(client, "bruteforce").status_code == 302
            token = _csrf_from(client, "/login/2fa")
            for attempt in range(5):
                response = client.post(
                    "/login/2fa", data={"code": "abcdef", "csrf_token": token}
                )
                if attempt < 4:
                    assert response.status_code == 200
                else:
                    assert response.status_code == 302
                    assert response.headers["Location"].endswith("/login")

            with client.session_transaction() as sess:
                assert "pre_2fa_user_id" not in sess

    def test_enrollment_requires_valid_code_and_shows_codes_once(self, app, make_user):
        make_user(username="enroller", role=UserRole.ANALYST)
        client = app.test_client()
        assert _login(client, "enroller").status_code == 302

        setup_page = client.get("/setup-2fa")
        assert setup_page.status_code == 200
        with client.session_transaction() as sess:
            pending = sess.get("pending_totp_secret")
        assert isinstance(pending, str)
        secret = decrypt_totp_secret(pending)

        # Re-use the token from the page that generated this secret: a fresh GET
        # of /setup-2fa rotates the pending enrollment secret.
        token_match = CSRF_INPUT_RE.search(setup_page.get_data(as_text=True))
        assert token_match is not None
        token = token_match.group(1)
        invalid = client.post(
            "/setup-2fa", data={"code": "abcdef", "csrf_token": token}
        )
        assert invalid.status_code == 302
        with get_db_session() as session:
            user = session.query(User).filter_by(username="enroller").one()
            assert user.is_totp_enabled is False
            assert user.totp_secret is None

        enabled = client.post(
            "/setup-2fa",
            data={"code": _code_for(secret), "csrf_token": token},
        )
        assert enabled.status_code == 200
        body = enabled.get_data(as_text=True)
        displayed = set(re.findall(r"[A-Z0-9]{5}-[A-Z0-9]{5}", body))
        assert len(displayed) == 10

        with get_db_session() as session:
            user = session.query(User).filter_by(username="enroller").one()
            assert user.is_totp_enabled is True
            assert user.totp_secret is not None
            assert secret not in (user.totp_secret or "")
            assert decrypt_totp_secret(user.totp_secret or "") == secret
            stored = session.query(RecoveryCode).filter_by(user_id=user.id).all()
            assert len(stored) == 10
            for row in stored:
                assert row.code_hash not in displayed

        # Codes are shown once; revisiting the enrollment page does not re-render them.
        again = client.get("/setup-2fa").get_data(as_text=True)
        assert not any(code in again for code in displayed)


# ---------------------------------------------------------------------------
# Server-side sessions
# ---------------------------------------------------------------------------


class TestTotpEnrollmentHttpFlow:
    """End-to-end enrollment through GET/POST, cookies, CSRF, and real DB state."""

    def test_enrollment_uses_one_secret_across_reloads_and_enables_2fa(
        self, app, make_user
    ):
        make_user(username="http_enroller", role=UserRole.ANALYST)
        client = app.test_client()
        assert _login(client, "http_enroller").status_code == 302

        with get_db_session() as db:
            before = db.query(User).filter_by(username="http_enroller").one()
            assert before.is_totp_enabled is False
            assert before.totp_secret is None

        first = client.get("/setup-2fa")
        assert first.status_code == 200
        secret, qr_data, csrf = _setup_page_values(first)
        with client.session_transaction() as sess:
            pending_first = sess.get("pending_totp_secret")

        # A refresh/navigation must not rotate the secret behind the user's back.
        reloaded = client.get("/setup-2fa")
        assert reloaded.status_code == 200
        reloaded_secret, reloaded_qr, _ = _setup_page_values(reloaded)
        assert (reloaded_secret == secret) is True, "reload rotated enrollment secret"
        assert (reloaded_qr == qr_data) is True, "reload regenerated the QR code"
        with client.session_transaction() as sess:
            assert (sess.get("pending_totp_secret") == pending_first) is True

        enabled = client.post(
            "/setup-2fa",
            data={"code": pyotp.TOTP(secret).now(), "csrf_token": csrf},
        )
        assert enabled.status_code == 200
        body = enabled.get_data(as_text=True)
        displayed = set(re.findall(r"[A-Z0-9]{5}-[A-Z0-9]{5}", body))
        assert len(displayed) == settings.RECOVERY_CODE_COUNT

        with get_db_session() as db:
            user = db.query(User).filter_by(username="http_enroller").one()
            assert user.is_totp_enabled is True
            assert user.totp_secret is not None
            assert (decrypt_totp_secret(user.totp_secret) == secret) is True
            stored = db.query(RecoveryCode).filter_by(user_id=user.id).all()
            assert len(stored) == settings.RECOVERY_CODE_COUNT
            for entry in db.query(AuditLog).all():
                payload = entry.details or ""
                assert secret not in payload
                assert not any(code in payload for code in displayed)

        with client.session_transaction() as sess:
            assert "pending_totp_secret" not in sess

    def test_wrong_code_reports_invalid_code_not_not_activated(self, app, make_user):
        make_user(username="wrong_code_enroller", role=UserRole.ANALYST)
        client = app.test_client()
        assert _login(client, "wrong_code_enroller").status_code == 302
        page = client.get("/setup-2fa")
        secret, _, csrf = _setup_page_values(page)

        # Pick a numeric code that cannot match any code accepted by the
        # current +/-1 step verification window, so this never flakes.
        now = time.time()
        accepted_codes = {_code_for(secret, now + offset * 30) for offset in (-1, 0, 1)}
        wrong_code = next(
            code
            for code in ("000000", "111111", "222222", "333333", "444444")
            if code not in accepted_codes
        )
        rejected = client.post(
            "/setup-2fa", data={"code": wrong_code, "csrf_token": csrf}
        )
        assert rejected.status_code == 302
        with client.session_transaction() as sess:
            messages = [str(item[1]) for item in sess.get("_flashes", [])]
        assert any("Invalid verification code" in message for message in messages)
        assert not any("not activated" in message.lower() for message in messages)

        # The rejected code must not destroy the pending enrollment.
        with client.session_transaction() as sess:
            assert isinstance(sess.get("pending_totp_secret"), str)
        with get_db_session() as db:
            user = db.query(User).filter_by(username="wrong_code_enroller").one()
            assert user.is_totp_enabled is False

        retry = client.get("/setup-2fa")
        retry_secret, _, retry_csrf = _setup_page_values(retry)
        assert (retry_secret == secret) is True
        enabled = client.post(
            "/setup-2fa",
            data={"code": pyotp.TOTP(secret).now(), "csrf_token": retry_csrf},
        )
        assert enabled.status_code == 200

    def test_missing_pending_secret_reports_not_activated(self, app, make_user):
        make_user(username="no_pending_enroller", role=UserRole.ANALYST)
        client = app.test_client()
        assert _login(client, "no_pending_enroller").status_code == 302
        page = client.get("/setup-2fa")
        secret, _, csrf = _setup_page_values(page)

        with client.session_transaction() as sess:
            sess.pop("pending_totp_secret", None)

        rejected = client.post(
            "/setup-2fa",
            data={"code": pyotp.TOTP(secret).now(), "csrf_token": csrf},
        )
        assert rejected.status_code == 302
        with client.session_transaction() as sess:
            messages = [str(item[1]) for item in sess.get("_flashes", [])]
        assert any("not activated" in message.lower() for message in messages)
        assert not any("Invalid verification code" in message for message in messages)
        with get_db_session() as db:
            user = db.query(User).filter_by(username="no_pending_enroller").one()
            assert user.is_totp_enabled is False

    def test_forced_password_change_rotation_preserves_pending_enrollment(
        self, app, make_user
    ):
        make_user(username="rotated_enroller", must_change_password=True)
        client = app.test_client()
        assert (
            _login(client, "rotated_enroller")
            .headers["Location"]
            .endswith("/change-password")
        )

        staged_secret = generate_totp_secret()
        with client.session_transaction() as sess:
            sess["pending_totp_secret"] = encrypt_totp_secret(staged_secret)

        changed = client.post(
            "/change-password",
            data={
                "current_password": PASSWORD,
                "new_password": SECOND_PASSWORD,
                "confirm_password": SECOND_PASSWORD,
                "csrf_token": _csrf_from(client, "/change-password"),
            },
        )
        assert changed.status_code == 302

        page = client.get("/setup-2fa")
        rendered_secret, _, csrf = _setup_page_values(page)
        assert (rendered_secret == staged_secret) is True

        enabled = client.post(
            "/setup-2fa",
            data={"code": pyotp.TOTP(staged_secret).now(), "csrf_token": csrf},
        )
        assert enabled.status_code == 200
        with get_db_session() as db:
            user = db.query(User).filter_by(username="rotated_enroller").one()
            assert user.must_change_password is False
            assert user.is_totp_enabled is True


class TestServerSideSessions:
    def test_session_id_is_rotated_at_login(self, app, make_user):
        make_user(username="fixation")
        client = app.test_client()
        with client.session_transaction() as sess:
            sess["sid"] = "attacker-fixed-token"
            sess["is_2fa_verified"] = True

        assert _login(client, "fixation").status_code == 302
        with client.session_transaction() as sess:
            sid = sess["sid"]
            assert sid != "attacker-fixed-token"

        with get_db_session() as session:
            assert (
                session.query(UserSession)
                .filter_by(session_token=hash_session_token("attacker-fixed-token"))
                .first()
                is None
            )
            record = get_session_by_token(sid, session)
            assert record is not None
            assert record.is_revoked is False

    def test_logout_revokes_server_side_session(self, app, make_user):
        make_user(username="logoutuser")
        client = app.test_client()
        assert _login(client, "logoutuser").status_code == 302
        with client.session_transaction() as sess:
            sid = sess["sid"]

        cookie = client.get_cookie("ai_ids_session")
        assert cookie is not None
        old_value = cookie.value

        assert client.get("/logout").status_code == 302
        with get_db_session() as session:
            record = get_session_by_token(sid, session)
            assert record is not None
            assert record.is_revoked is True
            assert record.revoke_reason == "logout"

        # Replaying the pre-logout cookie cannot resurrect the revoked session.
        stale_client = app.test_client()
        stale_client.set_cookie("ai_ids_session", old_value)
        replay = stale_client.get("/dashboard")
        assert replay.status_code == 302
        assert replay.headers["Location"].endswith("/login")

    def test_idle_timeout_revokes_session(self, db_session):
        secret = generate_totp_secret()
        with get_db_session() as session:
            user = User(
                username="idleuser",
                email="idle@example.test",
                password_hash=hash_password(PASSWORD),
                role=UserRole.VIEWER,
                is_totp_enabled=True,
                totp_secret=encrypt_totp_secret(secret),
            )
            session.add(user)
            session.flush()

            with freeze_time("2026-05-01 08:00:00"):
                token = create_user_session(user, session)

            with freeze_time("2026-05-01 08:31:00"):
                assert validate_user_session(token, session) is None
                record = get_session_by_token(token, session)
                assert record is not None
                assert record.is_revoked is True
                assert record.revoke_reason == "idle_timeout"

    def test_absolute_timeout_revokes_session(self, db_session):
        secret = generate_totp_secret()
        with get_db_session() as session:
            user = User(
                username="absoluteuser",
                email="absolute@example.test",
                password_hash=hash_password(PASSWORD),
                role=UserRole.VIEWER,
                is_totp_enabled=True,
                totp_secret=encrypt_totp_secret(secret),
            )
            session.add(user)
            session.flush()

            with freeze_time("2026-05-01 08:00:00"):
                token = create_user_session(user, session)

            with freeze_time("2026-05-01 16:01:00"):
                record = get_session_by_token(token, session)
                assert record is not None
                # Keep the idle window fresh so only the absolute limit applies.
                record.last_activity_at = datetime.now(UTC) - timedelta(seconds=30)
                assert validate_user_session(token, session) is None
                assert record.is_revoked is True
                assert record.revoke_reason == "absolute_timeout"

    def test_revoke_all_sessions(self, db_session):
        secret = generate_totp_secret()
        with get_db_session() as session:
            user = User(
                username="multisession",
                email="multi@example.test",
                password_hash=hash_password(PASSWORD),
                role=UserRole.VIEWER,
                is_totp_enabled=True,
                totp_secret=encrypt_totp_secret(secret),
            )
            session.add(user)
            session.flush()

            tokens = [create_user_session(user, session) for _ in range(3)]
            revoked = revoke_all_user_sessions(user.id, session, "password_change")
            assert revoked == 3
            for token in tokens:
                record = get_session_by_token(token, session)
                assert record is not None
                assert record.is_revoked is True
                assert record.revoke_reason == "password_change"


# ---------------------------------------------------------------------------
# Password change and forced rotation
# ---------------------------------------------------------------------------


class TestPasswordChangeFlow:
    def test_forced_password_change_blocks_other_routes(self, app, make_user):
        make_user(
            username="forcedadmin",
            role=UserRole.ADMIN,
            must_change_password=True,
        )
        client = app.test_client()
        login_response = _login(client, "forcedadmin")
        assert login_response.status_code == 302
        assert login_response.headers["Location"].endswith("/change-password")

        blocked = client.get("/dashboard")
        assert blocked.status_code == 302
        assert blocked.headers["Location"].endswith("/change-password")

        page = client.get("/change-password")
        assert page.status_code == 200
        token = _csrf_from(client, "/change-password")
        changed = client.post(
            "/change-password",
            data={
                "current_password": PASSWORD,
                "new_password": SECOND_PASSWORD,
                "confirm_password": SECOND_PASSWORD,
                "csrf_token": token,
            },
        )
        assert changed.status_code == 302
        assert changed.headers["Location"].endswith("/dashboard")

        with get_db_session() as session:
            user = session.query(User).filter_by(username="forcedadmin").one()
            assert user.must_change_password is False
            assert verify_password(user.password_hash, SECOND_PASSWORD) is True
            actions = [entry.action for entry in session.query(AuditLog).all()]
            assert "PASSWORD_CHANGED" in actions

        assert client.get("/dashboard").status_code == 200

    def test_password_change_rotates_session_and_revokes_others(self, app, make_user):
        make_user(username="rotator")
        client = app.test_client()
        assert _login(client, "rotator").status_code == 302
        with client.session_transaction() as sess:
            old_sid = sess["sid"]

        # Another live session for the same account is revoked by the change.
        with get_db_session() as session:
            user = session.query(User).filter_by(username="rotator").one()
            other_token = create_user_session(user, session)

        token = _csrf_from(client, "/change-password")
        changed = client.post(
            "/change-password",
            data={
                "current_password": PASSWORD,
                "new_password": SECOND_PASSWORD,
                "confirm_password": SECOND_PASSWORD,
                "csrf_token": token,
            },
        )
        assert changed.status_code == 302

        with client.session_transaction() as sess:
            new_sid = sess["sid"]
        assert new_sid != old_sid

        with get_db_session() as session:
            old_record = get_session_by_token(old_sid, session)
            assert old_record is not None
            assert old_record.is_revoked is True
            assert old_record.revoke_reason == "password_change"
            other_record = get_session_by_token(other_token, session)
            assert other_record is not None
            assert other_record.is_revoked is True

    def test_password_reuse_is_rejected(self, app, make_user):
        make_user(username="reuser")
        client = app.test_client()
        assert _login(client, "reuser").status_code == 302

        token = _csrf_from(client, "/change-password")
        first = client.post(
            "/change-password",
            data={
                "current_password": PASSWORD,
                "new_password": SECOND_PASSWORD,
                "confirm_password": SECOND_PASSWORD,
                "csrf_token": token,
            },
        )
        assert first.status_code == 302

        token = _csrf_from(client, "/change-password")
        reuse = client.post(
            "/change-password",
            data={
                "current_password": SECOND_PASSWORD,
                "new_password": PASSWORD,
                "confirm_password": PASSWORD,
                "csrf_token": token,
            },
        )
        assert reuse.status_code == 400
        assert "must not match" in reuse.get_data(as_text=True).lower()

    def test_password_confirmation_mismatch_is_rejected(self, app, make_user):
        make_user(username="mismatch")
        client = app.test_client()
        assert _login(client, "mismatch").status_code == 302
        token = _csrf_from(client, "/change-password")
        response = client.post(
            "/change-password",
            data={
                "current_password": PASSWORD,
                "new_password": SECOND_PASSWORD,
                "confirm_password": "Different-Passphrase!9",
                "csrf_token": token,
            },
        )
        assert response.status_code == 400
        assert "do not match" in response.get_data(as_text=True).lower()

    def test_totp_user_password_change_forces_reverification(self, app, make_user):
        secret = generate_totp_secret()
        make_user(
            username="totpchange",
            is_totp_enabled=True,
            totp_secret=encrypt_totp_secret(secret),
        )
        client = app.test_client()
        with freeze_time("2026-06-01 10:00:00"):
            assert _login(client, "totpchange").status_code == 302
            token = _csrf_from(client, "/login/2fa")
            verified = client.post(
                "/login/2fa",
                data={"code": _code_for(secret), "csrf_token": token},
            )
            assert verified.status_code == 302

            token = _csrf_from(client, "/change-password")
            changed = client.post(
                "/change-password",
                data={
                    "current_password": PASSWORD,
                    "new_password": SECOND_PASSWORD,
                    "confirm_password": SECOND_PASSWORD,
                    "csrf_token": token,
                },
            )
            assert changed.status_code == 302

            with client.session_transaction() as sess:
                assert sess.get("is_2fa_verified") is False

            reverify = client.get("/dashboard")
            assert reverify.status_code == 302
            assert reverify.headers["Location"].endswith("/login")


# ---------------------------------------------------------------------------
# Open redirect handling
# ---------------------------------------------------------------------------


class TestOpenRedirect:
    @pytest.mark.parametrize(
        "target,expected",
        [
            ("/dashboard", True),
            ("/audit?range=7d", True),
            ("https://evil.example/steal", False),
            ("//evil.example/steal", False),
            ("/\\evil.example", False),
            ("javascript:alert(1)", False),
            ("", False),
            (None, False),
        ],
    )
    def test_is_safe_next_url(self, target, expected):
        assert is_safe_next_url(target) is expected

    def test_safe_next_url_falls_back_to_dashboard(self):
        assert safe_next_url("https://evil.example") == "/dashboard"
        assert safe_next_url("/audit") == "/audit"

    def test_login_ignores_external_next_value(self, client, make_user):
        make_user(username="redirectuser")
        token = _csrf_from(client, "/login")
        response = client.post(
            "/login",
            data={
                "username": "redirectuser",
                "password": PASSWORD,
                "next": "https://evil.example/steal",
                "csrf_token": token,
            },
        )
        assert response.status_code == 302
        assert response.headers["Location"].endswith("/dashboard")
        assert "evil.example" not in response.headers["Location"]


# ---------------------------------------------------------------------------
# CSRF and rate limiting
# ---------------------------------------------------------------------------


class TestCsrfAndRateLimiting:
    def test_state_changing_post_without_csrf_is_rejected(self, client):
        response = client.post(
            "/login", data={"username": "someone", "password": "something"}
        )
        assert response.status_code == 400
        assert b"CSRF" in response.data or b"csrf" in response.data.lower()

    def test_csrf_token_can_be_sent_in_header(self, client, make_user):
        make_user(username="headeruser")
        token = _csrf_from(client, "/login")
        response = client.post(
            "/login",
            data={"username": "headeruser", "password": PASSWORD},
            headers={"X-CSRFToken": token},
        )
        assert response.status_code == 302
        assert response.headers["Location"].endswith("/dashboard")

    def test_json_error_negotiation(self, client, make_user, app):
        anonymous = client.get("/dashboard", headers={"Accept": "application/json"})
        assert anonymous.status_code == 401
        assert anonymous.is_json
        assert anonymous.get_json()["error"] == "authentication_required"

        make_user(username="viewerjson", role=UserRole.VIEWER)
        viewer = app.test_client()
        assert _login(viewer, "viewerjson").status_code == 302
        forbidden = viewer.get("/users", headers={"Accept": "application/json"})
        assert forbidden.status_code == 403
        assert forbidden.is_json
        assert forbidden.get_json()["error"] == "forbidden"

    def test_login_rate_limit_returns_429(self, client):
        token = _csrf_from(client, "/login")
        statuses = []
        for _ in range(11):
            response = client.post(
                "/login",
                data={
                    "username": "rate-limited",
                    "password": "Wrong-Password!1",
                    "csrf_token": token,
                },
            )
            statuses.append(response.status_code)
        assert statuses[:10] == [200] * 10
        assert statuses[10] == 429


# ---------------------------------------------------------------------------
# Audit ledger integrity
# ---------------------------------------------------------------------------


class TestAuditLedger:
    def test_security_events_form_a_valid_chain(self):
        from core.security import audit_details, log_security_event

        for index in range(5):
            log_security_event(
                action="TEST_EVENT",
                resource_type="TEST",
                resource_id=str(index),
                username="tester",
                details=audit_details(index=index),
            )

        with get_db_session() as session:
            entries = session.query(AuditLog).order_by(AuditLog.id.asc()).all()
            assert len(entries) == 5
            assert AuditLog.verify_chain(settings.AUDIT_HMAC_SECRET, entries) == []

    def test_tampering_breaks_verification(self, db_session):
        from core.security import audit_details, log_security_event

        for index in range(3):
            log_security_event(
                action="CHAIN_EVENT",
                resource_type="TEST",
                resource_id=str(index),
                username="tester",
                details=audit_details(index=index),
            )

        with get_db_session() as session:
            entries = session.query(AuditLog).order_by(AuditLog.id.asc()).all()
            target = entries[1]
            target_id = target.id
            target.action = "CHAIN_EVENT_TAMPERED"
            session.commit()

        with get_db_session() as session:
            entries = session.query(AuditLog).order_by(AuditLog.id.asc()).all()
            assert AuditLog.verify_chain(settings.AUDIT_HMAC_SECRET, entries) == [
                target_id
            ]

    def test_v1_and_v2_entries_verify_together(self, db_session):
        from core.models.audit import GENESIS_HASH

        with get_db_session() as session:
            v1 = AuditLog.create_entry(
                hmac_key=settings.AUDIT_HMAC_SECRET,
                prev_hash=GENESIS_HASH,
                user_id=None,
                username="system",
                action="LEGACY_EVENT",
                resource_type="TEST",
                resource_id="1",
                status="SUCCESS",
                details=json.dumps({"legacy": True}),
                hash_version=1,
            )
            session.add(v1)
            session.flush()

            v2 = AuditLog.create_entry(
                hmac_key=settings.AUDIT_HMAC_SECRET,
                prev_hash=v1.entry_hash,
                user_id=None,
                username="system",
                action="MODERN_EVENT",
                resource_type="TEST",
                resource_id="2",
                status="SUCCESS",
                details=json.dumps({"modern": True}),
                ip_address="127.0.0.1",
                correlation_id="corr-1",
                hash_version=2,
            )
            session.add(v2)
            session.commit()

        with get_db_session() as session:
            entries = session.query(AuditLog).order_by(AuditLog.id.asc()).all()
            assert [entry.hash_version for entry in entries] == [1, 2]
            assert AuditLog.verify_chain(settings.AUDIT_HMAC_SECRET, entries) == []

    def test_audit_entries_never_contain_password_or_totp_secrets(self, app, make_user):
        secret = generate_totp_secret()
        make_user(
            username="audituser",
            is_totp_enabled=True,
            totp_secret=encrypt_totp_secret(secret),
        )
        client = app.test_client()
        assert _login(client, "audituser").status_code == 302
        token = _csrf_from(client, "/login/2fa")
        client.post("/login/2fa", data={"code": _code_for(secret), "csrf_token": token})

        with get_db_session() as session:
            entries = session.query(AuditLog).all()
            assert entries
            for entry in entries:
                payload = entry.details or ""
                assert PASSWORD not in payload
                assert secret not in payload

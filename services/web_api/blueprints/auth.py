"""Authentication & Two-Factor Authentication Blueprint.

Handles credential verification, generic failure responses, account lockout,
password policy/history, encrypted TOTP enrollment, replay protection,
one-time recovery codes, and server-side session lifecycle.
"""

from __future__ import annotations

from datetime import UTC, datetime

from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import current_user, login_required, login_user, logout_user
from pydantic import ValidationError

from core.config import settings
from core.crypto import CryptoError
from core.db import get_db_session
from core.logging import get_logger
from core.models.user import User
from core.schemas import PasswordChange
from core.security import (
    GENERIC_2FA_ERROR,
    GENERIC_AUTH_ERROR,
    audit_details,
    clear_expired_lockout,
    create_user_session,
    decrypt_totp_secret,
    dummy_verify_password,
    encrypt_totp_secret,
    generate_qr_code_svg,
    generate_totp_secret,
    get_client_ip,
    get_totp_uri,
    hash_password,
    is_account_locked,
    is_password_reused,
    issue_recovery_codes,
    log_security_event,
    record_failed_login,
    record_password_history,
    rehash_password_if_needed,
    reset_failed_login_attempts,
    revoke_all_user_sessions,
    revoke_session,
    safe_next_url,
    validate_password_policy,
    verify_password,
    verify_recovery_code,
    verify_totp_code_with_step,
)
from services.web_api import limiter

logger = get_logger(__name__)

auth_bp = Blueprint("auth", __name__)

PRE_2FA_USER_KEY = "pre_2fa_user_id"
PRE_2FA_FAILURES_KEY = "pre_2fa_failures"
PENDING_TOTP_KEY = "pending_totp_secret"
MAX_2FA_FAILURES = 5

# Keep the two failure modes distinguishable for the user: a missing pending
# enrollment is not the same as a wrong code for a live enrollment.
ENROLLMENT_NOT_ACTIVE_ERROR = (
    "Two-factor authentication is not activated. Open the enrollment page "
    "and scan the QR code again."
)
INVALID_ENROLLMENT_CODE_ERROR = "Invalid verification code. Please try again."


def _log_failed_login(
    db_session, username: str, reason: str, user: User | None = None
) -> None:
    """Record a generic login failure without leaking account existence."""
    log_security_event(
        action="USER_LOGIN_FAILED",
        resource_type="USER",
        resource_id=str(user.id) if user else None,
        user_id=user.id if user else None,
        username=user.username if user else username or "unknown",
        status="FAILED",
        details=audit_details(reason=reason),
        db_session=db_session,
    )


def _finalize_login(
    user: User, db_session, auth_method: str, next_url: str | None
) -> str:
    """Rotate the session, create server-side state, and sign the user in."""
    session.clear()
    session_token = create_user_session(user, db_session)
    session["sid"] = session_token
    session["is_2fa_verified"] = True
    session.permanent = True
    login_user(user, remember=False, fresh=True)

    user.last_login_at = datetime.now(UTC)
    user.last_login_ip = get_client_ip()

    log_security_event(
        action="USER_LOGIN_SUCCESS",
        resource_type="USER",
        resource_id=str(user.id),
        user_id=user.id,
        username=user.username,
        status="SUCCESS",
        details=audit_details(auth_method=auth_method),
        db_session=db_session,
    )
    db_session.flush()

    if user.must_change_password:
        flash(
            "Initial password change required before accessing defensive controls.",
            "warning",
        )
        return url_for("auth.change_password")
    return safe_next_url(next_url)


def _stage_2fa(user: User) -> None:
    """Create a password-verified but unauthenticated pending-2FA state."""
    session.clear()
    session[PRE_2FA_USER_KEY] = user.id
    session[PRE_2FA_FAILURES_KEY] = 0
    session["pre_2fa_started_at"] = datetime.now(UTC).isoformat()
    session["is_2fa_verified"] = False


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])
@limiter.limit("60 per hour", methods=["POST"])
def login():
    """Authenticate with username/password before any second-factor challenge."""
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        next_url = request.form.get("next") or request.args.get("next")

        if not username or not password:
            flash("Username and password are required.", "error")
            return render_template("auth/login.html", next_url=next_url), 400

        with get_db_session() as db_session:
            user = db_session.query(User).filter_by(username=username).first()

            if user is None:
                # Burn equivalent Argon2id work so unknown users are not
                # distinguishable from wrong-password responses by timing.
                dummy_verify_password(password)
                _log_failed_login(db_session, username, "invalid_credentials")
                flash(GENERIC_AUTH_ERROR, "error")
                return render_template("auth/login.html", next_url=next_url)

            password_ok = verify_password(user.password_hash, password)

            if not password_ok:
                newly_locked = record_failed_login(user, db_session)
                _log_failed_login(db_session, username, "invalid_credentials", user)
                if newly_locked:
                    log_security_event(
                        action="USER_LOCKED",
                        resource_type="USER",
                        resource_id=str(user.id),
                        user_id=user.id,
                        username=user.username,
                        status="LOCKED",
                        details=audit_details(
                            failed_attempts=user.failed_login_attempts,
                            locked_until=(
                                user.locked_until.isoformat()
                                if user.locked_until
                                else None
                            ),
                            reason="failed_login_threshold",
                        ),
                        db_session=db_session,
                    )
                db_session.commit()
                flash(GENERIC_AUTH_ERROR, "error")
                return render_template("auth/login.html", next_url=next_url)

            # Password is correct. Keep inactive/locked responses identical.
            if not user.is_active:
                _log_failed_login(db_session, username, "account_inactive", user)
                flash(GENERIC_AUTH_ERROR, "error")
                return render_template("auth/login.html", next_url=next_url)

            if is_account_locked(user):
                _log_failed_login(db_session, username, "account_locked", user)
                flash(GENERIC_AUTH_ERROR, "error")
                return render_template("auth/login.html", next_url=next_url)

            if clear_expired_lockout(user):
                log_security_event(
                    action="USER_UNLOCKED",
                    resource_type="USER",
                    resource_id=str(user.id),
                    user_id=user.id,
                    username=user.username,
                    status="SUCCESS",
                    details=audit_details(reason="lockout_expired"),
                    db_session=db_session,
                )

            reset_failed_login_attempts(user)
            rehash_password_if_needed(user, password)

            if user.is_totp_enabled:
                _stage_2fa(user)
                db_session.commit()
                log_security_event(
                    action="USER_LOGIN_PASSWORD_VERIFIED",
                    resource_type="USER",
                    resource_id=str(user.id),
                    user_id=user.id,
                    username=user.username,
                    status="SUCCESS",
                    details=audit_details(auth_method="password_pending_2fa"),
                    db_session=db_session,
                )
                return redirect(url_for("auth.login_2fa"))

            destination = _finalize_login(user, db_session, "password_only", next_url)
            db_session.commit()
            flash(f"Authenticated successfully as {user.username}.", "success")
            return redirect(destination)

    return render_template("auth/login.html", next_url=request.args.get("next"))


@auth_bp.route("/login/2fa", methods=["GET", "POST"])
@limiter.limit("10 per 5 minutes", methods=["POST"])
@limiter.limit("30 per 15 minutes", methods=["POST"])
def login_2fa():
    """Second-factor challenge. No authenticated session exists before this."""
    user_id = session.get(PRE_2FA_USER_KEY)
    if not user_id:
        return redirect(url_for("auth.login"))
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        failures = int(session.get(PRE_2FA_FAILURES_KEY, 0) or 0)

        if failures >= MAX_2FA_FAILURES:
            session.clear()
            flash(GENERIC_2FA_ERROR, "error")
            return redirect(url_for("auth.login"))

        with get_db_session() as db_session:
            user = db_session.query(User).filter_by(id=user_id).first()
            if not user or not user.is_active or not user.is_totp_enabled:
                session.clear()
                flash(GENERIC_2FA_ERROR, "error")
                return redirect(url_for("auth.login"))

            verified = False
            matched_step: int | None = None
            method = "totp"

            if code.isdigit() and len(code) == 6:
                try:
                    secret = decrypt_totp_secret(user.totp_secret or "")
                    verified, matched_step = verify_totp_code_with_step(
                        secret, code, last_step=user.totp_last_step
                    )
                except CryptoError:
                    log_security_event(
                        action="2FA_SECRET_DECRYPT_FAILED",
                        resource_type="USER",
                        resource_id=str(user.id),
                        user_id=user.id,
                        username=user.username,
                        status="FAILED",
                        details=audit_details(reason="ciphertext_invalid"),
                        db_session=db_session,
                    )
                    verified = False
            else:
                method = "recovery_code"
                verified = verify_recovery_code(
                    user, code, db_session, ip_address=get_client_ip()
                )

            if not verified:
                failures += 1
                session[PRE_2FA_FAILURES_KEY] = failures
                log_security_event(
                    action="TWO_FACTOR_FAILED",
                    resource_type="USER",
                    resource_id=str(user.id),
                    user_id=user.id,
                    username=user.username,
                    status="FAILED",
                    details=audit_details(
                        method=method,
                        attempt=failures,
                        max_attempts=MAX_2FA_FAILURES,
                    ),
                    db_session=db_session,
                )
                db_session.commit()
                if failures >= MAX_2FA_FAILURES:
                    session.clear()
                    flash(
                        "Too many failed verification attempts. Please sign in again.",
                        "error",
                    )
                    return redirect(url_for("auth.login"))
                flash(GENERIC_2FA_ERROR, "error")
                return render_template("auth/login_2fa.html")

            if method == "totp" and matched_step is not None:
                user.totp_last_step = matched_step

            session.pop(PRE_2FA_USER_KEY, None)
            session.pop(PRE_2FA_FAILURES_KEY, None)
            session.pop("pre_2fa_started_at", None)
            reset_failed_login_attempts(user)
            destination = _finalize_login(user, db_session, method, None)
            db_session.commit()

            flash(f"Two-factor authentication verified for {user.username}.", "success")
            return redirect(destination)

    return render_template("auth/login_2fa.html")


@auth_bp.route("/logout")
def logout():
    """Revoke the server-side session, clear cookies, and sign out."""
    if current_user.is_authenticated:
        sid = session.get("sid")
        with get_db_session() as db_session:
            if isinstance(sid, str) and sid:
                revoke_session(sid, db_session, reason="logout")
            log_security_event(
                action="USER_LOGOUT",
                resource_type="USER",
                resource_id=str(current_user.id),
                user_id=current_user.id,
                username=current_user.username,
                status="SUCCESS",
                db_session=db_session,
            )
        logout_user()
    session.clear()
    flash("You have been signed out.", "info")
    return redirect(url_for("auth.login"))


@auth_bp.route("/change-password", methods=["GET", "POST"])
@login_required
@limiter.limit("10 per hour", methods=["POST"])
def change_password():
    """Change the account password and invalidate every other session."""
    if request.method == "POST":
        try:
            payload = PasswordChange(
                current_password=request.form.get("current_password", ""),
                new_password=request.form.get("new_password", ""),
                confirm_password=request.form.get("confirm_password", ""),
            )
        except ValidationError as exc:
            for error in exc.errors():
                flash(error["msg"], "error")
            return render_template("auth/change_password.html"), 400

        with get_db_session() as db_session:
            user = db_session.query(User).filter_by(id=current_user.id).first()
            if user is None:
                flash(GENERIC_AUTH_ERROR, "error")
                return redirect(url_for("auth.logout"))

            if not verify_password(user.password_hash, payload.current_password):
                flash("Current password provided is incorrect.", "error")
                return render_template("auth/change_password.html"), 400

            is_valid, errors = validate_password_policy(
                payload.new_password, username=user.username, email=user.email
            )
            if not is_valid:
                for error in errors:
                    flash(error, "error")
                return render_template("auth/change_password.html"), 400

            if is_password_reused(user, payload.new_password, db_session):
                flash(
                    f"Password must not match your current password or your last "
                    f"{settings.PASSWORD_HISTORY_DEPTH} passwords.",
                    "error",
                )
                return render_template("auth/change_password.html"), 400

            previous_hash = user.password_hash
            user.password_hash = hash_password(payload.new_password)
            user.must_change_password = False
            user.last_password_change_at = datetime.now(UTC)
            record_password_history(user, previous_hash, db_session)

            # Password changes revoke every existing server-side session. The
            # current browser receives a brand-new token so the user stays
            # signed in without reusing the old session identifier.
            revoke_all_user_sessions(user.id, db_session, reason="password_change")
            new_token = create_user_session(user, db_session)
            session["sid"] = new_token
            # A password change revokes all sessions. The fresh token is only
            # considered 2FA-verified if the account does not require 2FA;
            # otherwise the global guard forces a new login + code entry.
            session["is_2fa_verified"] = not user.is_totp_enabled

            log_security_event(
                action="PASSWORD_CHANGED",
                resource_type="USER",
                resource_id=str(user.id),
                user_id=user.id,
                username=user.username,
                status="SUCCESS",
                details=audit_details(target_user=user.username),
                db_session=db_session,
            )
            db_session.commit()

            flash("Password updated successfully.", "success")
            return redirect(url_for("dashboard.index"))

    return render_template("auth/change_password.html")


@auth_bp.route("/setup-2fa", methods=["GET", "POST"])
@login_required
@limiter.limit("20 per hour", methods=["POST"])
def setup_2fa():
    """Enroll or manage encrypted TOTP two-factor authentication."""
    with get_db_session() as db_session:
        user = db_session.query(User).filter_by(id=current_user.id).first()
        if user is None:
            return redirect(url_for("auth.logout"))

        if request.method == "POST":
            if user.is_totp_enabled:
                flash("Two-factor authentication is already enabled.", "info")
                return redirect(url_for("auth.setup_2fa"))

            pending = session.get(PENDING_TOTP_KEY)
            if not isinstance(pending, str):
                flash(ENROLLMENT_NOT_ACTIVE_ERROR, "error")
                return redirect(url_for("auth.setup_2fa"))

            try:
                secret = decrypt_totp_secret(pending)
            except CryptoError:
                session.pop(PENDING_TOTP_KEY, None)
                flash(
                    "Enrollment data could not be verified. Please try again.", "error"
                )
                return redirect(url_for("auth.setup_2fa"))

            code = request.form.get("code", "").strip()
            verified, matched_step = verify_totp_code_with_step(secret, code)
            if not verified:
                flash(INVALID_ENROLLMENT_CODE_ERROR, "error")
                return redirect(url_for("auth.setup_2fa"))

            # Only persist the encrypted envelope, never the raw secret.
            user.totp_secret = encrypt_totp_secret(secret)
            user.is_totp_enabled = True
            user.totp_last_step = matched_step
            session.pop(PENDING_TOTP_KEY, None)
            session["is_2fa_verified"] = True

            recovery_codes = issue_recovery_codes(user, db_session)
            log_security_event(
                action="2FA_ENABLED",
                resource_type="USER",
                resource_id=str(user.id),
                user_id=user.id,
                username=user.username,
                status="SUCCESS",
                details=audit_details(target_user=user.username, method="totp"),
                db_session=db_session,
            )
            db_session.commit()

            return render_template(
                "auth/recovery_codes.html",
                recovery_codes=recovery_codes,
                page_title="Two-Factor Authentication Enabled",
            )

        if user.is_totp_enabled:
            return render_template("auth/setup_2fa.html", enabled=True)

        # An enrollment secret belongs to the whole enrollment, not to a single
        # page render. Reusing it keeps a QR that was already scanned valid when
        # the page is reloaded or navigated back to.
        pending = session.get(PENDING_TOTP_KEY)
        secret: str | None = None
        if isinstance(pending, str):
            try:
                secret = decrypt_totp_secret(pending)
            except CryptoError:
                session.pop(PENDING_TOTP_KEY, None)
        if secret is None:
            secret = generate_totp_secret()
            session[PENDING_TOTP_KEY] = encrypt_totp_secret(secret)

        uri = get_totp_uri(secret, user.username)
        qr_data = generate_qr_code_svg(uri)
        return render_template(
            "auth/setup_2fa.html",
            enabled=False,
            secret=secret,
            qr_code_data=qr_data,
        )


@auth_bp.route("/setup-2fa/recovery-codes", methods=["POST"])
@login_required
@limiter.limit("5 per hour", methods=["POST"])
def regenerate_recovery_codes():
    """Regenerate one-time recovery codes after re-verifying the password."""
    current_password = request.form.get("current_password", "")
    with get_db_session() as db_session:
        user = db_session.query(User).filter_by(id=current_user.id).first()
        if user is None:
            return redirect(url_for("auth.logout"))
        if not user.is_totp_enabled:
            flash(
                "Enable two-factor authentication before generating recovery codes.",
                "error",
            )
            return redirect(url_for("auth.setup_2fa"))
        if not verify_password(user.password_hash, current_password):
            flash("Current password provided is incorrect.", "error")
            return redirect(url_for("auth.setup_2fa"))

        recovery_codes = issue_recovery_codes(user, db_session)
        log_security_event(
            action="RECOVERY_CODES_REGENERATED",
            resource_type="USER",
            resource_id=str(user.id),
            user_id=user.id,
            username=user.username,
            status="SUCCESS",
            details=audit_details(target_user=user.username),
            db_session=db_session,
        )
        db_session.commit()

    return render_template(
        "auth/recovery_codes.html",
        recovery_codes=recovery_codes,
        page_title="New Recovery Codes",
    )

"""Authentication & Two-Factor Authentication Blueprint.

Handles credentials verification, account lockouts, TOTP 2FA, password change enforcement,
and audit logging.
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

from core.db import get_db_session
from core.logging import get_logger
from core.models.user import User
from core.security import (
    generate_qr_code_svg,
    generate_totp_secret,
    get_totp_uri,
    hash_password,
    is_account_locked,
    log_security_event,
    record_failed_login,
    reset_failed_login_attempts,
    validate_password_complexity,
    verify_password,
    verify_totp_code,
)

logger = get_logger(__name__)

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """Authenticate user with username and password, with account lockout protection."""
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Username and password are required.", "error")
            return render_template("auth/login.html")

        with get_db_session() as db_session:
            user = db_session.query(User).filter_by(username=username).first()

            if not user:
                logger.warning(f"Login attempt failed: Unknown username '{username}'")
                log_security_event(
                    action="USER_LOGIN_FAILED",
                    resource_type="USER",
                    username=username,
                    status="FAILED",
                    details='{"reason": "user_not_found"}',
                )
                flash("Invalid credentials provided.", "error")
                return render_template("auth/login.html")

            # Check if user account is deactivated
            if not user.is_active:
                logger.warning(f"Login attempt blocked: Account '{username}' is disabled.")
                log_security_event(
                    action="USER_LOGIN_BLOCKED",
                    resource_type="USER",
                    user_id=user.id,
                    username=user.username,
                    status="BLOCKED",
                    details='{"reason": "account_deactivated"}',
                )
                flash("This account has been deactivated by an administrator.", "error")
                return render_template("auth/login.html")

            # Check account lockout status
            if is_account_locked(user):
                logger.warning(f"Login attempt blocked: Account '{username}' is currently locked.")
                log_security_event(
                    action="USER_LOGIN_LOCKED",
                    resource_type="USER",
                    user_id=user.id,
                    username=user.username,
                    status="LOCKED",
                    details=f'{{"locked_until": "{user.locked_until}"}}',
                )
                flash("Account is temporarily locked due to multiple failed attempts. Please try again later.", "error")
                return render_template("auth/login.html")

            # Verify password hash
            if not verify_password(user.password_hash, password):
                newly_locked = record_failed_login(user, db_session)
                db_session.commit()

                log_security_event(
                    action="USER_LOGIN_FAILED",
                    resource_type="USER",
                    user_id=user.id,
                    username=user.username,
                    status="FAILED",
                    details=f'{{"failed_attempts": {user.failed_login_attempts}, "newly_locked": {newly_locked}}}',
                )

                if newly_locked:
                    flash("Account locked for 15 minutes due to 5 consecutive failed login attempts.", "error")
                else:
                    remaining = 5 - user.failed_login_attempts
                    flash(f"Invalid credentials. {remaining} attempt(s) remaining before temporary lockout.", "error")
                return render_template("auth/login.html")

            # Password verified: reset failure counters and record login telemetry
            reset_failed_login_attempts(user)
            user.last_login_at = datetime.now(UTC)
            user.last_login_ip = request.remote_addr
            db_session.commit()

            # If user has 2FA enabled, stage session and redirect to 2FA challenge
            if user.is_totp_enabled:
                session["pre_2fa_user_id"] = user.id
                session["is_2fa_verified"] = False
                logger.info(f"User '{username}' passed primary password authentication; prompting for 2FA TOTP.")
                return redirect(url_for("auth.login_2fa"))

            # Log the user into Flask-Login
            db_session.expunge(user)
            login_user(user, remember=False)
            session["is_2fa_verified"] = False

            log_security_event(
                action="USER_LOGIN_SUCCESS",
                resource_type="USER",
                user_id=user.id,
                username=user.username,
                status="SUCCESS",
                details='{"auth_method": "password_only"}',
            )

            # Enforce password change if flagged
            if user.must_change_password:
                flash("Initial password change required before accessing defensive controls.", "warning")
                return redirect(url_for("auth.change_password"))

            flash(f"Authenticated successfully as {user.username}.", "success")
            next_url = request.args.get("next") or url_for("dashboard.index")
            return redirect(next_url)

    return render_template("auth/login.html")


@auth_bp.route("/login/2fa", methods=["GET", "POST"])
def login_2fa():
    """Second-factor TOTP verification view."""
    user_id = session.get("pre_2fa_user_id")
    if not user_id:
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        code = request.form.get("code", "").strip()

        with get_db_session() as db_session:
            user = db_session.query(User).filter_by(id=user_id).first()
            if not user or not user.totp_secret:
                flash("2FA configuration error. Please sign in again.", "error")
                return redirect(url_for("auth.login"))

            if not verify_totp_code(user.totp_secret, code):
                logger.warning(f"2FA verification failed for user '{user.username}' with code '{code}'")
                log_security_event(
                    action="2FA_VERIFICATION_FAILED",
                    resource_type="USER",
                    user_id=user.id,
                    username=user.username,
                    status="FAILED",
                )
                flash("Invalid two-factor authentication code. Please check your authenticator clock.", "error")
                return render_template("auth/login_2fa.html")

            # TOTP code valid: log user in and set session flag
            session.pop("pre_2fa_user_id", None)
            session["is_2fa_verified"] = True
            db_session.expunge(user)
            login_user(user, remember=False)

            log_security_event(
                action="USER_LOGIN_SUCCESS",
                resource_type="USER",
                user_id=user.id,
                username=user.username,
                status="SUCCESS",
                details='{"auth_method": "password_and_2fa"}',
            )

            if user.must_change_password:
                flash("Initial password change required before accessing defensive controls.", "warning")
                return redirect(url_for("auth.change_password"))

            flash(f"Two-factor authentication verified for {user.username}.", "success")
            return redirect(url_for("dashboard.index"))

    return render_template("auth/login_2fa.html")


@auth_bp.route("/logout")
def logout():
    """Sign out user, revoke session, and clear cookies."""
    if current_user.is_authenticated:
        log_security_event(
            action="USER_LOGOUT",
            resource_type="USER",
            user_id=current_user.id,
            username=current_user.username,
            status="SUCCESS",
        )
        logout_user()
    session.clear()
    flash("You have been signed out.", "info")
    return redirect(url_for("auth.login"))


@auth_bp.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    """Change account password with strict complexity verification."""
    if request.method == "POST":
        current_pwd = request.form.get("current_password", "")
        new_pwd = request.form.get("new_password", "")
        confirm_pwd = request.form.get("confirm_password", "")

        if not current_pwd or not new_pwd or not confirm_pwd:
            flash("All password fields are required.", "error")
            return render_template("auth/change_password.html")

        if new_pwd != confirm_pwd:
            flash("New password and confirmation do not match.", "error")
            return render_template("auth/change_password.html")

        with get_db_session() as db_session:
            user = db_session.query(User).filter_by(id=current_user.id).first()

            if not verify_password(user.password_hash, current_pwd):
                flash("Current password provided is incorrect.", "error")
                return render_template("auth/change_password.html")

            # Validate password complexity
            is_valid, errors = validate_password_complexity(new_pwd)
            if not is_valid:
                for err in errors:
                    flash(err, "error")
                return render_template("auth/change_password.html")

            # Update password hash and clear temporary flag
            user.password_hash = hash_password(new_pwd)
            user.must_change_password = False
            db_session.commit()

            log_security_event(
                action="PASSWORD_CHANGED",
                resource_type="USER",
                user_id=user.id,
                username=user.username,
                status="SUCCESS",
            )

            flash("Password updated successfully.", "success")
            return redirect(url_for("dashboard.index"))

    return render_template("auth/change_password.html")


@auth_bp.route("/setup-2fa", methods=["GET", "POST"])
@login_required
def setup_2fa():
    """Configure and activate TOTP two-factor authentication."""
    if request.method == "POST":
        submitted_secret = request.form.get("secret", "").strip()
        code = request.form.get("code", "").strip()

        if not verify_totp_code(submitted_secret, code):
            flash("Verification code invalid. 2FA was not activated.", "error")
            return redirect(url_for("auth.setup_2fa"))

        with get_db_session() as db_session:
            user = db_session.query(User).filter_by(id=current_user.id).first()
            user.totp_secret = submitted_secret
            user.is_totp_enabled = True
            db_session.commit()

            session["is_2fa_verified"] = True

            log_security_event(
                action="2FA_ENABLED",
                resource_type="USER",
                user_id=user.id,
                username=user.username,
                status="SUCCESS",
            )

            flash("Two-Factor Authentication is now active on your account.", "success")
            return redirect(url_for("dashboard.index"))

    # Generate new temporary secret and QR code for enrollment
    secret = generate_totp_secret()
    uri = get_totp_uri(secret, current_user.username)
    qr_data = generate_qr_code_svg(uri)

    return render_template("auth/setup_2fa.html", secret=secret, qr_code_data=qr_data)

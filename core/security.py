"""AI-IDS/IPS Security & Authentication Core.

Implements Argon2id password hashing, strict password policy verification,
account lockout logic, RFC 6238 TOTP two-factor authentication, and
backend-enforced Role-Based Access Control (RBAC) decorators.
"""

from __future__ import annotations

import io
import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from functools import wraps
from typing import Any

import pyotp
import qrcode
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask import flash, redirect, request, session, url_for
from flask_login import current_user

from core.config import settings
from core.db import get_db_session
from core.logging import get_logger
from core.models.audit import GENESIS_HASH, AuditLog
from core.models.user import User, UserRole

logger = get_logger(__name__)

# Argon2id password hasher configured for high cryptographic resistance
# time_cost=3 iterations, memory_cost=65536 KiB (64MB), parallelism=4 threads
hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
)

MAX_FAILED_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15


# ---------------------------------------------------------------------------
# Password Validation & Hashing
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    """Hash a plaintext password using Argon2id."""
    return hasher.hash(password)


def verify_password(hashed: str, plaintext: str) -> bool:
    """Verify plaintext password against an Argon2id hash."""
    try:
        return hasher.verify(hashed, plaintext)
    except (VerifyMismatchError, ValueError, TypeError):
        return False


def validate_password_complexity(password: str) -> tuple[bool, list[str]]:
    """Validate that password meets enterprise security standards.

    Rules:
    - Minimum 12 characters
    - At least one uppercase letter [A-Z]
    - At least one lowercase letter [a-z]
    - At least one digit [0-9]
    - At least one special symbol [!@#$%^&*()_+\\-=\\[\\]{};':"\\\\|,.<>\\/?]
    """
    errors = []
    if len(password) < 12:
        errors.append("Password must be at least 12 characters long.")
    if not re.search(r"[A-Z]", password):
        errors.append("Password must contain at least one uppercase letter.")
    if not re.search(r"[a-z]", password):
        errors.append("Password must contain at least one lowercase letter.")
    if not re.search(r"[0-9]", password):
        errors.append("Password must contain at least one number.")
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password):
        errors.append("Password must contain at least one special character.")
    return (len(errors) == 0, errors)


# ---------------------------------------------------------------------------
# Account Lockout Management
# ---------------------------------------------------------------------------

def is_account_locked(user: User) -> bool:
    """Check if the user account is currently locked due to failed attempts."""
    if user.locked_until:
        if user.locked_until.tzinfo is None:
            locked_until_utc = user.locked_until.replace(tzinfo=UTC)
        else:
            locked_until_utc = user.locked_until.astimezone(UTC)
            
        if datetime.now(UTC) < locked_until_utc:
            return True
    return False


def record_failed_login(user: User, db_session) -> bool:
    """Increment failed login attempts and lock account if threshold is met.

    Returns True if the account was newly locked.
    """
    user.failed_login_attempts += 1
    newly_locked = False

    if user.failed_login_attempts >= MAX_FAILED_LOGIN_ATTEMPTS:
        user.locked_until = datetime.now(UTC) + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
        newly_locked = True
        logger.warning(
            f"Account locked: User '{user.username}' reached {user.failed_login_attempts} failed attempts. "
            f"Locked until {user.locked_until.isoformat()}"
        )
    return newly_locked


def reset_failed_login_attempts(user: User) -> None:
    """Reset failed login attempts and clear lockout after successful login."""
    user.failed_login_attempts = 0
    user.locked_until = None


# ---------------------------------------------------------------------------
# Two-Factor Authentication (TOTP - RFC 6238)
# ---------------------------------------------------------------------------

def generate_totp_secret() -> str:
    """Generate a base32 encoded random secret key for TOTP."""
    return pyotp.random_base32()


def get_totp_uri(secret: str, username: str) -> str:
    """Generate provisioning URI for authenticator applications."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name="AI-IDS-IPS-SOC")


def generate_qr_code_svg(uri: str) -> str:
    """Generate an SVG or PNG QR code as a data URI for authenticator setup."""
    qr = qrcode.QRCode(
        version=1,
        box_size=8,
        border=2,
    )
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    import base64
    b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/png;base64,{b64}"


def verify_totp_code(secret: str, code: str) -> bool:
    """Verify 6-digit TOTP code allowing +/- 1 time step (30 seconds) tolerance."""
    if not secret or not code or not code.isdigit() or len(code) != 6:
        return False
    totp = pyotp.TOTP(secret)
    return totp.verify(code.strip(), valid_window=1)


# ---------------------------------------------------------------------------
# Audit Trail Helper
# ---------------------------------------------------------------------------

def log_security_event(
    action: str,
    resource_type: str,
    resource_id: str | None = None,
    user_id: int | None = None,
    username: str = "system",
    status: str = "SUCCESS",
    details: str | None = None,
    ip_address: str | None = None,
    correlation_id: str | None = None,
) -> None:
    """Synchronously record an event in the tamper-evident hash-chained audit ledger."""
    with get_db_session() as db_session:
        # Retrieve the latest audit log entry to extract previous hash
        latest_entry = (
            db_session.query(AuditLog)
            .order_by(AuditLog.id.desc())
            .first()
        )
        prev_hash = latest_entry.entry_hash if latest_entry else GENESIS_HASH

        audit_entry = AuditLog.create_entry(
            hmac_key=settings.AUDIT_HMAC_SECRET,
            prev_hash=prev_hash,
            user_id=user_id,
            username=username,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            status=status,
            details=details,
            ip_address=ip_address or request.remote_addr if request else None,
            correlation_id=correlation_id,
        )
        db_session.add(audit_entry)


# ---------------------------------------------------------------------------
# Role-Based Access Control (RBAC) Decorators
# ---------------------------------------------------------------------------

def role_required(*allowed_roles: UserRole) -> Callable:
    """Enforce hierarchical or exact role authorization on backend endpoints.

    Admin has access to all roles; Analyst can access Analyst and Viewer roles;
    Viewer has read-only access.
    """
    def decorator(fn: Callable) -> Callable:
        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if not current_user.is_authenticated:
                if request.is_json or request.path.startswith("/api/"):
                    return {"error": "Authentication required", "status": 401}, 401
                return redirect(url_for("auth.login", next=request.path))

            # Role hierarchy check:
            # ADMIN > ANALYST > VIEWER
            user_role = current_user.role

            # If user is admin, allow everywhere
            if user_role == UserRole.ADMIN:
                return fn(*args, **kwargs)

            # If current role is directly in allowed_roles, allow
            if user_role in allowed_roles:
                return fn(*args, **kwargs)

            # If user is analyst and VIEWER is in allowed_roles, allow
            if user_role == UserRole.ANALYST and UserRole.VIEWER in allowed_roles:
                return fn(*args, **kwargs)

            logger.warning(
                f"Unauthorized access attempt: User '{current_user.username}' (Role: {user_role.value}) "
                f"attempted to access {request.method} {request.path}"
            )
            log_security_event(
                action="UNAUTHORIZED_ACCESS_ATTEMPT",
                resource_type="ENDPOINT",
                resource_id=request.path,
                user_id=current_user.id,
                username=current_user.username,
                status="DENIED",
                details=f'{{"required_roles": {[r.value for r in allowed_roles]}, "user_role": "{user_role.value}"}}',
            )

            if request.is_json or request.path.startswith("/api/"):
                return {"error": "Forbidden: Insufficient privileges", "status": 403}, 403

            flash("Access denied: You do not possess the required security role for this operation.", "error")
            return redirect(url_for("dashboard.index"))

        return wrapper
    return decorator


def require_password_change(fn: Callable) -> Callable:
    """Redirect users flagged with must_change_password to the password change view."""
    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        if current_user.is_authenticated and current_user.must_change_password:
            # Allow access only to change_password and logout routes
            allowed_endpoints = {"auth.change_password", "auth.logout", "static"}
            if request.endpoint not in allowed_endpoints:
                flash("Initial password change is required before proceeding.", "warning")
                return redirect(url_for("auth.change_password"))
        return fn(*args, **kwargs)
    return wrapper


def require_2fa_verification(fn: Callable) -> Callable:
    """Ensure user who has 2FA enabled has verified the TOTP token for this session."""
    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        if current_user.is_authenticated and current_user.is_totp_enabled and not session.get("is_2fa_verified", False):
            allowed_endpoints = {"auth.login_2fa", "auth.logout", "static"}
            if request.endpoint not in allowed_endpoints:
                flash("Two-Factor Authentication verification required.", "warning")
                return redirect(url_for("auth.login_2fa"))
        return fn(*args, **kwargs)
    return wrapper

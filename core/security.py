"""AI-IDS/IPS Security & Authentication Core.

Implements Argon2id password hashing with parameter migration, strict password
policy and history checks, account lockout, encrypted RFC 6238 TOTP with replay
protection, one-time recovery codes, server-side session lifecycle management,
tamper-evident audit logging, and default-deny Role-Based Access Control.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import re
import secrets
import threading
import time
from collections.abc import Callable
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from functools import wraps
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import pyotp
import qrcode
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from flask import (
    flash,
    has_request_context,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import current_user, logout_user
from sqlalchemy import select, text

from core.config import settings
from core.crypto import decrypt_secret, encrypt_secret
from core.db import get_db_session
from core.logging import get_correlation_id, get_logger
from core.models.audit import GENESIS_HASH, AuditLog
from core.models.user import (
    PasswordHistory,
    RecoveryCode,
    User,
    UserRole,
    UserSession,
)
from core.rbac import Permission, has_permission

logger = get_logger(__name__)

# Argon2id parameters are explicit and configurable so they can be raised over
# time; existing hashes are transparently re-hashed after a successful login.
hasher = PasswordHasher(
    time_cost=settings.ARGON2_TIME_COST,
    memory_cost=settings.ARGON2_MEMORY_COST,
    parallelism=settings.ARGON2_PARALLELISM,
    hash_len=settings.ARGON2_HASH_LEN,
    salt_len=settings.ARGON2_SALT_LEN,
)

# A real Argon2id hash of a random value. Unknown-user login attempts verify
# against this so response timing does not reveal whether an account exists.
DUMMY_PASSWORD_HASH = hasher.hash(secrets.token_urlsafe(32))

MAX_FAILED_LOGIN_ATTEMPTS = settings.LOGIN_MAX_ATTEMPTS
LOCKOUT_DURATION_MINUTES = settings.LOGIN_LOCKOUT_MINUTES
GENERIC_AUTH_ERROR = "Invalid credentials. Please verify your username and password."
GENERIC_2FA_ERROR = "Invalid verification code. Please try again."

_RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_AUDIT_LOCK = threading.Lock()

_COMMON_PASSWORDS_PATH = (
    Path(__file__).resolve().parent / "data" / "common_passwords.txt"
)


def _load_common_passwords() -> frozenset[str]:
    """Load the local common-password denylist, normalising for comparison."""
    try:
        raw = _COMMON_PASSWORDS_PATH.read_text(encoding="utf-8").splitlines()
    except OSError:
        logger.warning("Common-password denylist is missing; using minimal fallback")
        raw = [
            "password",
            "password1",
            "password123",
            "admin",
            "administrator",
            "letmein",
            "qwerty",
            "welcome",
            "changeme",
            "123456",
            "12345678",
        ]
    return frozenset(
        line.strip().lower()
        for line in raw
        if line.strip() and not line.lstrip().startswith("#")
    )


COMMON_PASSWORDS = _load_common_passwords()


# ---------------------------------------------------------------------------
# Password Validation, Hashing & History
# ---------------------------------------------------------------------------


def hash_password(password: str) -> str:
    """Hash a plaintext password using the configured Argon2id parameters."""
    return hasher.hash(password)


def verify_password(hashed: str, plaintext: str) -> bool:
    """Constant-time Argon2id verification that never raises for bad hashes."""
    if not hashed or not isinstance(plaintext, str):
        return False
    try:
        return hasher.verify(hashed, plaintext)
    except (VerificationError, InvalidHashError, ValueError, TypeError):
        return False


def dummy_verify_password(plaintext: str) -> bool:
    """Perform a disposable Argon2id comparison for unknown users."""
    verify_password(DUMMY_PASSWORD_HASH, plaintext)
    return False


def password_needs_rehash(hashed: str) -> bool:
    """Return True when a stored hash predates the configured parameters."""
    if not hashed:
        return True
    try:
        return hasher.check_needs_rehash(hashed)
    except (InvalidHashError, ValueError, TypeError):
        return True


def rehash_password_if_needed(user: User, plaintext: str) -> bool:
    """Upgrade a user's password hash when Argon2 parameters changed."""
    if not password_needs_rehash(user.password_hash):
        return False
    user.password_hash = hash_password(plaintext)
    logger.info(
        "Re-hashed password for user '%s' using current Argon2id parameters",
        user.username,
    )
    return True


def _normalise_password(value: str) -> str:
    """Normalise a candidate password for denylist comparison."""
    return re.sub(r"[^a-z0-9]", "", value.lower())


def validate_password_complexity(password: str) -> tuple[bool, list[str]]:
    """Validate baseline enterprise complexity rules."""
    errors: list[str] = []
    if len(password) < settings.PASSWORD_MIN_LENGTH:
        errors.append(
            f"Password must be at least {settings.PASSWORD_MIN_LENGTH} characters long."
        )
    if not re.search(r"[A-Z]", password):
        errors.append("Password must contain at least one uppercase letter.")
    if not re.search(r"[a-z]", password):
        errors.append("Password must contain at least one lowercase letter.")
    if not re.search(r"[0-9]", password):
        errors.append("Password must contain at least one number.")
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password):
        errors.append("Password must contain at least one special character.")
    return (len(errors) == 0, errors)


def validate_password_policy(
    password: str,
    username: str | None = None,
    email: str | None = None,
    history_hashes: list[str] | None = None,
) -> tuple[bool, list[str]]:
    """Validate complexity, common-password, identity, and reuse rules.

    ``history_hashes`` should contain the previous Argon2id hashes (current
    password is checked separately by :func:`is_password_reused`).
    """
    _valid, errors = validate_password_complexity(password)

    normalised = _normalise_password(password)
    if password.strip().lower() in COMMON_PASSWORDS or normalised in COMMON_PASSWORDS:
        errors.append("Password is too common and has been seen in breach corpora.")

    if (
        username
        and len(username.strip()) >= 3
        and username.strip().lower() in password.lower()
    ):
        errors.append("Password must not contain your username.")

    if email:
        lowered_password = password.lower()
        lowered_email = email.strip().lower()
        local_part = lowered_email.split("@", 1)[0]
        if (lowered_email and lowered_email in lowered_password) or (
            len(local_part) >= 3 and local_part in lowered_password
        ):
            errors.append("Password must not contain your email address.")

    for previous_hash in history_hashes or []:
        if verify_password(previous_hash, password):
            errors.append(
                f"Password must not match any of your last "
                f"{settings.PASSWORD_HISTORY_DEPTH} passwords."
            )
            break

    return (len(errors) == 0, errors)


def is_password_reused(user: User, new_password: str, db_session) -> bool:
    """Return True when the candidate matches the current or recent password."""
    if verify_password(user.password_hash, new_password):
        return True
    history = (
        db_session.query(PasswordHistory)
        .filter_by(user_id=user.id)
        .order_by(PasswordHistory.created_at.desc())
        .limit(settings.PASSWORD_HISTORY_DEPTH)
        .all()
    )
    return any(verify_password(entry.password_hash, new_password) for entry in history)


def record_password_history(
    user: User, previous_hash: str, db_session, keep: int | None = None
) -> None:
    """Record a previous hash and prune history beyond the configured depth."""
    retain = keep or settings.PASSWORD_HISTORY_DEPTH
    if user.id is None:
        db_session.flush()
    db_session.add(PasswordHistory(user_id=user.id, password_hash=previous_hash))
    db_session.flush()
    entries = (
        db_session.query(PasswordHistory)
        .filter_by(user_id=user.id)
        .order_by(PasswordHistory.created_at.desc())
        .all()
    )
    for stale in entries[retain:]:
        db_session.delete(stale)
    if len(entries) > retain:
        db_session.flush()


# ---------------------------------------------------------------------------
# Account Lockout Management
# ---------------------------------------------------------------------------


def _as_utc(value: datetime | None) -> datetime | None:
    """Normalise SQLite's naive datetimes to timezone-aware UTC values."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def is_account_locked(user: User) -> bool:
    """Check whether the account is currently inside a lockout window."""
    locked_until = _as_utc(user.locked_until)
    return bool(locked_until and datetime.now(UTC) < locked_until)


def clear_expired_lockout(user: User) -> bool:
    """Reset counters if a lockout has expired. Returns True when it expired."""
    locked_until = _as_utc(user.locked_until)
    if locked_until and datetime.now(UTC) >= locked_until:
        user.failed_login_attempts = 0
        user.locked_until = None
        return True
    return False


def record_failed_login(user: User, db_session) -> bool:
    """Increment failed attempts and lock the account at the threshold.

    Returns True if the account was newly locked.
    """
    del db_session  # retained for API symmetry / future per-account throttling
    user.failed_login_attempts += 1
    newly_locked = False
    if user.failed_login_attempts >= MAX_FAILED_LOGIN_ATTEMPTS:
        user.locked_until = datetime.now(UTC) + timedelta(
            minutes=LOCKOUT_DURATION_MINUTES
        )
        newly_locked = True
        logger.warning(
            "Account locked: user=%s attempts=%s until=%s",
            user.username,
            user.failed_login_attempts,
            user.locked_until.isoformat(),
        )
    return newly_locked


def reset_failed_login_attempts(user: User) -> None:
    """Reset failed login attempts and clear any lockout."""
    user.failed_login_attempts = 0
    user.locked_until = None


# ---------------------------------------------------------------------------
# Two-Factor Authentication (TOTP - RFC 6238)
# ---------------------------------------------------------------------------


def generate_totp_secret() -> str:
    """Generate a base32-encoded random TOTP shared secret."""
    return pyotp.random_base32()


def get_totp_uri(secret: str, username: str) -> str:
    """Generate an otpauth provisioning URI for authenticator applications."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=settings.TOTP_ISSUER)


def generate_qr_code_svg(uri: str) -> str:
    """Generate a PNG QR code rendered as a data URI."""
    qr = qrcode.QRCode(version=1, box_size=8, border=2)
    qr.add_data(uri)
    qr.make(fit=True)
    image = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    import base64

    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def verify_totp_code(secret: str, code: str, valid_window: int | None = None) -> bool:
    """Verify a six-digit TOTP code without replay tracking."""
    matched, _ = verify_totp_code_with_step(
        secret, code, last_step=None, valid_window=valid_window
    )
    return matched


def verify_totp_code_with_step(
    secret: str,
    code: str,
    last_step: int | None = None,
    valid_window: int | None = None,
    at_time: float | None = None,
) -> tuple[bool, int | None]:
    """Verify a TOTP code and return the matched 30-second time step.

    A step less than or equal to ``last_step`` is rejected to prevent replay of
    a previously accepted code.
    """
    if not secret or not code:
        return False, None
    cleaned = code.strip().replace(" ", "")
    if not cleaned.isdigit() or len(cleaned) != 6:
        return False, None

    window = settings.TOTP_VALID_WINDOW if valid_window is None else valid_window
    now = time.time() if at_time is None else at_time
    current_step = int(now // 30)

    for offset in range(-window, window + 1):
        step = current_step + offset
        if step < 0:
            continue
        try:
            candidate = pyotp.TOTP(secret).at(step * 30)
        except (ValueError, TypeError):
            return False, None
        if hmac.compare_digest(candidate, cleaned):
            if last_step is not None and step <= last_step:
                return False, None
            return True, step
    return False, None


def encrypt_totp_secret(secret: str) -> str:
    """Encrypt a TOTP shared secret using the Phase 1 AES-256-GCM envelope."""
    return encrypt_secret(secret)


def decrypt_totp_secret(token: str) -> str:
    """Decrypt a TOTP shared secret, raising CryptoError on tamper."""
    return decrypt_secret(token)


# ---------------------------------------------------------------------------
# One-Time Recovery Codes
# ---------------------------------------------------------------------------


def _normalise_recovery_code(code: str) -> str:
    """Strip separators and normalise case for recovery-code comparison."""
    return re.sub(r"[^A-Za-z0-9]", "", code).upper()


def generate_recovery_code() -> str:
    """Generate a high-entropy, human-transcribable recovery code."""
    raw = "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(10))
    return f"{raw[:5]}-{raw[5:]}"


def generate_recovery_codes(count: int | None = None) -> list[str]:
    """Generate distinct plaintext recovery codes for one-time display."""
    total = count or settings.RECOVERY_CODE_COUNT
    return [generate_recovery_code() for _ in range(total)]


def hash_recovery_code(code: str) -> str:
    """Hash a recovery code with Argon2id before persistence."""
    return hash_password(_normalise_recovery_code(code))


def issue_recovery_codes(user: User, db_session, count: int | None = None) -> list[str]:
    """Replace all existing recovery codes and return the new plaintext set."""
    if user.id is None:
        db_session.flush()
    # Delete through the ORM so the identity map is updated before new rows are
    # inserted; a bulk delete can leave stale objects that collide on reused
    # primary keys and emit identity-map warnings.
    for existing in db_session.query(RecoveryCode).filter_by(user_id=user.id).all():
        db_session.delete(existing)
    db_session.flush()
    plaintext_codes = generate_recovery_codes(count)
    for code in plaintext_codes:
        db_session.add(
            RecoveryCode(user_id=user.id, code_hash=hash_recovery_code(code))
        )
    db_session.flush()
    return plaintext_codes


def verify_recovery_code(
    user: User, code: str, db_session, ip_address: str | None = None
) -> bool:
    """Consume a valid, unused recovery code. Codes are single-use."""
    normalised = _normalise_recovery_code(code)
    if len(normalised) < 8:
        return False
    unused = (
        db_session.query(RecoveryCode)
        .filter_by(user_id=user.id)
        .filter(RecoveryCode.used_at.is_(None))
        .all()
    )
    for candidate in unused:
        if verify_password(candidate.code_hash, normalised):
            candidate.used_at = datetime.now(UTC)
            candidate.used_ip = ip_address
            # Sessions are configured with ``autoflush=False``; flush so a second
            # lookup in the same transaction cannot reuse the consumed code.
            db_session.flush()
            return True
    return False


# ---------------------------------------------------------------------------
# Server-side Session Lifecycle
# ---------------------------------------------------------------------------


def hash_session_token(token: str) -> str:
    """Return a keyed digest for a high-entropy session token."""
    return hmac.new(
        settings.APP_SECRET_KEY.encode("utf-8"),
        token.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def create_user_session(
    user: User,
    db_session,
    absolute_hours: int | None = None,
) -> str:
    """Create a server-side session and return the raw cookie token."""
    now = datetime.now(UTC)
    token = secrets.token_urlsafe(32)
    ip_address = (request.remote_addr if has_request_context() else None) or "unknown"
    user_agent = None
    if has_request_context():
        user_agent = (request.user_agent.string or "")[:255] or None

    db_session.add(
        UserSession(
            session_token=hash_session_token(token),
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            expires_at=now
            + timedelta(
                hours=absolute_hours or settings.SESSION_ABSOLUTE_TIMEOUT_HOURS
            ),
            last_activity_at=now,
        )
    )
    db_session.flush()
    return token


def get_session_by_token(token: str, db_session) -> UserSession | None:
    """Look up a session by its raw token without mutating it."""
    return (
        db_session.query(UserSession)
        .filter_by(session_token=hash_session_token(token))
        .first()
    )


def validate_user_session(token: str, db_session) -> UserSession | None:
    """Validate absolute/idle timeouts and refresh last activity.

    Returns the live session, or ``None`` after revoking an expired session.
    """
    record = get_session_by_token(token, db_session)
    if record is None or record.is_revoked:
        return None

    now = datetime.now(UTC)
    expires_at = _as_utc(record.expires_at)
    last_activity = _as_utc(record.last_activity_at) or now

    if expires_at is None or now >= expires_at:
        record.is_revoked = True
        record.revoked_at = now
        record.revoke_reason = "absolute_timeout"
        return None

    idle_deadline = last_activity + timedelta(
        minutes=settings.SESSION_IDLE_TIMEOUT_MINUTES
    )
    if now >= idle_deadline:
        record.is_revoked = True
        record.revoked_at = now
        record.revoke_reason = "idle_timeout"
        return None

    # Avoid a database write on every asset/request; one minute granularity is
    # sufficient for a 30-minute idle window.
    if (now - last_activity).total_seconds() >= 60:
        record.last_activity_at = now
    return record


def revoke_session(token: str, db_session, reason: str = "logout") -> bool:
    """Revoke a single server-side session by its raw token."""
    record = get_session_by_token(token, db_session)
    if record is None or record.is_revoked:
        return False
    record.is_revoked = True
    record.revoked_at = datetime.now(UTC)
    record.revoke_reason = reason[:64]
    return True


def revoke_all_user_sessions(
    user_id: int,
    db_session,
    reason: str,
    except_token: str | None = None,
) -> int:
    """Revoke every live session for a user, optionally preserving one token."""
    query = db_session.query(UserSession).filter(
        UserSession.user_id == user_id,
        UserSession.is_revoked.is_(False),
    )
    if except_token:
        query = query.filter(
            UserSession.session_token != hash_session_token(except_token)
        )
    now = datetime.now(UTC)
    return int(
        query.update(
            {
                UserSession.is_revoked: True,
                UserSession.revoked_at: now,
                UserSession.revoke_reason: reason[:64],
            },
            synchronize_session=False,
        )
    )


# ---------------------------------------------------------------------------
# Audit Trail
# ---------------------------------------------------------------------------


def _latest_audit_hash(db_session) -> str:
    """Return the current chain head while serialising concurrent appends."""
    if db_session.bind is not None and db_session.bind.dialect.name == "postgresql":
        db_session.execute(
            text("SELECT pg_advisory_xact_lock(hashtext('ai_ids_audit_chain'))")
        )
    latest = db_session.execute(
        select(AuditLog).order_by(AuditLog.id.desc()).limit(1).with_for_update()
    ).scalar_one_or_none()
    return latest.entry_hash if latest else GENESIS_HASH


def audit_details(**values: Any) -> str:
    """Serialize structured audit details with stable, escaped JSON."""
    return json.dumps(values, default=str, sort_keys=True)


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
    db_session=None,
) -> AuditLog:
    """Append a tamper-evident audit entry.

    When ``db_session`` is supplied the caller owns the transaction and must
    commit it; otherwise a short-lived transaction is committed here.
    """
    own_session = db_session is None
    context = get_db_session() if own_session else nullcontext(db_session)
    resolved_ip = ip_address
    if resolved_ip is None and has_request_context():
        resolved_ip = request.remote_addr
    resolved_cid = correlation_id or get_correlation_id()

    with context as active_session, _AUDIT_LOCK:
        entry = AuditLog.create_entry(
            hmac_key=settings.AUDIT_HMAC_SECRET,
            prev_hash=_latest_audit_hash(active_session),
            user_id=user_id,
            username=username,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            status=status,
            details=details,
            ip_address=resolved_ip,
            correlation_id=resolved_cid,
        )
        active_session.add(entry)
        active_session.flush()
    return entry


# ---------------------------------------------------------------------------
# Role-Based Access Control (RBAC) & Request Guards
# ---------------------------------------------------------------------------


def _wants_json_response() -> bool:
    """Return True for API/AJAX callers that expect JSON errors."""
    if request.path.startswith("/api/") or request.is_json:
        return True
    accept = request.accept_mimetypes
    # HTML wins ties (e.g. browsers sending ``*/*``); JSON requires an explicit
    # preference so ordinary form posts never receive JSON error bodies.
    return bool(accept["application/json"] > accept["text/html"])


def _unauthenticated_response():
    """Return 401 for unauthenticated callers (never leak role information)."""
    if _wants_json_response():
        return jsonify({"error": "authentication_required", "status": 401}), 401
    return render_template("errors/401.html"), 401


def _forbidden_response(action: str) -> Any:
    """Return 403 for authenticated callers lacking permission."""
    logger.warning(
        "Unauthorized access attempt: user=%s role=%s method=%s path=%s",
        getattr(current_user, "username", "anonymous"),
        getattr(getattr(current_user, "role", None), "value", "unknown"),
        request.method,
        request.path,
    )
    if current_user.is_authenticated:
        log_security_event(
            action="UNAUTHORIZED_ACCESS_ATTEMPT",
            resource_type="ENDPOINT",
            resource_id=request.path,
            user_id=current_user.id,
            username=current_user.username,
            status="DENIED",
            details=audit_details(
                required_action=action,
                method=request.method,
                path=request.path,
            ),
        )
    if _wants_json_response():
        return jsonify({"error": "forbidden", "status": 403}), 403
    return render_template("errors/403.html"), 403


def role_required(*allowed_roles: UserRole) -> Callable:
    """Enforce exact role membership. Unlisted roles are denied by default."""

    def decorator(fn: Callable) -> Callable:
        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if not current_user.is_authenticated:
                return _unauthenticated_response()
            if current_user.role not in allowed_roles:
                return _forbidden_response(
                    "roles:" + ",".join(role.value for role in allowed_roles)
                )
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def permission_required(permission: Permission) -> Callable:
    """Enforce an explicit permission from the documented role matrix."""

    def decorator(fn: Callable) -> Callable:
        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if not current_user.is_authenticated:
                return _unauthenticated_response()
            if not has_permission(current_user.role, permission):
                return _forbidden_response(permission.value)
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def require_password_change(fn: Callable) -> Callable:
    """Redirect users flagged with must_change_password to the password view."""
    allowed_endpoints = {
        "auth.change_password",
        "auth.logout",
        "static",
        "health.liveness",
        "health.readiness",
    }

    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        if (
            current_user.is_authenticated
            and current_user.must_change_password
            and request.endpoint not in allowed_endpoints
        ):
            flash("Initial password change is required before proceeding.", "warning")
            if request.path.startswith("/api/") or request.is_json:
                return (
                    jsonify({"error": "password_change_required", "status": 403}),
                    403,
                )
            return redirect(url_for("auth.change_password"))
        return fn(*args, **kwargs)

    return wrapper


def require_2fa_verification(fn: Callable) -> Callable:
    """Require a verified second factor for users with TOTP enabled."""
    allowed_endpoints = {
        "auth.login_2fa",
        "auth.logout",
        "static",
        "health.liveness",
        "health.readiness",
    }

    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        if (
            current_user.is_authenticated
            and current_user.is_totp_enabled
            and not session.get("is_2fa_verified", False)
            and request.endpoint not in allowed_endpoints
        ):
            logout_user()
            session.clear()
            flash("Two-Factor Authentication verification required.", "warning")
            return redirect(url_for("auth.login"))
        return fn(*args, **kwargs)

    return wrapper


def is_safe_next_url(target: str | None) -> bool:
    """Validate a post-login redirect target against the current host."""
    if not target:
        return False
    cleaned = target.strip()
    if not cleaned or cleaned.startswith("//") or "\\" in cleaned:
        return False
    if any(ord(char) < 32 for char in cleaned):
        return False

    parsed = urlparse(cleaned)
    if not parsed.scheme and not parsed.netloc:
        return parsed.path.startswith("/")
    if parsed.scheme not in {"http", "https"}:
        return False
    if not has_request_context():
        return False
    return parsed.netloc == request.host


def safe_next_url(
    target: str | None, fallback_endpoint: str = "dashboard.index"
) -> str:
    """Return a validated redirect target or the safe fallback URL."""
    if is_safe_next_url(target):
        return target  # type: ignore[return-value]
    try:
        return url_for(fallback_endpoint)
    except RuntimeError:
        # Utility callers (e.g. unit tests) may run without an app context.
        return "/dashboard"


def get_client_ip() -> str | None:
    """Return the trusted client address after ProxyFix processing."""
    if has_request_context():
        return request.remote_addr
    return None

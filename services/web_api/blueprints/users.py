"""User Administration & Access Control Blueprint.

All routes require the ``users:manage`` permission. Destructive actions guard
the last active administrator, revoke server-side sessions, validate input with
Pydantic, and write actor/target/correlation-aware audit entries.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user
from pydantic import ValidationError

from core.config import settings
from core.db import get_db_session
from core.logging import get_logger
from core.models.user import RecoveryCode, User, UserRole
from core.rbac import Permission
from core.schemas import RoleUpdate, UserCreate
from core.security import (
    audit_details,
    hash_password,
    log_security_event,
    permission_required,
    record_password_history,
    reset_failed_login_attempts,
    revoke_all_user_sessions,
    validate_password_policy,
)

logger = get_logger(__name__)

users_bp = Blueprint("users", __name__, url_prefix="/users")


def _user_view(user: User, now: datetime) -> dict[str, object]:
    """Return only non-sensitive fields for template rendering."""
    locked_until = user.locked_until
    if locked_until is not None and locked_until.tzinfo is None:
        locked_until = locked_until.replace(tzinfo=UTC)
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "is_active": user.is_active,
        "is_totp_enabled": user.is_totp_enabled,
        "failed_login_attempts": user.failed_login_attempts,
        "locked": bool(locked_until and locked_until > now),
        "locked_until": locked_until,
        "must_change_password": user.must_change_password,
    }


def _active_admin_count(db_session, exclude_user_id: int | None = None) -> int:
    """Count currently active administrators, optionally excluding one user."""
    query = db_session.query(User).filter(
        User.role == UserRole.ADMIN, User.is_active.is_(True)
    )
    if exclude_user_id is not None:
        query = query.filter(User.id != exclude_user_id)
    return int(query.count())


def _is_last_active_admin(db_session, user: User) -> bool:
    """Return True when removing this user would leave zero active admins."""
    if user.role != UserRole.ADMIN or not user.is_active:
        return False
    return _active_admin_count(db_session, exclude_user_id=user.id) == 0


def _audit(
    action: str,
    actor: User,
    target: User | None,
    db_session,
    status: str = "SUCCESS",
    **details,
) -> None:
    """Write a privileged-action audit entry with actor and target context."""
    log_security_event(
        action=action,
        resource_type="USER",
        resource_id=str(target.id) if target else None,
        user_id=actor.id,
        username=actor.username,
        status=status,
        details=audit_details(
            actor=actor.username,
            target=target.username if target else None,
            **details,
        ),
        db_session=db_session,
    )


def _validation_messages(exc: ValidationError) -> list[str]:
    """Convert Pydantic validation errors into operator-friendly messages."""
    messages: list[str] = []
    for error in exc.errors():
        location = ".".join(str(part) for part in error["loc"])
        message = error["msg"]
        messages.append(f"{location}: {message}" if location else message)
    return messages


def _redirect() -> object:
    return redirect(url_for("users.index"))


@users_bp.route("")
@permission_required(Permission.USERS_MANAGE)
def index():
    """List all console users using safe, non-sensitive view fields."""
    with get_db_session() as db_session:
        users = db_session.query(User).order_by(User.id.asc()).all()
        now = datetime.now(UTC)
        return render_template(
            "users/index.html",
            users=[_user_view(user, now) for user in users],
            roles=list(UserRole),
        )


@users_bp.route("/create", methods=["POST"])
@permission_required(Permission.USERS_MANAGE)
def create_user():
    """Provision a user with an explicit field allow-list (no mass assignment)."""
    try:
        payload = UserCreate(
            username=request.form.get("username", ""),
            email=request.form.get("email", ""),
            role=request.form.get("role", "viewer"),
            password=request.form.get("password", ""),
        )
    except ValidationError as exc:
        for message in _validation_messages(exc):
            flash(message, "error")
        return _redirect()

    is_valid, errors = validate_password_policy(
        payload.password, username=payload.username, email=payload.email
    )
    if not is_valid:
        for error in errors:
            flash(error, "error")
        return _redirect()

    with get_db_session() as db_session:
        if db_session.query(User).filter_by(username=payload.username).first():
            flash(f"Username '{payload.username}' already exists.", "error")
            return _redirect()
        if db_session.query(User).filter_by(email=payload.email).first():
            flash(f"Email '{payload.email}' is already registered.", "error")
            return _redirect()

        new_user = User(
            username=payload.username,
            email=payload.email,
            password_hash=hash_password(payload.password),
            role=payload.role,
            is_active=True,
            must_change_password=True,
        )
        db_session.add(new_user)
        db_session.flush()
        record_password_history(new_user, new_user.password_hash, db_session)

        _audit(
            "USER_CREATED",
            current_user,
            new_user,
            db_session,
            created_role=payload.role.value,
        )
        flash(
            f"User '{payload.username}' created successfully with role "
            f"'{payload.role.value}'. The user must change the password at first login.",
            "success",
        )
    return _redirect()


@users_bp.route("/<int:user_id>/role", methods=["POST"])
@permission_required(Permission.USERS_MANAGE)
def update_role(user_id: int):
    """Change a user's role while protecting the last active administrator."""
    try:
        raw_role = request.form.get("role", "")
        payload = RoleUpdate(role=UserRole(raw_role))
    except (ValidationError, ValueError) as exc:
        if isinstance(exc, ValidationError):
            messages = _validation_messages(exc)
        else:
            messages = ["Select a valid role."]
        for message in messages:
            flash(message, "error")
        return _redirect()

    with get_db_session() as db_session:
        target = db_session.query(User).filter_by(id=user_id).first()
        if target is None:
            flash("User not found.", "error")
            return _redirect()

        if (
            target.role == UserRole.ADMIN
            and payload.role != UserRole.ADMIN
            and _is_last_active_admin(db_session, target)
        ):
            _audit(
                "USER_ROLE_CHANGE_DENIED",
                current_user,
                target,
                db_session,
                status="DENIED",
                requested_role=payload.role.value,
                reason="last_active_admin",
            )
            flash("Cannot change the role of the last active administrator.", "error")
            return _redirect()

        previous_role = target.role
        target.role = payload.role
        revoked = revoke_all_user_sessions(target.id, db_session, "role_change")
        _audit(
            "USER_ROLE_CHANGED",
            current_user,
            target,
            db_session,
            previous_role=previous_role.value,
            new_role=payload.role.value,
            sessions_revoked=revoked,
        )
        flash(
            f"Role for '{target.username}' changed from '{previous_role.value}' "
            f"to '{payload.role.value}'.",
            "success",
        )
    return _redirect()


def _set_active(user_id: int, active: bool):
    """Shared activation/deactivation handler with last-admin protection."""
    with get_db_session() as db_session:
        target = db_session.query(User).filter_by(id=user_id).first()
        if target is None:
            flash("User not found.", "error")
            return _redirect()

        if not active:
            if target.id == current_user.id:
                flash("You cannot deactivate your own account.", "error")
                return _redirect()
            if _is_last_active_admin(db_session, target):
                _audit(
                    "USER_DEACTIVATION_DENIED",
                    current_user,
                    target,
                    db_session,
                    status="DENIED",
                    reason="last_active_admin",
                )
                flash("Cannot deactivate the last active administrator.", "error")
                return _redirect()

        if target.is_active == active:
            flash(
                f"User '{target.username}' is already in the requested state.", "info"
            )
            return _redirect()

        target.is_active = active
        revoked = 0
        if not active:
            revoked = revoke_all_user_sessions(target.id, db_session, "deactivated")
        _audit(
            "USER_ACTIVATED" if active else "USER_DEACTIVATED",
            current_user,
            target,
            db_session,
            is_active=active,
            sessions_revoked=revoked,
        )
        state = "activated" if active else "deactivated"
        flash(f"User '{target.username}' has been {state}.", "success")
    return _redirect()


@users_bp.route("/<int:user_id>/deactivate", methods=["POST"])
@permission_required(Permission.USERS_MANAGE)
def deactivate_user(user_id: int):
    """Deactivate an account and revoke all of its sessions."""
    return _set_active(user_id, False)


@users_bp.route("/<int:user_id>/activate", methods=["POST"])
@permission_required(Permission.USERS_MANAGE)
def activate_user(user_id: int):
    """Reactivate an account."""
    return _set_active(user_id, True)


@users_bp.route("/<int:user_id>/lock", methods=["POST"])
@permission_required(Permission.USERS_MANAGE)
def lock_user(user_id: int):
    """Administratively lock an account and revoke its sessions."""
    with get_db_session() as db_session:
        target = db_session.query(User).filter_by(id=user_id).first()
        if target is None:
            flash("User not found.", "error")
            return _redirect()
        if target.id == current_user.id:
            flash("You cannot lock your own account.", "error")
            return _redirect()
        if _is_last_active_admin(db_session, target):
            _audit(
                "USER_LOCK_DENIED",
                current_user,
                target,
                db_session,
                status="DENIED",
                reason="last_active_admin",
            )
            flash("Cannot lock the last active administrator.", "error")
            return _redirect()

        target.failed_login_attempts = settings.LOGIN_MAX_ATTEMPTS
        target.locked_until = datetime.now(UTC) + timedelta(
            minutes=settings.LOGIN_LOCKOUT_MINUTES
        )
        revoked = revoke_all_user_sessions(target.id, db_session, "admin_lockout")
        _audit(
            "USER_LOCKED",
            current_user,
            target,
            db_session,
            reason="admin_lockout",
            locked_until=target.locked_until.isoformat(),
            sessions_revoked=revoked,
        )
        flash(
            f"Account '{target.username}' locked until {target.locked_until}.",
            "success",
        )
    return _redirect()


@users_bp.route("/<int:user_id>/unlock", methods=["POST"])
@permission_required(Permission.USERS_MANAGE)
def unlock_user(user_id: int):
    """Administratively clear lockout counters."""
    with get_db_session() as db_session:
        target = db_session.query(User).filter_by(id=user_id).first()
        if target is None:
            flash("User not found.", "error")
            return _redirect()

        reset_failed_login_attempts(target)
        _audit("USER_UNLOCKED", current_user, target, db_session, reason="admin_unlock")
        flash(f"Account for '{target.username}' has been unlocked.", "success")
    return _redirect()


@users_bp.route("/<int:user_id>/reset-2fa", methods=["POST"])
@permission_required(Permission.USERS_MANAGE)
def reset_2fa(user_id: int):
    """Reset a user's TOTP secret and recovery codes, then revoke sessions."""
    with get_db_session() as db_session:
        target = db_session.query(User).filter_by(id=user_id).first()
        if target is None:
            flash("User not found.", "error")
            return _redirect()

        target.totp_secret = None
        target.is_totp_enabled = False
        target.totp_last_step = None
        db_session.query(RecoveryCode).filter_by(user_id=target.id).delete(
            synchronize_session=False
        )
        revoked = revoke_all_user_sessions(target.id, db_session, "admin_2fa_reset")
        _audit(
            "2FA_RESET",
            current_user,
            target,
            db_session,
            sessions_revoked=revoked,
        )
        flash(f"Two-factor authentication reset for '{target.username}'.", "success")
    return _redirect()


@users_bp.route("/<int:user_id>/force-password-change", methods=["POST"])
@permission_required(Permission.USERS_MANAGE)
def force_password_change(user_id: int):
    """Require a password change at the target user's next login."""
    with get_db_session() as db_session:
        target = db_session.query(User).filter_by(id=user_id).first()
        if target is None:
            flash("User not found.", "error")
            return _redirect()

        target.must_change_password = True
        revoked = revoke_all_user_sessions(
            target.id, db_session, "forced_password_change"
        )
        _audit(
            "PASSWORD_CHANGE_REQUIRED",
            current_user,
            target,
            db_session,
            sessions_revoked=revoked,
        )
        flash(
            f"'{target.username}' will be required to change the password at next login.",
            "success",
        )
    return _redirect()


@users_bp.route("/<int:user_id>/delete", methods=["POST"])
@permission_required(Permission.USERS_MANAGE)
def delete_user(user_id: int):
    """Delete a user, protecting the last active administrator."""
    with get_db_session() as db_session:
        target = db_session.query(User).filter_by(id=user_id).first()
        if target is None:
            flash("User not found.", "error")
            return _redirect()
        if target.id == current_user.id:
            flash("You cannot delete your own account.", "error")
            return _redirect()
        if _is_last_active_admin(db_session, target):
            _audit(
                "USER_DELETE_DENIED",
                current_user,
                target,
                db_session,
                status="DENIED",
                reason="last_active_admin",
            )
            flash("Cannot delete the last active administrator.", "error")
            return _redirect()

        target_name = target.username
        target_id = target.id
        revoke_all_user_sessions(target.id, db_session, "account_deleted")
        _audit("USER_DELETED", current_user, target, db_session)
        db_session.delete(target)
        flash(f"User '{target_name}' (ID {target_id}) has been deleted.", "success")
    return _redirect()

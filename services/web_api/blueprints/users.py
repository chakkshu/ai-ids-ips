"""User Administration & Access Control Blueprint.

Enforces Admin-only access to user management, account activation/locking,
and role assignment.
"""

from __future__ import annotations

from datetime import UTC, datetime

from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user

from core.db import get_db_session
from core.logging import get_logger
from core.models.user import User, UserRole
from core.security import (
    hash_password,
    log_security_event,
    role_required,
    validate_password_complexity,
)

logger = get_logger(__name__)

users_bp = Blueprint("users", __name__, url_prefix="/users")


@users_bp.route("")
@role_required(UserRole.ADMIN)
def index():
    """List all registered users with status and role indicators."""
    with get_db_session() as db_session:
        user_list = db_session.query(User).order_by(User.id.asc()).all()
        return render_template("users/index.html", users=user_list, now=datetime.now(UTC))


@users_bp.route("/create", methods=["POST"])
@role_required(UserRole.ADMIN)
def create_user():
    """Provision a new console user with initial temporary credentials."""
    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip()
    role_str = request.form.get("role", "viewer").strip().lower()
    temp_password = request.form.get("password", "")

    if not username or not email or not temp_password:
        flash("All fields are required to provision a user.", "error")
        return redirect(url_for("users.index"))

    # Validate role string
    try:
        role = UserRole(role_str)
    except ValueError:
        flash("Invalid security role specified.", "error")
        return redirect(url_for("users.index"))

    # Validate temporary password complexity
    is_valid, errors = validate_password_complexity(temp_password)
    if not is_valid:
        for err in errors:
            flash(err, "error")
        return redirect(url_for("users.index"))

    with get_db_session() as db_session:
        # Check uniqueness
        if db_session.query(User).filter_by(username=username).first():
            flash(f"Username '{username}' already exists.", "error")
            return redirect(url_for("users.index"))

        if db_session.query(User).filter_by(email=email).first():
            flash(f"Email '{email}' is already registered.", "error")
            return redirect(url_for("users.index"))

        new_user = User(
            username=username,
            email=email,
            password_hash=hash_password(temp_password),
            role=role,
            is_active=True,
            must_change_password=True,
        )
        db_session.add(new_user)
        db_session.flush()

        log_security_event(
            action="USER_CREATED",
            resource_type="USER",
            resource_id=str(new_user.id),
            user_id=current_user.id,
            username=current_user.username,
            status="SUCCESS",
            details=f'{{"created_user": "{username}", "role": "{role.value}"}}',
        )

        flash(f"User '{username}' created successfully with role '{role.value}'.", "success")
        return redirect(url_for("users.index"))


@users_bp.route("/<int:user_id>/unlock", methods=["POST"])
@role_required(UserRole.ADMIN)
def unlock_user(user_id: int):
    """Administratively clear account lockout and reset failed attempt counters."""
    with get_db_session() as db_session:
        user = db_session.query(User).filter_by(id=user_id).first()
        if not user:
            flash("User not found.", "error")
            return redirect(url_for("users.index"))

        user.failed_login_attempts = 0
        user.locked_until = None
        db_session.commit()

        log_security_event(
            action="USER_UNLOCKED",
            resource_type="USER",
            resource_id=str(user.id),
            user_id=current_user.id,
            username=current_user.username,
            status="SUCCESS",
            details=f'{{"unlocked_user": "{user.username}"}}',
        )

        flash(f"Account for '{user.username}' has been unlocked.", "success")
        return redirect(url_for("users.index"))


@users_bp.route("/<int:user_id>/toggle-active", methods=["POST"])
@role_required(UserRole.ADMIN)
def toggle_active(user_id: int):
    """Enable or disable a user account."""
    if user_id == current_user.id:
        flash("You cannot deactivate your own administrative account.", "error")
        return redirect(url_for("users.index"))

    with get_db_session() as db_session:
        user = db_session.query(User).filter_by(id=user_id).first()
        if not user:
            flash("User not found.", "error")
            return redirect(url_for("users.index"))

        user_name = user.username
        user.is_active = not user.is_active
        status_str = "activated" if user.is_active else "deactivated"
        db_session.commit()

        log_security_event(
            action="USER_STATUS_TOGGLED",
            resource_type="USER",
            resource_id=str(user.id),
            user_id=current_user.id,
            username=current_user.username,
            status="SUCCESS",
            details=f'{{"target_user": "{user_name}", "is_active": {user.is_active}}}',
        )

        flash(f"User '{user_name}' has been {status_str}.", "success")
        return redirect(url_for("users.index"))

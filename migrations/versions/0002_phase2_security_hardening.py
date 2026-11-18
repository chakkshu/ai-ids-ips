"""Phase 2 security hardening.

Revision ID: 0002_phase2_security_hardening
Revises: 0001_initial_schema
Create Date: 2026-11-17 00:00:00.000000

Adds password history, recovery codes, TOTP replay state, session revocation
metadata, encrypted-secret storage capacity, and audit hash versioning.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0002_phase2_security_hardening"
down_revision: str | None = "0001_initial_schema"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Users: encrypted TOTP envelope, replay state, password change time.
    with op.batch_alter_table("users") as batch_op:
        batch_op.alter_column(
            "totp_secret",
            existing_type=sa.String(length=64),
            type_=sa.Text(),
            existing_nullable=True,
        )
        batch_op.add_column(sa.Column("totp_last_step", sa.Integer(), nullable=True))
        batch_op.add_column(
            sa.Column(
                "last_password_change_at", sa.DateTime(timezone=True), nullable=True
            )
        )

    # 2. Password history (Argon2id hashes only).
    op.create_table(
        "password_history",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_password_history_user_id", "password_history", ["user_id"])

    # 3. One-time recovery codes (Argon2id hashes only).
    op.create_table(
        "recovery_codes",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("code_hash", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("used_ip", sa.String(length=45), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_recovery_codes_user_id", "recovery_codes", ["user_id"])

    # 4. Server-side session revocation metadata.
    with op.batch_alter_table("user_sessions") as batch_op:
        batch_op.add_column(
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True)
        )
        batch_op.add_column(
            sa.Column("revoke_reason", sa.String(length=64), nullable=True)
        )
        batch_op.create_index("ix_user_sessions_user_id", ["user_id"])

    # 5. Audit hash versioning. Existing rows are version 1; new rows are v2.
    with op.batch_alter_table("audit_logs") as batch_op:
        batch_op.add_column(
            sa.Column(
                "hash_version",
                sa.Integer(),
                nullable=False,
                server_default="1",
            )
        )


def downgrade() -> None:
    with op.batch_alter_table("audit_logs") as batch_op:
        batch_op.drop_column("hash_version")

    with op.batch_alter_table("user_sessions") as batch_op:
        batch_op.drop_index("ix_user_sessions_user_id")
        batch_op.drop_column("revoke_reason")
        batch_op.drop_column("revoked_at")

    op.drop_index("ix_recovery_codes_user_id", table_name="recovery_codes")
    op.drop_table("recovery_codes")

    op.drop_index("ix_password_history_user_id", table_name="password_history")
    op.drop_table("password_history")

    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_column("last_password_change_at")
        batch_op.drop_column("totp_last_step")
        batch_op.alter_column(
            "totp_secret",
            existing_type=sa.Text(),
            type_=sa.String(length=64),
            existing_nullable=True,
        )

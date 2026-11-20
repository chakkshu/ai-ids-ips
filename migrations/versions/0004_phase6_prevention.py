"""Phase 6 prevention, alerting, and threat-intelligence tables.

Revision ID: 0004_phase6_prevention
Revises: 0003_phase3_ml_registry
Create Date: 2026-11-21 00:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004_phase6_prevention"
down_revision: str | None = "0003_phase3_ml_registry"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _big_integer() -> sa.types.TypeEngine:
    """Use a variant that remains an INTEGER primary key on SQLite."""

    return sa.BigInteger().with_variant(sa.Integer, "sqlite")


def upgrade() -> None:
    op.create_table(
        "prevention_candidates",
        sa.Column("id", _big_integer(), autoincrement=True, nullable=False),
        sa.Column("event_id", sa.String(length=128), nullable=False),
        sa.Column("candidate_id", sa.String(length=128), nullable=False),
        sa.Column("detection_event_id", sa.String(length=128), nullable=False),
        sa.Column("detection_id", _big_integer(), nullable=True),
        sa.Column("flow_id", sa.String(length=128), nullable=False),
        sa.Column("src_ip", sa.String(length=45), nullable=False),
        sa.Column("dst_ip", sa.String(length=45), nullable=False),
        sa.Column("dst_port", sa.Integer(), nullable=False),
        sa.Column("model_version", sa.String(length=32), nullable=False),
        sa.Column("predicted_label", sa.String(length=64), nullable=False),
        sa.Column("verdict", sa.String(length=32), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("rare_class_flag", sa.Boolean(), nullable=False, default=False),
        sa.Column("simulation", sa.Boolean(), nullable=False, default=True),
        sa.Column("source_label", sa.String(length=64), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("processed", sa.Boolean(), nullable=False, default=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("event_id"),
        sa.UniqueConstraint("candidate_id"),
    )
    for name, columns in (
        ("ix_prevention_candidates_flow_id", ["flow_id"]),
        ("ix_prevention_candidates_detection_id", ["detection_id"]),
        ("ix_prevention_candidates_src_ip", ["src_ip"]),
        ("ix_prevention_candidates_predicted_label", ["predicted_label"]),
        ("ix_prevention_candidates_observed_at", ["observed_at"]),
        ("ix_prevention_candidates_ip_time", ["src_ip", "observed_at"]),
        ("ix_prevention_candidates_label_time", ["predicted_label", "observed_at"]),
    ):
        op.create_index(name, "prevention_candidates", columns)

    op.create_table(
        "policy_configs",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, default=False),
        sa.Column(
            "version", sa.String(length=32), nullable=False, default="phase6-default"
        ),
        sa.Column("config_json", sa.Text(), nullable=False, default="{}"),
        sa.Column("updated_by_user_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["updated_by_user_id"], ["users.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )

    op.create_table(
        "prevention_decisions",
        sa.Column("id", _big_integer(), autoincrement=True, nullable=False),
        sa.Column("candidate_id", sa.String(length=128), nullable=True),
        sa.Column("src_ip", sa.String(length=45), nullable=False),
        sa.Column("predicted_label", sa.String(length=64), nullable=False),
        sa.Column("action", sa.String(length=32), nullable=False),
        sa.Column("reason", sa.String(length=500), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("block_duration_minutes", sa.Integer(), nullable=True),
        sa.Column("requires_approval", sa.Boolean(), nullable=False, default=False),
        sa.Column("kill_switch_active", sa.Boolean(), nullable=False, default=False),
        sa.Column("repeat_count", sa.Integer(), nullable=False, default=1),
        sa.Column("escalation_level", sa.Integer(), nullable=False, default=0),
        sa.Column("details_json", sa.Text(), nullable=False, default="{}"),
        sa.Column("block_id", sa.Integer(), nullable=True),
        sa.Column("actor_user_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["actor_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["block_id"], ["blocked_ips.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    for name, columns in (
        ("ix_prevention_decisions_candidate_id", ["candidate_id"]),
        ("ix_prevention_decisions_src_ip", ["src_ip"]),
        ("ix_prevention_decisions_action", ["action"]),
        ("ix_prevention_decisions_created_at", ["created_at"]),
        ("ix_prevention_decisions_ip_time", ["src_ip", "created_at"]),
        ("ix_prevention_decisions_action_time", ["action", "created_at"]),
    ):
        op.create_index(name, "prevention_decisions", columns)

    op.create_table(
        "prevention_actions",
        sa.Column("id", _big_integer(), autoincrement=True, nullable=False),
        sa.Column("block_id", sa.Integer(), nullable=True),
        sa.Column("decision_id", _big_integer(), nullable=True),
        sa.Column("action", sa.String(length=32), nullable=False),
        sa.Column("ip_address", sa.String(length=45), nullable=False),
        sa.Column("rule_name", sa.String(length=128), nullable=True),
        sa.Column("dry_run", sa.Boolean(), nullable=False, default=True),
        sa.Column("command_preview", sa.Text(), nullable=True),
        sa.Column("result", sa.String(length=32), nullable=False),
        sa.Column("error", sa.String(length=500), nullable=True),
        sa.Column("attempted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor_user_id", sa.Integer(), nullable=True),
        sa.Column("correlation_id", sa.String(length=64), nullable=True),
        sa.ForeignKeyConstraint(["actor_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["block_id"], ["blocked_ips.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(
            ["decision_id"], ["prevention_decisions.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    for name, columns in (
        ("ix_prevention_actions_action", ["action"]),
        ("ix_prevention_actions_ip_address", ["ip_address"]),
        ("ix_prevention_actions_attempted_at", ["attempted_at"]),
        ("ix_prevention_actions_ip_time", ["ip_address", "attempted_at"]),
    ):
        op.create_index(name, "prevention_actions", columns)

    op.create_table(
        "alert_comments",
        sa.Column("id", _big_integer(), autoincrement=True, nullable=False),
        sa.Column("alert_id", _big_integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("username", sa.String(length=64), nullable=False, default="system"),
        sa.Column("comment", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["alert_id"], ["alerts.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_alert_comments_alert_id", "alert_comments", ["alert_id"])

    op.create_table(
        "alert_escalation_rules",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column(
            "severity",
            sa.Enum(
                "low",
                "medium",
                "high",
                "critical",
                name="alert_severity_enum",
                create_type=False,
            ),
            nullable=False,
        ),
        sa.Column("after_minutes", sa.Integer(), nullable=False),
        sa.Column("target_user_id", sa.Integer(), nullable=True),
        sa.Column("target_role", sa.String(length=32), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, default=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["target_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )

    op.create_table(
        "notifications",
        sa.Column("id", _big_integer(), autoincrement=True, nullable=False),
        sa.Column("alert_id", _big_integer(), nullable=True),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column(
            "channel",
            sa.Enum(
                "dashboard",
                "email",
                "webhook",
                name="notification_channel_enum",
            ),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.Enum(
                "pending",
                "sent",
                "failed",
                name="notification_status_enum",
            ),
            nullable=False,
            default="pending",
        ),
        sa.Column("subject", sa.String(length=128), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False, default=0),
        sa.Column("error", sa.String(length=500), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["alert_id"], ["alerts.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    for name, columns in (
        ("ix_notifications_alert_id", ["alert_id"]),
        ("ix_notifications_created_at", ["created_at"]),
        ("ix_notifications_status_created", ["status", "created_at"]),
    ):
        op.create_index(name, "notifications", columns)

    op.create_table(
        "ip_profiles",
        sa.Column("id", _big_integer(), autoincrement=True, nullable=False),
        sa.Column("ip_address", sa.String(length=45), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("detection_count", sa.Integer(), nullable=False, default=0),
        sa.Column("attack_types_json", sa.Text(), nullable=False, default="[]"),
        sa.Column("max_severity", sa.String(length=16), nullable=False, default="low"),
        sa.Column("reverse_dns", sa.String(length=255), nullable=True),
        sa.Column("enrichment_json", sa.Text(), nullable=True),
        sa.Column("last_enriched_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("ip_address"),
    )
    for name, columns in (
        ("ix_ip_profiles_ip_address", ["ip_address"]),
        ("ix_ip_profiles_last_seen", ["last_seen"]),
        ("ix_ip_profiles_severity_seen", ["max_severity", "last_seen"]),
    ):
        op.create_index(name, "ip_profiles", columns)

    op.create_table(
        "threat_blocklist_entries",
        sa.Column("id", _big_integer(), autoincrement=True, nullable=False),
        sa.Column("ip_address", sa.String(length=45), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False, default="import"),
        sa.Column("reason", sa.String(length=255), nullable=True),
        sa.Column("created_by_user_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"], ["users.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("ip_address"),
    )
    op.create_index(
        "ix_threat_blocklist_entries_ip_address",
        "threat_blocklist_entries",
        ["ip_address"],
    )


def downgrade() -> None:
    for table in (
        "threat_blocklist_entries",
        "ip_profiles",
        "notifications",
        "alert_escalation_rules",
        "alert_comments",
        "prevention_actions",
        "prevention_decisions",
        "policy_configs",
        "prevention_candidates",
    ):
        op.drop_table(table)

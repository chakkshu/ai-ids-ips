"""Initial database schema.

Revision ID: 0001_initial_schema
Revises: None
Create Date: 2026-11-17 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0001_initial_schema"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Users Table
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("username", sa.String(length=64), nullable=False),
        sa.Column("email", sa.String(length=128), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column(
            "role",
            sa.Enum("admin", "analyst", "viewer", name="user_role_enum"),
            nullable=False,
        ),
        sa.Column("is_active", sa.Boolean(), nullable=False, default=True),
        sa.Column("must_change_password", sa.Boolean(), nullable=False, default=True),
        sa.Column("totp_secret", sa.String(length=64), nullable=True),
        sa.Column("is_totp_enabled", sa.Boolean(), nullable=False, default=False),
        sa.Column("failed_login_attempts", sa.Integer(), nullable=False, default=0),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_login_ip", sa.String(length=45), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_users_username", "users", ["username"], unique=True)
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    # 2. User Sessions Table
    op.create_table(
        "user_sessions",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("session_token", sa.String(length=128), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("ip_address", sa.String(length=45), nullable=False),
        sa.Column("user_agent", sa.String(length=255), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_revoked", sa.Boolean(), nullable=False, default=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_activity_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_user_sessions_session_token",
        "user_sessions",
        ["session_token"],
        unique=True,
    )

    # 3. API Keys Table
    op.create_table(
        "api_keys",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("key_prefix", sa.String(length=16), nullable=False),
        sa.Column("key_hash", sa.String(length=128), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("scopes", sa.String(length=255), nullable=False, default="read"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, default=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_api_keys_key_prefix", "api_keys", ["key_prefix"])
    op.create_index("ix_api_keys_key_hash", "api_keys", ["key_hash"], unique=True)

    # 4. Audit Logs Table (Tamper-Evident Hash Chain)
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("username", sa.String(length=64), nullable=False, default="system"),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("resource_type", sa.String(length=64), nullable=False),
        sa.Column("resource_id", sa.String(length=64), nullable=True),
        sa.Column("ip_address", sa.String(length=45), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False, default="SUCCESS"),
        sa.Column("details", sa.Text(), nullable=True),
        sa.Column("correlation_id", sa.String(length=64), nullable=True),
        sa.Column("previous_hash", sa.String(length=64), nullable=False),
        sa.Column("entry_hash", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_logs_timestamp", "audit_logs", ["timestamp"])
    op.create_index("ix_audit_logs_user_id", "audit_logs", ["user_id"])
    op.create_index("ix_audit_logs_action", "audit_logs", ["action"])
    op.create_index("ix_audit_logs_resource_type", "audit_logs", ["resource_type"])
    op.create_index("ix_audit_logs_entry_hash", "audit_logs", ["entry_hash"])

    # 5. Network Flows Table
    op.create_table(
        "network_flows",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("flow_id", sa.String(length=128), nullable=False),
        sa.Column("src_ip", sa.String(length=45), nullable=False),
        sa.Column("src_port", sa.Integer(), nullable=False),
        sa.Column("dst_ip", sa.String(length=45), nullable=False),
        sa.Column("dst_port", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(length=16), nullable=False),
        sa.Column("duration", sa.Float(), nullable=False, default=0.0),
        sa.Column("total_fwd_packets", sa.Integer(), nullable=False, default=0),
        sa.Column("total_bwd_packets", sa.Integer(), nullable=False, default=0),
        sa.Column("total_fwd_bytes", sa.BigInteger(), nullable=False, default=0),
        sa.Column("total_bwd_bytes", sa.BigInteger(), nullable=False, default=0),
        sa.Column("flow_bytes_per_sec", sa.Float(), nullable=False, default=0.0),
        sa.Column("flow_packets_per_sec", sa.Float(), nullable=False, default=0.0),
        sa.Column("features_json", sa.Text(), nullable=False),
        sa.Column("encrypted_payload", sa.Text(), nullable=True),
        sa.Column("encrypted_dek", sa.String(length=255), nullable=True),
        sa.Column("nonce", sa.String(length=64), nullable=True),
        sa.Column("auth_tag", sa.String(length=64), nullable=True),
        sa.Column("key_version", sa.String(length=16), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_network_flows_timestamp", "network_flows", ["timestamp"])
    op.create_index("ix_network_flows_flow_id", "network_flows", ["flow_id"])
    op.create_index("ix_network_flows_src_ip", "network_flows", ["src_ip"])
    op.create_index("ix_network_flows_dst_ip", "network_flows", ["dst_ip"])
    op.create_index("ix_network_flows_dst_port", "network_flows", ["dst_port"])
    op.create_index(
        "ix_flows_src_dst_proto", "network_flows", ["src_ip", "dst_ip", "protocol"]
    )
    op.create_index(
        "ix_flows_dst_port_time", "network_flows", ["dst_port", "timestamp"]
    )

    # 6. Detections Table
    op.create_table(
        "detections",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("flow_id", sa.BigInteger(), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("predicted_label", sa.String(length=64), nullable=False),
        sa.Column("is_malicious", sa.Boolean(), nullable=False, default=False),
        sa.Column("confidence_score", sa.Float(), nullable=False),
        sa.Column("is_anomaly", sa.Boolean(), nullable=False, default=False),
        sa.Column("anomaly_score", sa.Float(), nullable=False, default=0.0),
        sa.Column("top_features_json", sa.Text(), nullable=True),
        sa.Column("model_version", sa.String(length=32), nullable=False),
        sa.Column("inference_latency_ms", sa.Float(), nullable=False, default=0.0),
        sa.ForeignKeyConstraint(["flow_id"], ["network_flows.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("flow_id"),
    )
    op.create_index("ix_detections_timestamp", "detections", ["timestamp"])
    op.create_index("ix_detections_predicted_label", "detections", ["predicted_label"])
    op.create_index("ix_detections_is_malicious", "detections", ["is_malicious"])
    op.create_index("ix_detections_model_version", "detections", ["model_version"])
    op.create_index(
        "ix_detections_malicious_time", "detections", ["is_malicious", "timestamp"]
    )
    op.create_index(
        "ix_detections_label_conf",
        "detections",
        ["predicted_label", "confidence_score"],
    )

    # 7. Alerts Table
    op.create_table(
        "alerts",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("detection_id", sa.BigInteger(), nullable=False),
        sa.Column("dedup_key", sa.String(length=64), nullable=False),
        sa.Column("occurrence_count", sa.Integer(), nullable=False, default=1),
        sa.Column("title", sa.String(length=128), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "severity",
            sa.Enum("low", "medium", "high", "critical", name="alert_severity_enum"),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.Enum(
                "new",
                "acknowledged",
                "investigating",
                "resolved",
                "false_positive",
                name="alert_status_enum",
            ),
            nullable=False,
        ),
        sa.Column("src_ip", sa.String(length=45), nullable=False),
        sa.Column("dst_ip", sa.String(length=45), nullable=False),
        sa.Column("dst_port", sa.Integer(), nullable=False),
        sa.Column("attack_type", sa.String(length=64), nullable=False),
        sa.Column("assigned_user_id", sa.Integer(), nullable=True),
        sa.Column("assigned_username", sa.String(length=64), nullable=True),
        sa.Column("resolution_notes", sa.Text(), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("email_dispatched", sa.Boolean(), nullable=False, default=False),
        sa.Column("webhook_dispatched", sa.Boolean(), nullable=False, default=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["detection_id"], ["detections.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["assigned_user_id"], ["users.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_alerts_detection_id", "alerts", ["detection_id"])
    op.create_index("ix_alerts_dedup_key", "alerts", ["dedup_key"])
    op.create_index("ix_alerts_severity", "alerts", ["severity"])
    op.create_index("ix_alerts_status", "alerts", ["status"])
    op.create_index("ix_alerts_src_ip", "alerts", ["src_ip"])
    op.create_index("ix_alerts_dst_ip", "alerts", ["dst_ip"])
    op.create_index("ix_alerts_attack_type", "alerts", ["attack_type"])
    op.create_index("ix_alerts_assigned_user_id", "alerts", ["assigned_user_id"])
    op.create_index("ix_alerts_created_at", "alerts", ["created_at"])
    op.create_index(
        "ix_alerts_status_sev_time", "alerts", ["status", "severity", "created_at"]
    )
    op.create_index("ix_alerts_src_time", "alerts", ["src_ip", "created_at"])

    # 8. Blocked IPs Table
    op.create_table(
        "blocked_ips",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("ip_address", sa.String(length=45), nullable=False),
        sa.Column("reason", sa.String(length=255), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "pending_approval",
                "active",
                "expired",
                "released",
                name="block_status_enum",
            ),
            nullable=False,
        ),
        sa.Column("escalation_level", sa.Integer(), nullable=False, default=1),
        sa.Column("blocked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_dry_run", sa.Boolean(), nullable=False, default=True),
        sa.Column("firewall_rule_name", sa.String(length=128), nullable=True),
        sa.Column("created_by_user_id", sa.Integer(), nullable=True),
        sa.Column("approved_by_user_id", sa.Integer(), nullable=True),
        sa.Column("released_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("released_by_user_id", sa.Integer(), nullable=True),
        sa.Column("release_reason", sa.String(length=255), nullable=True),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"], ["users.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["approved_by_user_id"], ["users.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["released_by_user_id"], ["users.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_blocked_ips_ip_address", "blocked_ips", ["ip_address"])
    op.create_index("ix_blocked_ips_status", "blocked_ips", ["status"])
    op.create_index("ix_blocked_ips_expires_at", "blocked_ips", ["expires_at"])
    op.create_index("ix_blocks_ip_status", "blocked_ips", ["ip_address", "status"])
    op.create_index("ix_blocks_status_expires", "blocked_ips", ["status", "expires_at"])

    # 9. Whitelist Table
    op.create_table(
        "whitelist",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("cidr", sa.String(length=45), nullable=False),
        sa.Column("description", sa.String(length=255), nullable=False),
        sa.Column("is_immutable", sa.Boolean(), nullable=False, default=False),
        sa.Column("created_by_user_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"], ["users.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_whitelist_cidr", "whitelist", ["cidr"], unique=True)

    # 10. Model Artifacts Table
    op.create_table(
        "model_artifacts",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("version", sa.String(length=32), nullable=False),
        sa.Column(
            "algorithm",
            sa.String(length=64),
            nullable=False,
            default="RandomForestClassifier",
        ),
        sa.Column("model_path", sa.String(length=255), nullable=False),
        sa.Column("scaler_path", sa.String(length=255), nullable=False),
        sa.Column("encoder_path", sa.String(length=255), nullable=False),
        sa.Column("features_list_json", sa.Text(), nullable=False),
        sa.Column("metrics_json", sa.Text(), nullable=False),
        sa.Column("dataset_hash", sa.String(length=64), nullable=False),
        sa.Column("git_commit", sa.String(length=40), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, default=False),
        sa.Column("is_staged", sa.Boolean(), nullable=False, default=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_model_artifacts_version", "model_artifacts", ["version"], unique=True
    )
    op.create_index("ix_model_artifacts_is_active", "model_artifacts", ["is_active"])

    # 11. Drift Metrics Table
    op.create_table(
        "drift_metrics",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("model_version", sa.String(length=32), nullable=False),
        sa.Column("psi_score", sa.Float(), nullable=False),
        sa.Column("ks_statistic", sa.Float(), nullable=False),
        sa.Column("ks_p_value", sa.Float(), nullable=False),
        sa.Column("drift_detected", sa.Boolean(), nullable=False, default=False),
        sa.Column("drifted_features_json", sa.Text(), nullable=True),
        sa.Column("sample_size", sa.Integer(), nullable=False),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_drift_metrics_model_version", "drift_metrics", ["model_version"]
    )
    op.create_index(
        "ix_drift_metrics_drift_detected", "drift_metrics", ["drift_detected"]
    )
    op.create_index("ix_drift_metrics_evaluated_at", "drift_metrics", ["evaluated_at"])

    # 12. Analyst Feedback Table
    op.create_table(
        "analyst_feedback",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("detection_id", sa.BigInteger(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("is_false_positive", sa.Boolean(), nullable=False),
        sa.Column("verified_label", sa.String(length=64), nullable=False),
        sa.Column("analyst_notes", sa.Text(), nullable=True),
        sa.Column("used_in_retraining", sa.Boolean(), nullable=False, default=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["detection_id"], ["detections.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_analyst_feedback_detection_id", "analyst_feedback", ["detection_id"]
    )
    op.create_index("ix_analyst_feedback_user_id", "analyst_feedback", ["user_id"])


def downgrade() -> None:
    op.drop_table("analyst_feedback")
    op.drop_table("drift_metrics")
    op.drop_table("model_artifacts")
    op.drop_table("whitelist")
    op.drop_table("blocked_ips")
    op.drop_table("alerts")
    op.drop_table("detections")
    op.drop_table("network_flows")
    op.drop_table("audit_logs")
    op.drop_table("api_keys")
    op.drop_table("user_sessions")
    op.drop_table("users")
    # Native enum types only exist on PostgreSQL; SQLite stores enums as CHECK
    # constraints on the table, so there is nothing to drop there.
    if op.get_bind().dialect.name == "postgresql":
        for enum_name in (
            "user_role_enum",
            "alert_severity_enum",
            "alert_status_enum",
            "block_status_enum",
        ):
            op.execute(f"DROP TYPE IF EXISTS {enum_name}")

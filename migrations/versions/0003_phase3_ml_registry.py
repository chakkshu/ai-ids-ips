"""Phase 3 ML registry metadata.

Revision ID: 0003_phase3_ml_registry
Revises: 0002_phase2_security_hardening
Create Date: 2026-11-17 01:00:00.000000

Adds checksum, training-config, drift-baseline, Isolation Forest, and explicit
staged/active/archived status columns to ``model_artifacts``.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_phase3_ml_registry"
down_revision: str | None = "0002_phase2_security_hardening"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("model_artifacts") as batch_op:
        batch_op.add_column(
            sa.Column("isolation_forest_path", sa.String(length=255), nullable=True)
        )
        batch_op.add_column(
            sa.Column(
                "checksums_json",
                sa.Text(),
                nullable=False,
                server_default="{}",
            )
        )
        batch_op.add_column(
            sa.Column(
                "training_config_json",
                sa.Text(),
                nullable=False,
                server_default="{}",
            )
        )
        batch_op.add_column(
            sa.Column("drift_baseline_path", sa.String(length=255), nullable=True)
        )
        batch_op.add_column(
            sa.Column(
                "status",
                sa.String(length=16),
                nullable=False,
                server_default="staged",
            )
        )
        batch_op.add_column(
            sa.Column("promoted_at", sa.DateTime(timezone=True), nullable=True)
        )
        batch_op.create_index("ix_model_artifacts_status", ["status"])


def downgrade() -> None:
    with op.batch_alter_table("model_artifacts") as batch_op:
        batch_op.drop_index("ix_model_artifacts_status")
        batch_op.drop_column("promoted_at")
        batch_op.drop_column("status")
        batch_op.drop_column("drift_baseline_path")
        batch_op.drop_column("training_config_json")
        batch_op.drop_column("checksums_json")
        batch_op.drop_column("isolation_forest_path")

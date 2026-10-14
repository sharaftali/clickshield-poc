"""tasks 014/016/017: risk band, signal diversity, rule category, custom protection settings

Revision ID: f1a7c3d2b4e5
Revises: dd39d07fa137
Create Date: 2026-10-08 15:00:00.000000

"""
from __future__ import annotations

from typing import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = "f1a7c3d2b4e5"
down_revision: str | None = "dd39d07fa137"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("sessions", sa.Column("risk_band", sa.String(length=16), server_default="LOW", nullable=False))
    op.add_column("sessions", sa.Column("signal_diversity", sa.Integer(), server_default="0", nullable=False))
    op.add_column("sessions", sa.Column("risk_categories", postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.add_column("sessions", sa.Column("scoring_version", sa.Integer(), nullable=True))
    op.create_index("ix_sessions_org_verdict_created", "sessions", ["organization_id", "verdict", "created_at"])
    op.add_column("organizations", sa.Column("protection_settings", postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.add_column("fraud_events", sa.Column("category", sa.String(length=20), nullable=True))
    op.add_column("fraud_events", sa.Column("rule_version", sa.Integer(), nullable=True))
    op.add_column("fraud_events", sa.Column("rule_config", postgresql.JSONB(astext_type=sa.Text()), nullable=True))

    # Spec §24 bands for sessions scored before this change (verdicts are left as they were).
    op.execute(
        """
        UPDATE sessions SET risk_band = CASE
            WHEN risk_score >= 80 THEN 'VERY_HIGH'
            WHEN risk_score >= 60 THEN 'HIGH'
            WHEN risk_score >= 30 THEN 'MODERATE'
            ELSE 'LOW' END
        """
    )


def downgrade() -> None:
    op.drop_column("fraud_events", "rule_config")
    op.drop_column("fraud_events", "rule_version")
    op.drop_column("fraud_events", "category")
    op.drop_column("organizations", "protection_settings")
    op.drop_index("ix_sessions_org_verdict_created", table_name="sessions")
    op.drop_column("sessions", "scoring_version")
    op.drop_column("sessions", "risk_categories")
    op.drop_column("sessions", "signal_diversity")
    op.drop_column("sessions", "risk_band")

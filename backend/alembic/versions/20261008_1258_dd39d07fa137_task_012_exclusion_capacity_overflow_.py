"""task 012: exclusion capacity — overflow queue, last fraud time, external exclusion count

Revision ID: dd39d07fa137
Revises: e7b5a6c8d9f0
Create Date: 2026-10-08 12:58:57.153446

"""
from __future__ import annotations

from typing import Sequence

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision: str = "dd39d07fa137"
down_revision: str | None = "e7b5a6c8d9f0"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("exclusions", sa.Column("overflow", sa.Boolean(), server_default="false", nullable=False))
    op.add_column("exclusions", sa.Column("last_fraud_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_exclusions_campaign_status", "exclusions", ["google_campaign_id", "status"], unique=False)
    op.add_column(
        "google_campaigns",
        sa.Column("external_exclusion_count", sa.Integer(), server_default="0", nullable=False),
    )

    # Existing exclusions: last known fraud = when they were sent (or created).
    op.execute(
        "UPDATE exclusions SET last_fraud_at = COALESCE(submitted_at, created_at) WHERE last_fraud_at IS NULL"
    )
    # exclusion_count was never maintained before; recompute the slots in use.
    op.execute(
        """
        UPDATE google_campaigns c
        SET exclusion_count = (
            SELECT count(*) FROM exclusions e
            WHERE e.google_campaign_id = c.id
              AND e.status IN ('PENDING', 'SUBMITTED', 'ACTIVE')
        )
        """
    )


def downgrade() -> None:
    op.drop_column("google_campaigns", "external_exclusion_count")
    op.drop_index("ix_exclusions_campaign_status", table_name="exclusions")
    op.drop_column("exclusions", "last_fraud_at")
    op.drop_column("exclusions", "overflow")

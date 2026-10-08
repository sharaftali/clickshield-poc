"""task 005: one fraud_events row per (session_id, rule_name)

Revision ID: c5f3e4a6b7d8
Revises: b4e2d3f5a6c7
Create Date: 2026-10-06 17:20:00

"""
from __future__ import annotations

from typing import Sequence

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "c5f3e4a6b7d8"
down_revision: str | None = "b4e2d3f5a6c7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # The dedupe below deletes rows. Keep a copy; drop it once the upgrade is verified:
    #   DROP TABLE fraud_events_backup_005;
    op.execute("CREATE TABLE IF NOT EXISTS fraud_events_backup_005 AS TABLE fraud_events")

    # Keep the most recent row per (session, rule); every 3-second re-score inserted a copy.
    op.execute(
        """
        DELETE FROM fraud_events f
        USING (
            SELECT id,
                   ROW_NUMBER() OVER (
                       PARTITION BY session_id, rule_name
                       ORDER BY updated_at DESC, created_at DESC, id DESC
                   ) AS rn
            FROM fraud_events
        ) ranked
        WHERE f.id = ranked.id AND ranked.rn > 1
        """
    )

    op.create_unique_constraint(
        "uq_fraud_events_session_rule", "fraud_events", ["session_id", "rule_name"]
    )


def downgrade() -> None:
    # Deleted duplicates are not restored (they are in fraud_events_backup_005 if needed).
    op.drop_constraint("uq_fraud_events_session_rule", "fraud_events", type_="unique")

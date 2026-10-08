"""task 007: sessions unique per (website_id, session_token)

Revision ID: e7b5a6c8d9f0
Revises: d6a4f5b7c8e9
Create Date: 2026-10-06 17:40:00

"""
from __future__ import annotations

from typing import Sequence

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "e7b5a6c8d9f0"
down_revision: str | None = "d6a4f5b7c8e9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Merge duplicate sessions (concurrent first batches, or one token reused across a
    # website's sessions) into the oldest one. Their events move to the kept session;
    # their rule results are dropped — the kept session is re-scored on its next batch.
    op.execute(
        """
        CREATE TEMP TABLE session_dupes ON COMMIT DROP AS
        SELECT id AS dup_id, keep_id
        FROM (
            SELECT id,
                   first_value(id) OVER (
                       PARTITION BY website_id, session_token
                       ORDER BY created_at, id
                   ) AS keep_id
            FROM sessions
        ) ranked
        WHERE id <> keep_id
        """
    )
    op.execute(
        """
        UPDATE events e SET session_id = d.keep_id
        FROM session_dupes d WHERE e.session_id = d.dup_id
        """
    )
    op.execute("DELETE FROM fraud_events f USING session_dupes d WHERE f.session_id = d.dup_id")
    op.execute("DELETE FROM sessions s USING session_dupes d WHERE s.id = d.dup_id")

    op.create_unique_constraint(
        "uq_sessions_website_token", "sessions", ["website_id", "session_token"]
    )
    # Superseded by the unique constraint's (website_id, session_token) index.
    op.drop_index("ix_sessions_session_token", table_name="sessions")


def downgrade() -> None:
    # Merged duplicate sessions are not restored.
    op.create_index("ix_sessions_session_token", "sessions", ["session_token"])
    op.drop_constraint("uq_sessions_website_token", "sessions", type_="unique")

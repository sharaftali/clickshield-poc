"""task 003: google connection re-auth state, exclusion last_error, fix fake dry-run rows

Revision ID: a3f1c2d4e5b6
Revises: 1c9b8e22c81b
Create Date: 2026-10-06 17:00:00

"""
from __future__ import annotations

from typing import Sequence

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision: str = "a3f1c2d4e5b6"
down_revision: str | None = "1c9b8e22c81b"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "google_connections",
        sa.Column("needs_reauth", sa.Boolean(), server_default=sa.text("false"), nullable=False),
    )
    op.add_column("google_connections", sa.Column("auth_error", sa.Text(), nullable=True))
    op.add_column("exclusions", sa.Column("last_error", sa.Text(), nullable=True))

    # The old adapter reported "dry-run" exclusions as ACTIVE without calling Google.
    # They never existed in Google Ads: mark them SKIPPED so the dashboard is truthful.
    op.execute(
        """
        UPDATE exclusions
        SET status = 'SKIPPED',
            google_resource_name = NULL,
            last_error = 'Never sent to Google Ads (legacy dry-run record).'
        WHERE status = 'ACTIVE' AND api_request_id LIKE 'dry-run-%'
        """
    )


def downgrade() -> None:
    # The SKIPPED data fix is intentionally not reverted (those rows were never real exclusions).
    op.drop_column("exclusions", "last_error")
    op.drop_column("google_connections", "auth_error")
    op.drop_column("google_connections", "needs_reauth")

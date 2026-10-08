"""task 004: sessions.ad_landing_at + indexes for cross-session ad-click velocity

Revision ID: b4e2d3f5a6c7
Revises: a3f1c2d4e5b6
Create Date: 2026-10-06 17:10:00

"""
from __future__ import annotations

from typing import Sequence

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision: str = "b4e2d3f5a6c7"
down_revision: str | None = "a3f1c2d4e5b6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("sessions", sa.Column("ad_landing_at", sa.DateTime(timezone=True), nullable=True))

    # Existing paid sessions: treat their creation time as the landing time, using
    # the same signals as TrackingService._is_google_ads_traffic.
    op.execute(
        """
        UPDATE sessions
        SET ad_landing_at = created_at
        WHERE ad_landing_at IS NULL
          AND (
            gclid IS NOT NULL
            OR utm_source ILIKE '%google%'
            OR NULLIF(extra_signals ->> 'campaign_id', '') IS NOT NULL
          )
        """
    )

    op.create_index(
        "ix_sessions_org_ip_ad_landing", "sessions", ["organization_id", "ip_address", "ad_landing_at"]
    )
    op.create_index("ix_sessions_visitor_ad_landing", "sessions", ["visitor_id", "ad_landing_at"])


def downgrade() -> None:
    op.drop_index("ix_sessions_visitor_ad_landing", table_name="sessions")
    op.drop_index("ix_sessions_org_ip_ad_landing", table_name="sessions")
    op.drop_column("sessions", "ad_landing_at")

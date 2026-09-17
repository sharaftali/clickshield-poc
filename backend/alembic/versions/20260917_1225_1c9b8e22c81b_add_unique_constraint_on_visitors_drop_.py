"""add unique constraint on visitors, drop duplicate session ip index

Revision ID: 1c9b8e22c81b
Revises: 4b4622932e10
Create Date: 2026-09-17 12:25:14.247695

"""
from __future__ import annotations

from typing import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = '1c9b8e22c81b'
down_revision: str | None = '4b4622932e10'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Drop redundant/duplicate indexes if they exist.
    # Some were already removed from the initial migration by hand,
    # so we use IF EXISTS to be safe.
    op.execute("DROP INDEX IF EXISTS ix_sessions_ip")
    op.execute("DROP INDEX IF EXISTS ix_audit_logs_organization_id")
    op.execute("DROP INDEX IF EXISTS ix_exclusions_organization_id")
    op.execute("DROP INDEX IF EXISTS ix_fraud_events_session")

    # Add unique constraint to prevent duplicate visitors.
    # De-duplicate first in case any exist from testing.
    op.execute("""
        DELETE FROM visitors v1
        USING visitors v2
        WHERE v1.website_id = v2.website_id
          AND v1.visitor_token = v2.visitor_token
          AND v1.created_at > v2.created_at
    """)
    op.create_unique_constraint(
        'uq_visitors_website_token',
        'visitors',
        ['website_id', 'visitor_token'],
    )


def downgrade() -> None:
    op.drop_constraint(
        'uq_visitors_website_token', 'visitors', type_='unique'
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_fraud_events_session ON fraud_events (session_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_exclusions_organization_id ON exclusions (organization_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_audit_logs_organization_id ON audit_logs (organization_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_sessions_ip ON sessions (ip_address)")

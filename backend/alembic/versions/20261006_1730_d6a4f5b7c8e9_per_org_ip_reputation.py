"""task 006: per-organization ip_reputation, rebuilt from sessions; history index

Revision ID: d6a4f5b7c8e9
Revises: c5f3e4a6b7d8
Create Date: 2026-10-06 17:30:00

"""
from __future__ import annotations

from typing import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = "d6a4f5b7c8e9"
down_revision: str | None = "c5f3e4a6b7d8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("ip_reputation", sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=True))

    # Old rows were global and held an all-time maximum risk score. ip_reputation is a
    # cache, so rebuild it per organization from sessions. risk_score/confidence start
    # at 0 and are refreshed with the decayed score the next time each IP is scored.
    op.execute("DELETE FROM ip_reputation")
    op.execute(
        """
        INSERT INTO ip_reputation (
            organization_id, ip, risk_score, confidence, country, asn, isp,
            is_vpn, is_proxy, is_tor, is_datacenter,
            total_sessions, fraud_sessions, legitimate_sessions, blocked_count,
            first_seen, last_seen, created_at, updated_at
        )
        SELECT
            s.organization_id,
            s.ip_address,
            0, 0,
            (array_agg(s.country ORDER BY s.created_at DESC))[1],
            (array_agg(s.asn ORDER BY s.created_at DESC))[1],
            (array_agg(s.isp ORDER BY s.created_at DESC))[1],
            bool_or(s.is_vpn), bool_or(s.is_proxy), bool_or(s.is_tor), bool_or(s.is_datacenter),
            count(*),
            count(*) FILTER (WHERE COALESCE(s.final_label, s.verdict) = 'FRAUD'),
            count(*) FILTER (WHERE COALESCE(s.final_label, s.verdict) <> 'FRAUD'),
            0,
            min(s.created_at), max(s.created_at), now(), now()
        FROM sessions s
        WHERE s.ip_address IS NOT NULL
        GROUP BY s.organization_id, s.ip_address
        """
    )
    op.execute(
        """
        UPDATE ip_reputation r
        SET blocked_count = e.active
        FROM (
            SELECT organization_id, ip_address, count(*) AS active
            FROM exclusions
            WHERE status = 'ACTIVE'
            GROUP BY organization_id, ip_address
        ) e
        WHERE r.organization_id = e.organization_id AND r.ip = e.ip_address
        """
    )

    op.alter_column("ip_reputation", "organization_id", nullable=False)
    op.create_foreign_key(
        "fk_ip_reputation_organization_id_organizations",
        "ip_reputation", "organizations",
        ["organization_id"], ["id"],
        ondelete="CASCADE",
    )
    op.drop_constraint("pk_ip_reputation", "ip_reputation", type_="primary")
    op.create_primary_key("pk_ip_reputation", "ip_reputation", ["organization_id", "ip"])

    # Reputation history lookup: this org's other sessions on an IP, newest first.
    op.create_index("ix_sessions_org_ip_created", "sessions", ["organization_id", "ip_address", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_sessions_org_ip_created", table_name="sessions")
    # Per-org rows can't be folded back into one global row per IP; the cache is
    # cleared and refills as traffic is scored.
    op.execute("DELETE FROM ip_reputation")
    op.drop_constraint("pk_ip_reputation", "ip_reputation", type_="primary")
    op.drop_constraint("fk_ip_reputation_organization_id_organizations", "ip_reputation", type_="foreignkey")
    op.drop_column("ip_reputation", "organization_id")
    op.create_primary_key("pk_ip_reputation", "ip_reputation", ["ip"])

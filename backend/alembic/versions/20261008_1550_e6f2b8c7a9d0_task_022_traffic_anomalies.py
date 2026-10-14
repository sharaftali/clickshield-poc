"""task 022: campaign traffic statistics, traffic anomalies and TRAFFIC_ANOMALY rule

Revision ID: e6f2b8c7a9d0
Revises: d5e1a7b6f8c9
Create Date: 2026-10-08 15:50:00.000000

"""
from __future__ import annotations

from typing import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = "e6f2b8c7a9d0"
down_revision: str | None = "d5e1a7b6f8c9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


RULES_TABLE = sa.table(
    "rules",
    sa.column("code", sa.String), sa.column("name", sa.String), sa.column("description", sa.Text),
    sa.column("category", sa.String), sa.column("enabled", sa.Boolean), sa.column("weight", sa.Integer),
    sa.column("confidence", sa.Integer), sa.column("params", postgresql.JSONB), sa.column("version", sa.Integer),
)


def _seed(rules: list[tuple]) -> None:
    op.bulk_insert(RULES_TABLE, [
        {"code": code, "name": name, "category": category, "weight": weight, "confidence": confidence,
         "description": description, "params": params, "enabled": True, "version": 1}
        for code, name, category, weight, confidence, description, params in rules
    ])


def _unseed(rules: list[tuple]) -> None:
    codes = ", ".join(f"'{rule[0]}'" for rule in rules)
    op.execute(f"DELETE FROM rule_overrides WHERE rule_code IN ({codes})")
    op.execute(f"DELETE FROM rules WHERE code IN ({codes})")


RULES = [
    ("TRAFFIC_ANOMALY", "Campaign traffic anomaly", "ANOMALY", 10, 50,
     "The ad click arrived during a detected traffic spike on its campaign.", {"min_level": "HIGH"}),
]


def upgrade() -> None:
    op.create_table(
        "campaign_traffic_stats",
        sa.Column("google_campaign_id", sa.UUID(), nullable=False),
        sa.Column("hour_bucket", sa.DateTime(timezone=True), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("ad_landings", sa.Integer(), nullable=False),
        sa.Column("distinct_ips", sa.Integer(), nullable=False),
        sa.Column("distinct_visitors", sa.Integer(), nullable=False),
        sa.Column("fraud_sessions", sa.Integer(), nullable=False),
        sa.Column("median_click_interval_s", sa.Float(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["google_campaign_id"], ["google_campaigns.id"],
                                name=op.f("fk_campaign_traffic_stats_google_campaign_id_google_campaigns"),
                                ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"],
                                name=op.f("fk_campaign_traffic_stats_organization_id_organizations"),
                                ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("google_campaign_id", "hour_bucket", name=op.f("pk_campaign_traffic_stats")),
    )
    op.create_index(op.f("ix_campaign_traffic_stats_organization_id"), "campaign_traffic_stats", ["organization_id"])
    op.create_table(
        "traffic_anomalies",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("google_campaign_id", sa.UUID(), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("metric", sa.String(length=40), nullable=False),
        sa.Column("observed", sa.Float(), nullable=False),
        sa.Column("expected", sa.Float(), nullable=False),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("level", sa.String(length=10), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["google_campaign_id"], ["google_campaigns.id"],
                                name=op.f("fk_traffic_anomalies_google_campaign_id_google_campaigns"),
                                ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"],
                                name=op.f("fk_traffic_anomalies_organization_id_organizations"),
                                ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_traffic_anomalies")),
        sa.UniqueConstraint("google_campaign_id", "metric", "window_start", name="uq_traffic_anomalies_window"),
    )
    op.create_index("ix_traffic_anomalies_org_window", "traffic_anomalies", ["organization_id", "window_start"])
    op.create_index("ix_sessions_campaign_ad_landing", "sessions", ["google_campaign_id", "ad_landing_at"])
    _seed(RULES)


def downgrade() -> None:
    _unseed(RULES)
    op.drop_index("ix_sessions_campaign_ad_landing", table_name="sessions")
    op.drop_index("ix_traffic_anomalies_org_window", table_name="traffic_anomalies")
    op.drop_table("traffic_anomalies")
    op.drop_index(op.f("ix_campaign_traffic_stats_organization_id"), table_name="campaign_traffic_stats")
    op.drop_table("campaign_traffic_stats")

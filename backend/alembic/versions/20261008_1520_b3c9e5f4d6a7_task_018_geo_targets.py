"""task 018: campaign location targets and GEO rules

Revision ID: b3c9e5f4d6a7
Revises: a2b8d4e3c5f6
Create Date: 2026-10-08 15:20:00.000000

"""
from __future__ import annotations

from typing import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = "b3c9e5f4d6a7"
down_revision: str | None = "a2b8d4e3c5f6"
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
    ("GEO_ANOMALY", "Geo anomaly", "GEO", 15, 55,
     "The visitor's location is outside the campaign's location targeting.",
     {"interest_factor": 0.5, "region_factor": 0.4}),
    ("GEO_TIMEZONE_MISMATCH", "Timezone mismatch", "GEO", 8, 50,
     "The browser's timezone is not used in the IP's country.", {}),
]


def upgrade() -> None:
    op.add_column("google_campaigns", sa.Column("geo_target_type", sa.String(length=32), nullable=True))
    op.create_table(
        "google_campaign_locations",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("campaign_id", sa.UUID(), nullable=False),
        sa.Column("criterion_id", sa.String(length=32), nullable=False),
        sa.Column("criterion_type", sa.String(length=16), nullable=False),
        sa.Column("geo_target_constant", sa.String(length=64), nullable=True),
        sa.Column("country_code", sa.String(length=2), nullable=True),
        sa.Column("region", sa.String(length=100), nullable=True),
        sa.Column("name", sa.String(length=255), nullable=True),
        sa.Column("target_type", sa.String(length=32), nullable=True),
        sa.Column("negative", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["campaign_id"], ["google_campaigns.id"],
                                name=op.f("fk_google_campaign_locations_campaign_id_google_campaigns"),
                                ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_google_campaign_locations")),
    )
    op.create_index(op.f("ix_google_campaign_locations_campaign_id"), "google_campaign_locations", ["campaign_id"])
    _seed(RULES)


def downgrade() -> None:
    _unseed(RULES)
    op.drop_index(op.f("ix_google_campaign_locations_campaign_id"), table_name="google_campaign_locations")
    op.drop_table("google_campaign_locations")
    op.drop_column("google_campaigns", "geo_target_type")

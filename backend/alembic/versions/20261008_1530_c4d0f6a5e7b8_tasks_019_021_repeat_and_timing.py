"""tasks 019/021: device key, click / interaction interval statistics, repeat and timing rules

Revision ID: c4d0f6a5e7b8
Revises: b3c9e5f4d6a7
Create Date: 2026-10-08 15:30:00.000000

"""
from __future__ import annotations

from typing import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = "c4d0f6a5e7b8"
down_revision: str | None = "b3c9e5f4d6a7"
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
    ("REPEATED_VISITOR", "Repeated visitor", "VELOCITY", 20, 65,
     "The same visitor, IP or device clicked the same campaign's ad repeatedly over hours or days.",
     {"visitor_campaign_short_gte": 3, "visitor_campaign_long_gte": 6,
      "ip_campaign_short_gte": 5, "ip_campaign_long_gte": 10,
      "ip_landing_short_gte": 5, "ip_landing_long_gte": 10,
      "device_campaign_gte": 5, "device_min_distinct_ips": 3, "device_burst_factor": 3.0,
      "shared_ip_factor": 0.2, "base_strength": 0.5}),
    ("SUB_SECOND_CLICK_INTERVAL", "Sub-second ad clicks", "VELOCITY", 15, 65,
     "Ad clicks from this source came less than a second apart (spec §31).",
     {"min_landings": 4, "min_interval_seconds": 1.0}),
    ("REPEATED_IDENTICAL_SESSIONS", "Repeated identical sessions", "AUTOMATION", 20, 65,
     "Several recent sessions from the same IP and device behaved identically (same landing "
     "page, pages and duration). Bounces are left to UNUSUAL_SESSION.",
     {"min_matches": 3, "window_minutes": 60, "duration_tolerance_seconds": 1.0, "min_duration_seconds": 3.0}),
    ("ABNORMAL_CLICK_TIMING", "Abnormal click timing", "AUTOMATION", 20, 65,
     "Ad clicks from this source arrive at machine-regular intervals (a slow, steady bot "
     "below the velocity thresholds).",
     {"min_landings": 4, "max_cv": 0.15, "min_mean_interval_seconds": 2.0}),
    ("IMPOSSIBLE_INTERACTION_TIMING", "Impossible interaction timing", "AUTOMATION", 20, 70,
     "On-page actions happened faster or more regularly than a person can act.",
     {"min_events": 10, "min_interval_ms": 50.0, "max_cv": 0.1}),
]

FLOAT_COLUMNS = (
    "ad_click_interval_avg_s", "ad_click_interval_min_s", "ad_click_interval_var", "ad_click_interval_cv",
    "event_interval_avg_ms", "event_interval_min_ms", "event_interval_var", "event_interval_cv",
)


def upgrade() -> None:
    op.add_column("sessions", sa.Column("device_key", sa.String(length=64), nullable=True))
    for column in FLOAT_COLUMNS:
        op.add_column("sessions", sa.Column(column, sa.Float(), nullable=True))
    op.create_index("ix_sessions_org_device_ad_landing", "sessions", ["organization_id", "device_key", "ad_landing_at"])
    _seed(RULES)


def downgrade() -> None:
    _unseed(RULES)
    op.drop_index("ix_sessions_org_device_ad_landing", table_name="sessions")
    for column in reversed(FLOAT_COLUMNS):
        op.drop_column("sessions", column)
    op.drop_column("sessions", "device_key")

"""task 015: rules and rule_overrides tables, seeded with today's rule values

Revision ID: a2b8d4e3c5f6
Revises: f1a7c3d2b4e5
Create Date: 2026-10-08 15:10:00.000000

"""
from __future__ import annotations

from typing import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = "a2b8d4e3c5f6"
down_revision: str | None = "f1a7c3d2b4e5"
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


# Today's values (risk_scorer.py before task 015). VPN / proxy / Tor were one rule;
# each now has the old weight so it can be tuned on its own.
RULES = [
    ("ABNORMAL_CLICK_VELOCITY", "Abnormal click velocity", "VELOCITY", 25, 70,
     "The same IP or visitor clicked the ad unusually often in a short window.",
     {"clicks_60_seconds_gte": 8, "clicks_5_minutes_gte": None}),
    ("BURST_CLICK_PATTERN", "Burst click pattern", "VELOCITY", 15, 65,
     "Repeated ad clicks in a short burst with minimal browsing time.",
     {"clicks_30_seconds_gte": 4, "max_session_seconds": 10.0}),
    ("KNOWN_HIGH_RISK_IP", "Known high-risk IP", "REPUTATION", 30, 90,
     "Earlier sessions from this IP scored high risk (decayed average risk of this "
     "organization's past sessions on the IP).",
     {"min_score": 60, "confidence_floor": 50}),
    ("VPN_DETECTED", "VPN detected", "NETWORK", 10, 55, "The session comes from a VPN exit node.", {}),
    ("PROXY_DETECTED", "Proxy detected", "NETWORK", 10, 55, "The session comes through an open or anonymous proxy.", {}),
    ("TOR_DETECTED", "Tor detected", "NETWORK", 10, 55, "The session comes from a Tor exit node.", {}),
    ("DATACENTER_DETECTED", "Datacenter traffic", "NETWORK", 12, 60,
     "The traffic comes from a datacenter or hosting network.", {}),
    ("UNUSUAL_SESSION", "Unusual session", "BEHAVIOR", 18, 60,
     "The session had a very short lifetime and almost no browsing depth.",
     {"max_duration_seconds": 2.0, "max_pages": 1}),
    ("LOW_ENGAGEMENT_WITH_HIGH_CLICKS", "Low engagement with high clicks", "BEHAVIOR", 14, 58,
     "Many clicks without matching page engagement.",
     {"max_pages": 1, "min_clicks": 3, "max_scroll_depth": 20.0}),
    ("BOT_USER_AGENT_DETECTED", "Bot user agent", "AUTOMATION", 18, 65,
     "The user agent matches a known bot, crawler or automated client.",
     {"patterns": ["bot", "crawler", "spider"]}),
]


def upgrade() -> None:
    op.create_table(
        "rules",
        sa.Column("code", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("category", sa.String(length=20), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("weight", sa.Integer(), nullable=False),
        sa.Column("confidence", sa.Integer(), nullable=False),
        sa.Column("params", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("updated_by", sa.UUID(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("code", name=op.f("pk_rules")),
    )
    op.create_table(
        "rule_overrides",
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("rule_code", sa.String(length=64), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=True),
        sa.Column("weight", sa.Integer(), nullable=True),
        sa.Column("params", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("updated_by", sa.UUID(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"],
                                name=op.f("fk_rule_overrides_organization_id_organizations"), ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["rule_code"], ["rules.code"],
                                name=op.f("fk_rule_overrides_rule_code_rules"), ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("organization_id", "rule_code", name=op.f("pk_rule_overrides")),
    )
    _seed(RULES)


def downgrade() -> None:
    op.drop_table("rule_overrides")
    op.drop_table("rules")

"""task 020: HIGH_FRAUD_HISTORY rule

Revision ID: d5e1a7b6f8c9
Revises: c4d0f6a5e7b8
Create Date: 2026-10-08 15:40:00.000000

"""
from __future__ import annotations

from typing import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = "d5e1a7b6f8c9"
down_revision: str | None = "c4d0f6a5e7b8"
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
    ("HIGH_FRAUD_HISTORY", "High fraud history", "REPUTATION", 35, 85,
     "Most of this IP's labelled past sessions were fraud (decayed fraud ratio; client "
     "feedback overrides the system verdict).",
     {"min_sessions": 5, "min_ratio": 0.6, "full_weight": 10.0}),
]


def upgrade() -> None:
    _seed(RULES)


def downgrade() -> None:
    _unseed(RULES)

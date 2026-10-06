"""add fraud model state

Revision ID: 9ab1c3f4d2e6
Revises: 1c9b8e22c81b
Create Date: 2026-09-25 16:00:00.000000

"""
from __future__ import annotations

from typing import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = "9ab1c3f4d2e6"
down_revision: str | None = "1c9b8e22c81b"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "fraud_model_states",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("model_version", sa.String(length=32), nullable=False),
        sa.Column(
            "weights",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("bias", sa.Float(), server_default=sa.text("0"), nullable=False),
        sa.Column("sample_count", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("fraud_samples", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column(
            "legitimate_samples",
            sa.Integer(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column("last_trained_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_fraud_model_states_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_fraud_model_states")),
        sa.UniqueConstraint("organization_id", name=op.f("uq_fraud_model_states_organization_id")),
    )
    op.create_index(
        op.f("ix_fraud_model_states_organization_id"),
        "fraud_model_states",
        ["organization_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_fraud_model_states_organization_id"), table_name="fraud_model_states")
    op.drop_table("fraud_model_states")

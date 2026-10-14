from __future__ import annotations

import uuid

from sqlalchemy import Boolean, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin


class Rule(Base, TimestampMixin):
    """
    Global configuration of one fraud rule (spec §21–22, §57; task 015).
    The rule's logic is code (app/services/rules/evaluators.py, looked up by
    `code`); its numbers are data. `version` increases on every change and is
    stored with each rule result.
    """
    __tablename__ = "rules"

    code: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    category: Mapped[str] = mapped_column(String(20), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    weight: Mapped[int] = mapped_column(Integer, nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, nullable=False)
    params: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    # User id, no foreign key: the rules are reference data that outlives users
    # (the audit log holds who changed what).
    updated_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))


class RuleOverride(Base, TimestampMixin):
    """Per-organization tuning of a rule (Custom mode, spec §54). NULL = use the global value."""
    __tablename__ = "rule_overrides"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        primary_key=True,
    )
    rule_code: Mapped[str] = mapped_column(
        String(64), ForeignKey("rules.code", ondelete="CASCADE"), primary_key=True
    )
    enabled: Mapped[bool | None] = mapped_column(Boolean)
    weight: Mapped[int | None] = mapped_column(Integer)
    # Only the keys that differ from the global params.
    params: Mapped[dict | None] = mapped_column(JSONB)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    # User id, no foreign key: the rules are reference data that outlives users
    # (the audit log holds who changed what).
    updated_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))

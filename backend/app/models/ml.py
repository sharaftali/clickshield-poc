from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin


class FraudModelState(Base, TimestampMixin):
    """Per-organization lightweight fraud model state."""

    __tablename__ = "fraud_model_states"
    __table_args__ = (
        UniqueConstraint("organization_id", name="uq_fraud_model_states_organization_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    model_version: Mapped[str] = mapped_column(
        String(32), nullable=False, default="online-logreg-v1"
    )
    weights: Mapped[dict[str, float]] = mapped_column(JSONB, nullable=False, default=dict)
    bias: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    sample_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    fraud_samples: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    legitimate_samples: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_trained_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    organization = relationship("Organization", back_populates="fraud_model_state")

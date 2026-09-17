from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.models.base import Base, TimestampMixin


class Website(Base, TimestampMixin):
    __tablename__ = "websites"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    domain: Mapped[str] = mapped_column(String(255), nullable=False)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)

    # Tracking token — exposed in JS snippet (spec §8)
    tracking_token: Mapped[str] = mapped_column(
        String(64), unique=True, nullable=False, index=True
    )

    is_verified: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )

    # Consent mode (spec §9)
    require_consent: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )

    organization = relationship("Organization", back_populates="websites")
    sessions = relationship("Session", back_populates="website")

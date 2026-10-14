from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin


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

    # Consent mode (spec §9): the tracker stores and sends nothing before consent (task 024)
    require_consent: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )

    # ---- Task 023 ----
    # Extra hostnames allowed to send events (the domain and its subdomains always are).
    allowed_domains: Mapped[list] = mapped_column(JSONB, default=list, server_default="[]", nullable=False)
    # Reject events whose Origin isn't one of the website's hosts (TRACKING_ENFORCE_ORIGIN).
    enforce_origin: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true", nullable=False)
    # Soft delete: the token stops working, history stays.
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true", nullable=False)
    verification_method: Mapped[str | None] = mapped_column(String(32))  # first_event | snippet | meta_tag
    last_event_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    organization = relationship("Organization", back_populates="websites")
    sessions = relationship("Session", back_populates="website")

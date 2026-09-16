import uuid
from datetime import datetime
from sqlalchemy import (
    String, ForeignKey, Integer, DateTime, Text, UniqueConstraint, Index
)
from sqlalchemy.dialects.postgresql import UUID, INET
from sqlalchemy.orm import Mapped, mapped_column
from app.models.base import Base, TimestampMixin


class Exclusion(Base, TimestampMixin):
    """
    Google Ads IP exclusion record.
    Per spec §40: exclusion manager.
    """
    __tablename__ = "exclusions"
    __table_args__ = (
        # Idempotency: never submit the same IP twice to the same campaign (spec §41)
        UniqueConstraint("organization_id", "campaign_id", "ip_address",
                         name="uq_exclusion_org_campaign_ip"),
        Index("ix_exclusions_org_status", "organization_id", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True
    )
    google_customer_id: Mapped[str] = mapped_column(String(20), nullable=False)
    campaign_id: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    google_campaign_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("google_campaigns.id", ondelete="SET NULL")
    )

    ip_address: Mapped[str] = mapped_column(INET, nullable=False)

    reason: Mapped[str | None] = mapped_column(Text)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    status: Mapped[str] = mapped_column(
        String(20), default="PENDING", nullable=False, index=True
    )  # PENDING | SUBMITTED | ACTIVE | FAILED | REMOVED | SKIPPED

    google_resource_name: Mapped[str | None] = mapped_column(String(255))
    api_request_id: Mapped[str | None] = mapped_column(String(100))

    submitted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    removed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class PlatformAction(Base, TimestampMixin):
    """
    Generic action queue — future-proof for Meta/Microsoft/TikTok (spec §42, §69).
    """
    __tablename__ = "platform_actions"
    __table_args__ = (
        Index("ix_platform_actions_status", "status"),
        Index("ix_platform_actions_org", "organization_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False
    )

    platform: Mapped[str] = mapped_column(String(20), nullable=False)  # GOOGLE | META | ...
    action_type: Mapped[str] = mapped_column(String(50), nullable=False)
    # ADD_IP_EXCLUSION | REMOVE_IP_EXCLUSION | ADD_AUDIENCE_EXCLUSION | ...

    # Reference to the source record (e.g. Exclusion.id)
    reference_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))

    status: Mapped[str] = mapped_column(
        String(20), default="PENDING", nullable=False
    )  # PENDING | PROCESSING | SUCCESS | FAILED | RETRYING

    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_attempts: Mapped[int] = mapped_column(Integer, default=5, nullable=False)

    last_error: Mapped[str | None] = mapped_column(Text)
    scheduled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

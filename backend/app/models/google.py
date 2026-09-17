from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin
from app.models.enums import CampaignStatus, CampaignType


class GoogleConnection(Base, TimestampMixin):
    """
    Stores OAuth credentials for a Google Ads connection.
    Per spec §34–36, §63: never store Google passwords, only encrypted OAuth tokens.
    """
    __tablename__ = "google_connections"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Encrypted refresh token (spec §63)
    refresh_token_encrypted: Mapped[str] = mapped_column(Text, nullable=False)

    # Google Ads customer ID (10-digit, no dashes)
    customer_id: Mapped[str] = mapped_column(String(20), nullable=False)

    # Manager account ID if applicable (spec §35 login-customer-id)
    login_customer_id: Mapped[str | None] = mapped_column(String(20))

    # Google account email (for display only)
    google_account_email: Mapped[str | None] = mapped_column(String(255))

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Track auth expiration
    last_refreshed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    token_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )

    organization = relationship(
        "Organization", back_populates="google_connections"
    )
    campaigns = relationship("GoogleCampaign", back_populates="connection")


class GoogleCampaign(Base, TimestampMixin):
    """
    Discovered campaigns from Google Ads API.
    Per spec §48: campaign view.
    """
    __tablename__ = "google_campaigns"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    connection_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("google_connections.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    campaign_id: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)

    # Campaign type — important per spec §37:
    # PMax/YouTube don't support campaign-level IP exclusion
    campaign_type: Mapped[CampaignType] = mapped_column(
        Enum(CampaignType, name="campaign_type_enum"),
        default=CampaignType.SEARCH,
        nullable=False,
    )

    status: Mapped[CampaignStatus] = mapped_column(
        Enum(CampaignStatus, name="campaign_status_enum"),
        default=CampaignStatus.ENABLED,
        nullable=False,
    )

    # Protection toggle per campaign (spec §48)
    protection_enabled: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )

    # Cached count for exclusion capacity tracking (spec §39)
    exclusion_count: Mapped[int] = mapped_column(
        BigInteger, default=0, nullable=False
    )

    connection = relationship(
        "GoogleConnection", back_populates="campaigns"
    )

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Integer,
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

    # Set when Google rejects the refresh token (revoked/expired grant).
    # Protection actions fail until the user reconnects (spec §43, §66).
    needs_reauth: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false", nullable=False
    )
    auth_error: Mapped[str | None] = mapped_column(Text)

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

    # Click Shield exclusions holding a slot (PENDING/SUBMITTED/ACTIVE); kept in
    # sync by app/services/exclusion_capacity.py (spec §39).
    exclusion_count: Mapped[int] = mapped_column(
        BigInteger, default=0, nullable=False
    )
    # IP exclusions the advertiser added in Google Ads themselves; read during
    # campaign sync. They use the same per-campaign limit.
    external_exclusion_count: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0", nullable=False
    )
    # campaign.geo_target_type_setting.positive_geo_target_type: PRESENCE or
    # PRESENCE_OR_INTEREST (Google's default). Task 018.
    geo_target_type: Mapped[str | None] = mapped_column(String(32))

    connection = relationship(
        "GoogleConnection", back_populates="campaigns"
    )
    locations = relationship(
        "GoogleCampaignLocation", back_populates="campaign", cascade="all, delete-orphan"
    )


class GoogleCampaignLocation(Base, TimestampMixin):
    """A campaign's location target (positive or negative), resolved to country /
    region, read during campaign sync (spec §18, task 018)."""
    __tablename__ = "google_campaign_locations"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    campaign_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("google_campaigns.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    criterion_id: Mapped[str] = mapped_column(String(32), nullable=False)
    criterion_type: Mapped[str] = mapped_column(String(16), nullable=False)  # LOCATION | PROXIMITY
    geo_target_constant: Mapped[str | None] = mapped_column(String(64))
    country_code: Mapped[str | None] = mapped_column(String(2))
    region: Mapped[str | None] = mapped_column(String(100))
    name: Mapped[str | None] = mapped_column(String(255))
    target_type: Mapped[str | None] = mapped_column(String(32))  # Country, State, City, …
    negative: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    campaign = relationship("GoogleCampaign", back_populates="locations")

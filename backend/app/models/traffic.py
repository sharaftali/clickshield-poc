from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin
from app.models.enums import ClientVerdict, EventType, Verdict


class Visitor(Base, TimestampMixin):
    """
    Visitor identity — persists across sessions.
    Per spec §12: Visitor ID.
    """
    __tablename__ = "visitors"
    __table_args__ = (
        # A visitor_token must be unique per website.
        # Prevents duplicate rows from race conditions or replay.
        UniqueConstraint(
            "website_id", "visitor_token",
            name="uq_visitors_website_token",
        ),
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
    website_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("websites.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Client-side generated visitor identifier (from JS)
    visitor_token: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )

    # Primary IP seen (last known)
    ip_address: Mapped[str | None] = mapped_column(INET)

    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    total_sessions: Mapped[int] = mapped_column(
        Integer, default=0, nullable=False
    )

    sessions = relationship("Session", back_populates="visitor")


class Session(Base, TimestampMixin):
    """
    Session record — one per paid visitor session.
    Per spec §12: full session fields.
    """
    __tablename__ = "sessions"
    __table_args__ = (
        Index("ix_sessions_org_created", "organization_id", "created_at"),
        # ix_sessions_ip removed — duplicate of ix_sessions_ip_address
        # which is auto-created via index=True on the column.
        # Ad-click velocity lookups across sessions (spec §16)
        Index("ix_sessions_org_ip_ad_landing", "organization_id", "ip_address", "ad_landing_at"),
        Index("ix_sessions_visitor_ad_landing", "visitor_id", "ad_landing_at"),
        # IP reputation history: this org's other sessions on an IP (spec §14)
        Index("ix_sessions_org_ip_created", "organization_id", "ip_address", "created_at"),
        # Repeat-visitor lookups by coarse device key (task 019)
        Index("ix_sessions_org_device_ad_landing", "organization_id", "device_key", "ad_landing_at"),
        # Campaign traffic statistics / anomaly detection (task 022)
        Index("ix_sessions_campaign_ad_landing", "google_campaign_id", "ad_landing_at"),
        # Review queue: FLAG sessions (task 017)
        Index("ix_sessions_org_verdict_created", "organization_id", "verdict", "created_at"),
        # Browser-generated session tokens are only unique within a website (spec §58).
        UniqueConstraint("website_id", "session_token", name="uq_sessions_website_token"),
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
    website_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("websites.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    visitor_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("visitors.id", ondelete="SET NULL"),
        index=True,
    )

    # Client-side generated session identifier (unique per website, see __table_args__)
    session_token: Mapped[str] = mapped_column(String(64), nullable=False)

    # ---- Attribution (spec §10) ----
    gclid: Mapped[str | None] = mapped_column(String(255), index=True)
    utm_source: Mapped[str | None] = mapped_column(String(100))
    utm_medium: Mapped[str | None] = mapped_column(String(100))
    utm_campaign: Mapped[str | None] = mapped_column(String(255))
    utm_term: Mapped[str | None] = mapped_column(String(255))
    utm_content: Mapped[str | None] = mapped_column(String(255))
    landing_page: Mapped[str | None] = mapped_column(Text)
    referrer: Mapped[str | None] = mapped_column(Text)

    # Link to discovered Google campaign (nullable — matched by UTM/campaign name)
    google_campaign_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("google_campaigns.id", ondelete="SET NULL"),
        index=True,
    )

    # ---- IP Intelligence (spec §13) ----
    ip_address: Mapped[str | None] = mapped_column(INET, index=True)
    country: Mapped[str | None] = mapped_column(String(2))
    region: Mapped[str | None] = mapped_column(String(100))
    city: Mapped[str | None] = mapped_column(String(100))
    asn: Mapped[str | None] = mapped_column(String(50))
    isp: Mapped[str | None] = mapped_column(String(255))
    is_vpn: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_proxy: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_tor: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_datacenter: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # ---- Technical signals (spec §19) ----
    device: Mapped[str | None] = mapped_column(String(50))  # desktop | mobile | tablet
    browser: Mapped[str | None] = mapped_column(String(50))
    os: Mapped[str | None] = mapped_column(String(50))
    language: Mapped[str | None] = mapped_column(String(20))
    timezone: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(Text)
    # sha256 of coarse browser/OS/screen/timezone/language, salted per organization
    # (spec §17, §19: aggregated, no raw fingerprint stored). Task 019.
    device_key: Mapped[str | None] = mapped_column(String(64))

    # ---- Behavioral signals (spec §15) ----
    session_duration_seconds: Mapped[float] = mapped_column(
        Float, default=0.0, nullable=False
    )
    page_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    # On-page DOM clicks (engagement signal). NOT ad clicks — those are counted
    # by the velocity columns below.
    click_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    # Real interactions only (click, scroll, form, phone, outbound, conversion).
    interaction_count: Mapped[int] = mapped_column(
        Integer, default=0, nullable=False
    )
    scroll_depth: Mapped[float] = mapped_column(
        Float, default=0.0, nullable=False
    )

    # ---- Click velocity (spec §16) ----
    # Server time at which this session landed from a paid ad click (gclid /
    # Google Ads UTM / ad_landing event). NULL for non-paid sessions.
    ad_landing_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Paid ad landings from the same IP or visitor (whichever is higher) within
    # each window, counted across sessions at landing time; one per gclid.
    clicks_10_seconds: Mapped[int] = mapped_column(
        Integer, default=0, nullable=False
    )
    clicks_30_seconds: Mapped[int] = mapped_column(
        Integer, default=0, nullable=False
    )
    clicks_60_seconds: Mapped[int] = mapped_column(
        Integer, default=0, nullable=False
    )
    clicks_5_minutes: Mapped[int] = mapped_column(
        Integer, default=0, nullable=False
    )
    clicks_1_hour: Mapped[int] = mapped_column(
        Integer, default=0, nullable=False
    )
    clicks_24_hours: Mapped[int] = mapped_column(
        Integer, default=0, nullable=False
    )

    # ---- Click timing (spec §16, §20, task 021) ----
    # Intervals between this source's paid ad landings (last 24h, visitor / IP / device
    # key with the most landings). NULL with fewer than INTERVAL_MIN_SAMPLES intervals.
    ad_click_interval_avg_s: Mapped[float | None] = mapped_column(Float)
    ad_click_interval_min_s: Mapped[float | None] = mapped_column(Float)
    ad_click_interval_var: Mapped[float | None] = mapped_column(Float)
    ad_click_interval_cv: Mapped[float | None] = mapped_column(Float)
    # Intervals between on-page actions (clicks, forms, …; not scroll) in this session.
    event_interval_avg_ms: Mapped[float | None] = mapped_column(Float)
    event_interval_min_ms: Mapped[float | None] = mapped_column(Float)
    event_interval_var: Mapped[float | None] = mapped_column(Float)
    event_interval_cv: Mapped[float | None] = mapped_column(Float)

    # ---- Scoring (spec §24, §27, §28) ----
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    confidence_score: Mapped[int] = mapped_column(
        Integer, default=0, nullable=False
    )
    # LOW / MODERATE / HIGH / VERY_HIGH from risk_score (task 017)
    risk_band: Mapped[str] = mapped_column(
        String(16), default="LOW", server_default="LOW", nullable=False
    )
    # Independent rule categories with a meaningful contribution (task 014)
    signal_diversity: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0", nullable=False
    )
    # {category: contribution} after diminishing returns
    risk_categories: Mapped[dict | None] = mapped_column(JSONB)
    # Aggregation used (SCORING_VERSION); NULL for sessions scored before task 014
    scoring_version: Mapped[int | None] = mapped_column(Integer)

    verdict: Mapped[Verdict] = mapped_column(
        Enum(Verdict, name="verdict_enum"),
        default=Verdict.SAFE,
        nullable=False,
        index=True,
    )

    # ---- Feedback (spec §50) ----
    system_verdict: Mapped[Verdict] = mapped_column(
        Enum(Verdict, name="verdict_enum"),
        nullable=False,
    )
    client_verdict: Mapped[ClientVerdict | None] = mapped_column(
        Enum(ClientVerdict, name="client_verdict_enum"),
        nullable=True,
    )
    final_label: Mapped[Verdict | None] = mapped_column(
        Enum(Verdict, name="verdict_enum"),
        nullable=True,
    )

    # Extensible raw signals blob (useful for ML later, spec §30)
    extra_signals: Mapped[dict | None] = mapped_column(JSONB)

    website = relationship("Website", back_populates="sessions")
    visitor = relationship("Visitor", back_populates="sessions")
    events = relationship("Event", back_populates="session")
    fraud_events = relationship("FraudEvent", back_populates="session")


class Event(Base, TimestampMixin):
    """
    Individual visitor events.
    Per spec §11: event model.
    """
    __tablename__ = "events"
    __table_args__ = (
        Index("ix_events_session_created", "session_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sessions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    event_type: Mapped[EventType] = mapped_column(
        Enum(EventType, name="event_type_enum"),
        nullable=False,
    )

    page_url: Mapped[str | None] = mapped_column(Text)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    # Arbitrary event payload
    payload: Mapped[dict | None] = mapped_column(JSONB)

    session = relationship("Session", back_populates="events")

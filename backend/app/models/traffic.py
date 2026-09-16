import uuid
from datetime import datetime
from sqlalchemy import (
    String, ForeignKey, Integer, Float, DateTime, Text, Boolean, BigInteger, Index
)
from sqlalchemy.dialects.postgresql import UUID, INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import Base, TimestampMixin


class Visitor(Base, TimestampMixin):
    """
    Visitor identity — persists across sessions.
    Per spec §12: Visitor ID.
    """
    __tablename__ = "visitors"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True
    )
    website_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("websites.id", ondelete="CASCADE"),
        nullable=False, index=True
    )

    # Client-side generated visitor identifier (from JS)
    visitor_token: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    # Primary IP seen (last known)
    ip_address: Mapped[str | None] = mapped_column(INET)

    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    total_sessions: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    sessions = relationship("Session", back_populates="visitor")


class Session(Base, TimestampMixin):
    """
    Session record — one per paid visitor session.
    Per spec §12: full session fields.
    """
    __tablename__ = "sessions"
    __table_args__ = (
        Index("ix_sessions_org_created", "organization_id", "created_at"),
        Index("ix_sessions_ip", "ip_address"),
        Index("ix_sessions_verdict", "verdict"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True
    )
    website_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("websites.id", ondelete="CASCADE"),
        nullable=False, index=True
    )
    visitor_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("visitors.id", ondelete="SET NULL"),
        index=True
    )

    # Client-side generated session identifier
    session_token: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

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
        UUID(as_uuid=True), ForeignKey("google_campaigns.id", ondelete="SET NULL"),
        index=True
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
    device: Mapped[str | None] = mapped_column(String(50))       # desktop | mobile | tablet
    browser: Mapped[str | None] = mapped_column(String(50))
    os: Mapped[str | None] = mapped_column(String(50))
    language: Mapped[str | None] = mapped_column(String(20))
    timezone: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(Text)

    # ---- Behavioral signals (spec §15) ----
    session_duration_seconds: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    page_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    click_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    interaction_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    scroll_depth: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    # ---- Click velocity (spec §16) ----
    clicks_10_seconds: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    clicks_30_seconds: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    clicks_60_seconds: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    clicks_5_minutes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    clicks_1_hour: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    clicks_24_hours: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # ---- Scoring (spec §24, §28) ----
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    confidence_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    verdict: Mapped[str] = mapped_column(
        String(20), default="SAFE", nullable=False, index=True
    )  # SAFE | MONITOR | FLAG | FRAUD

    # ---- Feedback (spec §50) ----
    system_verdict: Mapped[str] = mapped_column(String(20), nullable=False)
    client_verdict: Mapped[str | None] = mapped_column(String(20))  # legitimate | fraud
    final_label: Mapped[str | None] = mapped_column(String(20))

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
        UUID(as_uuid=True), ForeignKey("sessions.id", ondelete="CASCADE"),
        nullable=False, index=True
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True
    )

    event_type: Mapped[str] = mapped_column(String(50), nullable=False)
    # ad_landing | page_view | scroll | click | form_start | form_submit |
    # phone_click | outbound_click | session_start | session_end | conversion

    page_url: Mapped[str | None] = mapped_column(Text)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # Arbitrary event payload
    payload: Mapped[dict | None] = mapped_column(JSONB)

    session = relationship("Session", back_populates="events")

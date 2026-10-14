from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin


class CampaignTrafficStat(Base, TimestampMixin):
    """Hourly paid-traffic statistics per campaign (spec §31, task 022)."""
    __tablename__ = "campaign_traffic_stats"

    google_campaign_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("google_campaigns.id", ondelete="CASCADE"),
        primary_key=True,
    )
    hour_bucket: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    ad_landings: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    distinct_ips: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    distinct_visitors: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    fraud_sessions: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    median_click_interval_s: Mapped[float | None] = mapped_column(Float)


class TrafficAnomaly(Base, TimestampMixin):
    """A campaign hour that deviates from its robust baseline (median / MAD)."""
    __tablename__ = "traffic_anomalies"
    __table_args__ = (
        UniqueConstraint("google_campaign_id", "metric", "window_start", name="uq_traffic_anomalies_window"),
        Index("ix_traffic_anomalies_org_window", "organization_id", "window_start"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    google_campaign_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("google_campaigns.id", ondelete="CASCADE"), nullable=False
    )
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # ad_landings (spike), median_click_interval (sudden fast clicking), ad_landings_drop
    metric: Mapped[str] = mapped_column(String(40), nullable=False)
    observed: Mapped[float] = mapped_column(Float, nullable=False)
    expected: Mapped[float] = mapped_column(Float, nullable=False)
    score: Mapped[float] = mapped_column(Float, nullable=False)   # robust z (signed towards "suspicious")
    level: Mapped[str] = mapped_column(String(10), nullable=False)  # MEDIUM | HIGH

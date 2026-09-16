import uuid
from datetime import datetime
from sqlalchemy import (
    String, ForeignKey, Integer, Float, DateTime, Text, Boolean, Index
)
from sqlalchemy.dialects.postgresql import UUID, INET
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import Base, TimestampMixin


class IPReputation(Base, TimestampMixin):
    """
    Internal IP reputation layer.
    Per spec §14: historical reputation influences risk but is never the sole reason.
    """
    __tablename__ = "ip_reputation"

    ip: Mapped[str] = mapped_column(INET, primary_key=True)

    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Cached IP intelligence
    country: Mapped[str | None] = mapped_column(String(2))
    asn: Mapped[str | None] = mapped_column(String(50))
    isp: Mapped[str | None] = mapped_column(String(255))
    is_vpn: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_proxy: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_tor: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_datacenter: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Counters
    total_sessions: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    fraud_sessions: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    legitimate_sessions: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    blocked_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class FraudEvent(Base, TimestampMixin):
    """
    Explains why a session was flagged.
    Per spec §21–22: rule engine output.
    Per spec §33: every blocked event must explain why.
    """
    __tablename__ = "fraud_events"
    __table_args__ = (
        Index("ix_fraud_events_session", "session_id"),
        Index("ix_fraud_events_org_created", "organization_id", "created_at"),
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

    # Rule identity (spec §21)
    rule_name: Mapped[str] = mapped_column(String(100), nullable=False)
    # e.g. ABNORMAL_CLICK_VELOCITY, HIGH_RISK_IP_REPUTATION, VPN_PROXY_DETECTED, ...

    reason_code: Mapped[str] = mapped_column(String(100), nullable=False)
    reason_text: Mapped[str | None] = mapped_column(Text)

    # Contribution to final risk score
    score_contribution: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Rule-level confidence (0-100)
    rule_confidence: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    triggered: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    session = relationship("Session", back_populates="fraud_events")

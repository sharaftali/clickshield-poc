from __future__ import annotations

import uuid

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin
from app.models.enums import ProtectionMode, UserRole


class Organization(Base, TimestampMixin):
    __tablename__ = "organizations"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # POC: protection mode per organization (Phase 1 spec §54)
    protection_mode: Mapped[ProtectionMode] = mapped_column(
        Enum(ProtectionMode, name="protection_mode_enum"),
        default=ProtectionMode.BALANCED,
        nullable=False,
    )
    # Custom mode thresholds (task 016): flag_risk, fraud_risk, fraud_confidence,
    # min_diversity, auto_exclude. Ignored by the other modes.
    protection_settings: Mapped[dict | None] = mapped_column(JSONB)

    # IANA timezone for "today", by-day and by-hour reporting (task 025)
    timezone: Mapped[str] = mapped_column(String(64), default="UTC", server_default="UTC", nullable=False)

    # Data retention overrides (task 029); NULL = the platform default setting
    raw_events_retention_days: Mapped[int | None] = mapped_column(Integer)
    sessions_retention_days: Mapped[int | None] = mapped_column(Integer)
    fraud_session_retention_days: Mapped[int | None] = mapped_column(Integer)

    # Relationships
    users = relationship("User", back_populates="organization")
    websites = relationship("Website", back_populates="organization")
    google_connections = relationship(
        "GoogleConnection", back_populates="organization"
    )


class User(Base, TimestampMixin):
    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("email"),
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
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str | None] = mapped_column(String(255))

    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole, name="user_role_enum"),
        default=UserRole.OWNER,
        nullable=False,
    )

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Click Shield staff (task 027). Granted only with `python -m app.cli grant-platform-admin`,
    # never through the public API.
    is_platform_admin: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false", nullable=False
    )
    # Alert emails on/off (task 028)
    alert_emails: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true", nullable=False)

    organization = relationship("Organization", back_populates="users")


class OrganizationInvitation(Base, TimestampMixin):
    """An emailed invitation to join an organization with a role (task 030).
    Only the sha256 of the invite token is stored."""
    __tablename__ = "organization_invitations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(Enum(UserRole, name="user_role_enum"), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    invited_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))

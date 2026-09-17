from __future__ import annotations

import uuid

from sqlalchemy import Enum, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.models.base import Base, TimestampMixin
from backend.app.models.enums import AuditResult


class AuditLog(Base, TimestampMixin):
    """
    Every automated action recorded.
    Per spec §44, §62.
    """
    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_logs_org_created", "organization_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="SET NULL"),
        index=True,
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
    )

    action: Mapped[str] = mapped_column(String(100), nullable=False)
    # ADD_IP_EXCLUSION | REMOVE_IP_EXCLUSION | CONNECT_GOOGLE | SELECT_CAMPAIGN | ...

    resource_type: Mapped[str | None] = mapped_column(String(50))
    resource_id: Mapped[str | None] = mapped_column(String(100))

    # Context
    ip_address: Mapped[str | None] = mapped_column(INET)
    details: Mapped[dict | None] = mapped_column(JSONB)

    result: Mapped[AuditResult] = mapped_column(
        Enum(AuditResult, name="audit_result_enum"),
        nullable=False,
    )

    error_message: Mapped[str | None] = mapped_column(Text)
    google_request_id: Mapped[str | None] = mapped_column(String(100))

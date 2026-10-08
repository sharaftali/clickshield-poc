from __future__ import annotations

import uuid
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Any

from pydantic import BaseModel, ConfigDict, field_validator

from app.models.enums import AuditResult


class AuditLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    created_at: datetime
    action: str
    result: AuditResult
    user_id: uuid.UUID | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    ip_address: str | None = None
    details: dict[str, Any] | None = None
    error_message: str | None = None
    google_request_id: str | None = None

    @field_validator("ip_address", mode="before")
    @classmethod
    def normalize_ip(cls, value: str | IPv4Address | IPv6Address | None) -> str | None:
        return None if value is None else str(value)


class AuditLogPage(BaseModel):
    items: list[AuditLogOut]
    total: int
    limit: int
    offset: int

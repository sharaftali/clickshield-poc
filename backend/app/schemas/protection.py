from __future__ import annotations

import uuid

from ipaddress import IPv4Address, IPv6Address

from pydantic import BaseModel, ConfigDict, field_validator

from app.models.enums import ExclusionStatus


class ProtectionExclusionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    google_customer_id: str
    campaign_id: str
    google_campaign_id: uuid.UUID | None = None
    ip_address: str
    reason: str | None = None
    risk_score: int
    confidence: int
    status: ExclusionStatus
    google_resource_name: str | None = None
    api_request_id: str | None = None

    @field_validator("ip_address", mode="before")
    @classmethod
    def normalize_ip(cls, value: str | IPv4Address | IPv6Address | None) -> str | None:
        if value is None:
            return None
        return str(value)


class ProtectionQueueSummary(BaseModel):
    queued: int
    processed: int
    successful: int
    failed: int
    skipped: int = 0

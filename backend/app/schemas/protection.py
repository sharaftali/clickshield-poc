from __future__ import annotations

import uuid
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address

from pydantic import BaseModel, ConfigDict, field_validator

from app.models.enums import ActionStatus, ActionType, ExclusionStatus


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
    last_error: str | None = None
    overflow: bool = False
    last_fraud_at: datetime | None = None

    @field_validator("ip_address", mode="before")
    @classmethod
    def normalize_ip(cls, value: str | IPv4Address | IPv6Address | None) -> str | None:
        if value is None:
            return None
        return str(value)


class ProtectionQueueStatus(BaseModel):
    """Read-only view of the automatic protection pipeline (task 010)."""

    auto_protection_enabled: bool
    dry_run: bool
    pending: int
    processing: int
    retrying: int
    failed: int
    succeeded: int
    active_exclusions: int
    overflow_exclusions: int


class ProtectionActionResponse(BaseModel):
    id: uuid.UUID
    action_type: ActionType
    status: ActionStatus
    attempts: int
    max_attempts: int
    last_error: str | None = None
    scheduled_at: datetime | None = None
    completed_at: datetime | None = None
    updated_at: datetime
    ip_address: str | None = None
    campaign_id: str | None = None

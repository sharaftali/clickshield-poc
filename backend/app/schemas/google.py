from __future__ import annotations

import re
import uuid

from ipaddress import IPv4Address, IPv6Address

from pydantic import BaseModel, ConfigDict, Field, field_validator


class GoogleAccountOut(BaseModel):
    """A Google Ads account accessible via OAuth."""

    customer_id: str = Field(..., min_length=10, max_length=20)
    descriptive_name: str | None = None
    is_manager: bool = False
    is_test_account: bool = False
    currency_code: str | None = None
    time_zone: str | None = None

    @field_validator("customer_id")
    @classmethod
    def validate_customer_id(cls, value: str) -> str:
        cleaned = value.strip()
        if not re.fullmatch(r"\d+", cleaned):
            raise ValueError("customer_id must contain only digits")
        return cleaned


class GoogleConnectionOut(BaseModel):
    id: uuid.UUID
    customer_id: str
    login_customer_id: str | None
    google_account_email: str | None
    is_active: bool

    model_config = ConfigDict(from_attributes=True)


class SelectCustomerIn(BaseModel):
    customer_id: str = Field(..., min_length=10, max_length=20)
    login_customer_id: str | None = Field(default=None, min_length=10, max_length=20)
    google_account_email: str | None = Field(default=None, max_length=255)

    @field_validator("customer_id", "login_customer_id")
    @classmethod
    def validate_customer_id(cls, value: str | None) -> str | None:
        if value is None:
            return value
        cleaned = value.strip()
        if not re.fullmatch(r"\d+", cleaned):
            raise ValueError("Google customer IDs must contain only digits")
        return cleaned


class CampaignOut(BaseModel):
    id: uuid.UUID
    campaign_id: str
    name: str
    campaign_type: str
    status: str
    protection_enabled: bool
    exclusion_count: int
    supports_ip_exclusion: bool = True

    model_config = ConfigDict(from_attributes=True)


class CampaignSyncSummary(BaseModel):
    synced: int
    created: int
    updated: int
    removed: int


class UpdateCampaignProtectionIn(BaseModel):
    protection_enabled: bool


class ExclusionIn(BaseModel):
    campaign_id: str
    ip_address: str
    reason: str | None = None
    risk_score: int = 0
    confidence: int = 0

    @field_validator("ip_address", mode="before")
    @classmethod
    def normalize_ip(cls, value: str | IPv4Address | IPv6Address | None) -> str | None:
        if value is None:
            return None
        return str(value)


class ExclusionOut(BaseModel):
    id: uuid.UUID
    campaign_id: str
    ip_address: str
    status: str
    google_resource_name: str | None
    api_request_id: str | None

    model_config = ConfigDict(from_attributes=True)

    @field_validator("ip_address", mode="before")
    @classmethod
    def normalize_ip(cls, value: str | IPv4Address | IPv6Address | None) -> str | None:
        if value is None:
            return None
        return str(value)

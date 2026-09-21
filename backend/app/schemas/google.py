from __future__ import annotations

import uuid

from pydantic import BaseModel


class GoogleAccountOut(BaseModel):
    """A Google Ads account accessible via OAuth."""
    customer_id: str
    descriptive_name: str | None = None
    is_manager: bool = False
    is_test_account: bool = False
    currency_code: str | None = None
    time_zone: str | None = None


class GoogleConnectionOut(BaseModel):
    id: uuid.UUID
    customer_id: str
    login_customer_id: str | None
    google_account_email: str | None
    is_active: bool

    model_config = {"from_attributes": True}


class SelectCustomerIn(BaseModel):
    customer_id: str
    login_customer_id: str | None = None
    google_account_email: str | None = None


class CampaignOut(BaseModel):
    id: uuid.UUID
    campaign_id: str
    name: str
    campaign_type: str
    status: str
    protection_enabled: bool
    exclusion_count: int

    model_config = {"from_attributes": True}


class ExclusionIn(BaseModel):
    campaign_id: str
    ip_address: str
    reason: str | None = None
    risk_score: int = 0
    confidence: int = 0


class ExclusionOut(BaseModel):
    id: uuid.UUID
    campaign_id: str
    ip_address: str
    status: str
    google_resource_name: str | None
    api_request_id: str | None

    model_config = {"from_attributes": True}

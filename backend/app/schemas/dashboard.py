from __future__ import annotations

import uuid
from datetime import datetime

from ipaddress import IPv4Address, IPv6Address

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.enums import Verdict


class DashboardOverview(BaseModel):
    total_sessions: int = Field(default=0, ge=0)
    suspicious_sessions: int = Field(default=0, ge=0)
    fraud_sessions: int = Field(default=0, ge=0)
    protected_ips: int = Field(default=0, ge=0)
    average_risk_score: float = Field(default=0.0, ge=0)
    high_confidence_traffic: int = Field(default=0, ge=0)


class DashboardSessionSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    created_at: datetime
    verdict: Verdict
    risk_score: int
    confidence_score: int
    ip_address: str | None = None
    device: str | None = None
    browser: str | None = None
    landing_page: str | None = None
    page_count: int = 0
    click_count: int = 0
    is_vpn: bool = False
    is_proxy: bool = False

    @field_validator("ip_address", mode="before")
    @classmethod
    def normalize_ip(cls, value: str | IPv4Address | IPv6Address | None) -> str | None:
        if value is None:
            return None
        return str(value)


class DashboardFraudEvent(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    session_id: uuid.UUID
    rule_name: str
    reason_code: str
    reason_text: str | None = None
    score_contribution: int
    rule_confidence: int
    triggered: bool
    created_at: datetime


class DashboardTopIP(BaseModel):
    ip: str
    risk_score: int
    confidence: int
    total_sessions: int
    fraud_sessions: int

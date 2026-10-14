from __future__ import annotations

import uuid
from datetime import datetime

from ipaddress import IPv4Address, IPv6Address

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.enums import ClientVerdict, Verdict


class DashboardOverview(BaseModel):
    total_sessions: int = Field(default=0, ge=0)
    suspicious_sessions: int = Field(default=0, ge=0)
    fraud_sessions: int = Field(default=0, ge=0)
    review_sessions: int = Field(default=0, ge=0)   # FLAG without client feedback
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
    risk_band: str = "LOW"
    signal_diversity: int = 0
    risk_categories: dict[str, int] | None = None
    scoring_version: int | None = None
    ip_address: str | None = None
    country: str | None = None
    device: str | None = None
    browser: str | None = None
    landing_page: str | None = None
    page_count: int = 0
    click_count: int = 0
    is_vpn: bool = False
    is_proxy: bool = False
    is_tor: bool = False
    is_datacenter: bool = False
    session_duration_seconds: float = 0.0
    clicks_60_seconds: int = 0
    ad_click_interval_cv: float | None = None
    event_interval_min_ms: float | None = None
    client_verdict: ClientVerdict | None = None
    final_label: Verdict | None = None

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
    category: str | None = None
    rule_version: int | None = None
    created_at: datetime


class DashboardTopIP(BaseModel):
    ip: str
    risk_score: int
    confidence: int
    total_sessions: int
    fraud_sessions: int


class SessionFeedbackIn(BaseModel):
    client_verdict: ClientVerdict


class DashboardAnomaly(BaseModel):
    id: uuid.UUID
    campaign_name: str
    campaign_id: str
    window_start: datetime
    window_end: datetime
    metric: str
    observed: float
    expected: float
    score: float
    level: str

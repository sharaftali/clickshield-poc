from __future__ import annotations

import uuid
from datetime import datetime

from ipaddress import IPv4Address, IPv6Address

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.enums import ClientVerdict, Verdict


class DashboardOverview(BaseModel):
    """Spec §46. Counts cover `range` in the organization's timezone (task 025)."""
    range: str = "today"
    timezone: str = "UTC"
    protection_status: str = "SETUP_REQUIRED"         # ACTIVE | SETUP_REQUIRED
    protection_missing: list[str] = []
    clicks: int = Field(default=0, ge=0)              # paid ad landings
    total_sessions: int = Field(default=0, ge=0)
    suspicious_sessions: int = Field(default=0, ge=0)
    fraud_sessions: int = Field(default=0, ge=0)      # client feedback overrides the system verdict
    fraud_rate: float = Field(default=0.0, ge=0)
    review_sessions: int = Field(default=0, ge=0)     # FLAG without client feedback (all time)
    protected_ips: int = Field(default=0, ge=0)       # ACTIVE exclusions (now)
    average_risk_score: float = Field(default=0.0, ge=0)
    high_confidence_traffic: int = Field(default=0, ge=0)
    connected_websites: int = Field(default=0, ge=0)
    connected_google_accounts: int = Field(default=0, ge=0)
    protected_campaigns: int = Field(default=0, ge=0)


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


class SessionReason(BaseModel):
    code: str
    category: str | None = None
    description: str | None = None
    contribution: int
    confidence: int


class SessionEventOut(BaseModel):
    event_type: str
    page_url: str | None = None
    timestamp: datetime
    payload: dict | None = None


class ExclusionTimelineEntry(BaseModel):
    at: datetime
    action: str
    result: str
    google_request_id: str | None = None
    error: str | None = None


class SessionExclusion(BaseModel):
    id: uuid.UUID
    campaign_id: str
    status: str
    google_resource_name: str | None = None
    api_request_id: str | None = None
    last_error: str | None = None
    created_at: datetime
    timeline: list[ExclusionTimelineEntry]


class SessionDetail(BaseModel):
    """Spec §49 fraud event details + §33 explanation (task 026)."""
    id: uuid.UUID
    created_at: datetime
    verdict: Verdict
    system_verdict: Verdict
    client_verdict: ClientVerdict | None = None
    final_label: Verdict | None = None
    risk_score: int
    confidence_score: int
    risk_band: str
    signal_diversity: int
    risk_categories: dict[str, int] | None = None
    explanation: str
    source: str                       # paid | organic | direct
    campaign_name: str | None = None
    campaign_id: str | None = None
    google_campaign_id: uuid.UUID | None = None
    ad_group_id: str | None = None
    keyword: str | None = None
    match_type: str | None = None
    gclid_present: bool = False
    utm_source: str | None = None
    utm_campaign: str | None = None
    ip_address: str | None = None
    country: str | None = None
    region: str | None = None
    city: str | None = None
    asn: str | None = None
    isp: str | None = None
    is_vpn: bool
    is_proxy: bool
    is_tor: bool
    is_datacenter: bool
    device: str | None = None
    browser: str | None = None
    os: str | None = None
    language: str | None = None
    timezone: str | None = None
    landing_page: str | None = None
    referrer: str | None = None
    clicks: dict[str, int]
    session_duration_seconds: float
    page_count: int
    click_count: int
    interaction_count: int
    scroll_depth: float
    reasons: list[SessionReason]
    events: list[SessionEventOut]
    events_truncated: bool
    exclusions: list[SessionExclusion]

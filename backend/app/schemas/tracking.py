from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, BeforeValidator, Field, model_validator


def _without_nul(value: Any) -> Any:
    """PostgreSQL text and JSONB reject U+0000: drop it from every string, keys included."""
    if isinstance(value, str):
        return value.replace("\x00", "")
    if isinstance(value, dict):
        return {_without_nul(k): _without_nul(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_without_nul(v) for v in value]
    return value


def _truncate(length: int):
    """Attribution values longer than their column are cut, not rejected: a long UTM value
    must not lose the whole visit."""
    def cut(value: Any) -> Any:
        return value[:length] if isinstance(value, str) else value
    return BeforeValidator(cut)


class TrackingEventIn(BaseModel):
    """Single event sent from the JS tracking script."""
    site_token: str = Field(..., min_length=8, max_length=64)
    visitor_token: str = Field(..., min_length=8, max_length=64)
    session_token: str = Field(..., min_length=8, max_length=64)
    event_type: str = Field(..., max_length=50)
    page_url: str | None = None
    timestamp: datetime
    # Attribution
    gclid: str | None = Field(default=None, max_length=255)
    gbraid: str | None = Field(default=None, max_length=255)
    wbraid: str | None = Field(default=None, max_length=255)
    campaign_id: str | None = Field(default=None, max_length=50)
    # ValueTrack parameters (task 024)
    adgroup_id: str | None = Field(default=None, max_length=50)
    keyword: str | None = Field(default=None, max_length=255)
    matchtype: str | None = Field(default=None, max_length=20)
    # Lengths of the sessions columns
    utm_source: Annotated[str | None, _truncate(100)] = None
    utm_medium: Annotated[str | None, _truncate(100)] = None
    utm_campaign: Annotated[str | None, _truncate(255)] = None
    utm_term: Annotated[str | None, _truncate(255)] = None
    utm_content: Annotated[str | None, _truncate(255)] = None
    language: str | None = Field(default=None, max_length=20)
    timezone: str | None = Field(default=None, max_length=64)
    referrer: str | None = None
    # Behavioral payload (scroll depth, click coords, etc.)
    payload: dict[str, Any] | None = None

    @model_validator(mode="before")
    @classmethod
    def strip_nul(cls, data: Any) -> Any:
        return _without_nul(data)


class TrackingBatchIn(BaseModel):
    """Batch of events — JS can send several at once."""
    events: list[TrackingEventIn] = Field(..., min_length=1, max_length=50)


class TrackingResponse(BaseModel):
    # "verified": the website's first event verified it (task 023); nothing was scored.
    status: Literal["ok", "verified", "error"]
    session_id: uuid.UUID | None = None
    risk_score: int = 0
    confidence_score: int = 0
    verdict: str = "SAFE"
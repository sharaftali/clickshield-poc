from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


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
    utm_source: str | None = None
    utm_medium: str | None = None
    utm_campaign: str | None = None
    utm_term: str | None = None
    utm_content: str | None = None
    referrer: str | None = None
    # Behavioral payload (scroll depth, click coords, etc.)
    payload: dict[str, Any] | None = None


class TrackingBatchIn(BaseModel):
    """Batch of events — JS can send several at once."""
    events: list[TrackingEventIn] = Field(..., min_length=1, max_length=50)


class TrackingResponse(BaseModel):
    status: Literal["ok", "error"]
    session_id: uuid.UUID | None = None
    risk_score: int = 0
    confidence_score: int = 0
    verdict: str = "SAFE"
"""Fraud analytics breakdowns (spec §47, task 025)."""
from __future__ import annotations

import uuid
from datetime import date, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.dependencies.permissions import Permission
from app.models import Organization
from app.services.analytics_service import GROUP_BY_VALUES, breakdown, period_for_dates, period_for_range

router = APIRouter(prefix="/api/v1/analytics", tags=["analytics"])
Viewer = Permission("dashboard:view")
MAX_DAYS = 366


class BreakdownRow(BaseModel):
    key: str
    label: str
    sessions: int
    clicks: int
    suspicious: int
    fraud: int
    fraud_rate: float
    avg_risk: float


class BreakdownOut(BaseModel):
    group_by: str
    timezone: str
    start: str
    end: str
    rows: list[BreakdownRow]


@router.get("/fraud", response_model=BreakdownOut)
async def fraud_breakdown(
    current_user: Viewer,
    db: AsyncSession = Depends(get_db),
    group_by: str = Query(..., description="day, hour, campaign, country, city, asn, isp, device or source"),
    range_name: str | None = Query(default="7d", alias="range", pattern="^(today|7d|30d)$"),
    from_date: date | None = Query(default=None, alias="from"),
    to_date: date | None = Query(default=None, alias="to"),
    website_id: uuid.UUID | None = None,
    campaign_id: uuid.UUID | None = None,
    limit: int = Query(default=20, ge=1, le=100),
) -> BreakdownOut:
    if group_by not in GROUP_BY_VALUES:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                            detail=f"group_by must be one of {', '.join(GROUP_BY_VALUES)}")
    organization = await db.get(Organization, current_user.organization_id)
    if from_date or to_date:
        first = from_date or (to_date - timedelta(days=29))
        last = to_date or date.today()
        if last < first or (last - first).days > MAX_DAYS:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid date range.")
        period = period_for_dates(first, last, organization.timezone)
    else:
        period = period_for_range(range_name or "7d", organization.timezone)
    rows = await breakdown(db, current_user.organization_id, group_by=group_by, period=period,
                           website_id=website_id, campaign_id=campaign_id, limit=limit)
    return BreakdownOut(group_by=group_by, timezone=period.timezone, start=period.start.isoformat(),
                        end=period.end.isoformat(), rows=[BreakdownRow(**row) for row in rows])

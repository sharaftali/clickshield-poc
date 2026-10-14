"""Campaign statistics (spec §48, task 026). Metric definitions: app/services/analytics_service.py."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import String, cast, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.dependencies.permissions import Permission
from app.models import Exclusion, ExclusionStatus, GoogleCampaign, GoogleConnection, Organization, Session
from app.schemas.protection import ProtectionExclusionResponse
from app.services.analytics_service import (
    IS_FRAUD,
    metric_columns,
    period_for_dates,
    period_for_range,
    rate,
    zone,
)
from app.services.exclusion_capacity import campaign_limit

router = APIRouter(prefix="/api/v1/campaigns", tags=["campaigns"])
Viewer = Permission("dashboard:view")
TREND_DAYS = 14


class TrendPoint(BaseModel):
    day: str
    sessions: int
    fraud_rate: float
    avg_risk: float


class CampaignStats(BaseModel):
    id: uuid.UUID
    campaign_id: str
    name: str
    status: str
    campaign_type: str
    protection_enabled: bool
    sessions: int
    clicks: int
    suspicious: int
    fraud: int
    fraud_rate: float
    avg_risk: float
    excluded_ips: int              # ACTIVE Click Shield exclusions
    exclusion_used: int            # incl. the advertiser's own exclusions
    exclusion_limit: int
    trend: list[TrendPoint]


class RecentFraudSession(BaseModel):
    id: uuid.UUID
    created_at: datetime
    ip_address: str | None
    country: str | None
    risk_score: int
    confidence_score: int
    verdict: str
    final_label: str | None


class CampaignDetail(CampaignStats):
    recent_fraud_sessions: list[RecentFraudSession]
    exclusions: list[ProtectionExclusionResponse]


def _campaigns_query(organization_id):
    return (
        select(GoogleCampaign)
        .join(GoogleConnection, GoogleConnection.id == GoogleCampaign.connection_id)
        .where(GoogleConnection.organization_id == organization_id)
    )


async def _stats(db: AsyncSession, organization: Organization, campaigns: list[GoogleCampaign], range_name: str) -> list[CampaignStats]:
    if not campaigns:
        return []
    ids = [c.id for c in campaigns]
    period = period_for_range(range_name, organization.timezone)
    rows = {
        row.google_campaign_id: row._mapping
        for row in (await db.execute(
            select(Session.google_campaign_id, *metric_columns())
            .where(Session.organization_id == organization.id, Session.google_campaign_id.in_(ids),
                   Session.created_at >= period.start, Session.created_at < period.end)
            .group_by(Session.google_campaign_id)
        )).all()
    }
    today = datetime.now(zone(organization.timezone)).date()
    trend_period = period_for_dates(today - timedelta(days=TREND_DAYS - 1), today, organization.timezone)
    day = cast(func.date(func.timezone(trend_period.timezone, Session.created_at)), String).label("day")
    trend: dict[uuid.UUID, dict[str, TrendPoint]] = {}
    for row in (await db.execute(
        select(Session.google_campaign_id, day, func.count().label("sessions"), func.count().filter(IS_FRAUD).label("fraud"),
               func.coalesce(func.avg(Session.risk_score), 0).label("avg_risk"))
        .where(Session.organization_id == organization.id, Session.google_campaign_id.in_(ids),
               Session.created_at >= trend_period.start, Session.created_at < trend_period.end)
        .group_by(Session.google_campaign_id, day)
    )).all():
        trend.setdefault(row.google_campaign_id, {})[row.day] = TrendPoint(
            day=row.day, sessions=row.sessions, fraud_rate=rate(row.fraud, row.sessions), avg_risk=round(float(row.avg_risk), 1))
    active = dict((await db.execute(
        select(Exclusion.google_campaign_id, func.count())
        .where(Exclusion.google_campaign_id.in_(ids), Exclusion.status == ExclusionStatus.ACTIVE)
        .group_by(Exclusion.google_campaign_id)
    )).all())

    limit = campaign_limit()
    days = [(today - timedelta(days=TREND_DAYS - 1 - i)).isoformat() for i in range(TREND_DAYS)]
    out = []
    for campaign in campaigns:
        m = rows.get(campaign.id) or {"sessions": 0, "clicks": 0, "suspicious": 0, "fraud": 0, "avg_risk": 0}
        points = trend.get(campaign.id, {})
        out.append(CampaignStats(
            id=campaign.id, campaign_id=campaign.campaign_id, name=campaign.name, status=campaign.status.value,
            campaign_type=campaign.campaign_type.value, protection_enabled=campaign.protection_enabled,
            sessions=int(m["sessions"]), clicks=int(m["clicks"]), suspicious=int(m["suspicious"]), fraud=int(m["fraud"]),
            fraud_rate=rate(int(m["fraud"]), int(m["sessions"])), avg_risk=round(float(m["avg_risk"] or 0), 1),
            excluded_ips=int(active.get(campaign.id, 0)),
            exclusion_used=int(campaign.exclusion_count or 0) + int(campaign.external_exclusion_count or 0),
            exclusion_limit=limit,
            trend=[points.get(d) or TrendPoint(day=d, sessions=0, fraud_rate=0.0, avg_risk=0.0) for d in days],
        ))
    return out


@router.get("", response_model=list[CampaignStats])
async def list_campaign_stats(
    current_user: Viewer,
    db: AsyncSession = Depends(get_db),
    range_name: str = Query(default="30d", alias="range", pattern="^(today|7d|30d)$"),
) -> list[CampaignStats]:
    organization = await db.get(Organization, current_user.organization_id)
    campaigns = list((await db.execute(_campaigns_query(organization.id).order_by(GoogleCampaign.name))).scalars())
    stats = await _stats(db, organization, campaigns, range_name)
    return sorted(stats, key=lambda c: (-c.sessions, c.name))


@router.get("/{campaign_row_id}", response_model=CampaignDetail)
async def campaign_detail(
    campaign_row_id: uuid.UUID,
    current_user: Viewer,
    db: AsyncSession = Depends(get_db),
    range_name: str = Query(default="30d", alias="range", pattern="^(today|7d|30d)$"),
) -> CampaignDetail:
    organization = await db.get(Organization, current_user.organization_id)
    campaign = (await db.execute(_campaigns_query(organization.id).where(GoogleCampaign.id == campaign_row_id))).scalar_one_or_none()
    if campaign is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Campaign not found.")
    [stats] = await _stats(db, organization, [campaign], range_name)
    fraud = (await db.execute(
        select(Session).where(Session.organization_id == organization.id, Session.google_campaign_id == campaign.id, IS_FRAUD)
        .order_by(Session.created_at.desc()).limit(20)
    )).scalars()
    exclusions = (await db.execute(
        select(Exclusion).where(Exclusion.organization_id == organization.id, Exclusion.google_campaign_id == campaign.id)
        .order_by(Exclusion.updated_at.desc()).limit(100)
    )).scalars()
    return CampaignDetail(
        **stats.model_dump(),
        recent_fraud_sessions=[
            RecentFraudSession(id=s.id, created_at=s.created_at, ip_address=str(s.ip_address) if s.ip_address else None,
                               country=s.country, risk_score=s.risk_score, confidence_score=s.confidence_score,
                               verdict=s.verdict.value, final_label=s.final_label.value if s.final_label else None)
            for s in fraud
        ],
        exclusions=[ProtectionExclusionResponse.model_validate(e) for e in exclusions],
    )


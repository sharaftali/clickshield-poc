from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.dependencies.auth import CurrentUser
from app.dependencies.permissions import Permission
from app.models import (
    AuditLog,
    AuditResult,
    Event,
    CampaignStatus,
    ClientVerdict,
    Exclusion,
    ExclusionStatus,
    FraudEvent,
    GoogleCampaign,
    GoogleConnection,
    Organization,
    Session,
    TrafficAnomaly,
    Verdict,
    Website,
)
from app.services.analytics_service import IS_SUSPICIOUS, period_for_range, totals
from app.services import audit_service
from app.services.audit_service import AuditAction
from app.services.ip_reputation import build_feedback_counter_update, counter_label
from app.schemas.dashboard import (
    ExclusionTimelineEntry,
    SessionDetail,
    SessionEventOut,
    SessionExclusion,
    SessionReason,
    DashboardAnomaly,
    DashboardFraudEvent,
    DashboardOverview,
    DashboardSessionSummary,
    DashboardTopIP,
    SessionFeedbackIn,
)

FeedbackUser = Permission("sessions:feedback")

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])


@router.get("/overview", response_model=DashboardOverview)
async def dashboard_overview(
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
    range_name: str = Query(default="today", alias="range", pattern="^(today|7d|30d)$"),
) -> DashboardOverview:
    """Spec §46 main dashboard for today / 7d / 30d in the organization's timezone (task 025)."""
    org_id = current_user.organization_id
    organization = await db.get(Organization, org_id)
    period = period_for_range(range_name, organization.timezone)
    in_period = (Session.organization_id == org_id, Session.created_at >= period.start, Session.created_at < period.end)
    figures = await totals(db, org_id, period)

    review_sessions = await db.scalar(
        select(func.count()).select_from(Session).where(
            Session.organization_id == org_id, Session.verdict == Verdict.FLAG, Session.client_verdict.is_(None),
        )
    )
    high_confidence_traffic = await db.scalar(
        select(func.count()).select_from(Session).where(*in_period, Session.confidence_score >= 80, IS_SUSPICIOUS)
    )
    protected_ips = await db.scalar(
        select(func.count()).select_from(Exclusion).where(
            Exclusion.organization_id == org_id, Exclusion.status == ExclusionStatus.ACTIVE,
        )
    )
    connected_websites = await db.scalar(
        select(func.count()).select_from(Website).where(
            Website.organization_id == org_id, Website.is_active.is_(True), Website.is_verified.is_(True),
        )
    )
    connected_google_accounts = await db.scalar(
        select(func.count()).select_from(GoogleConnection).where(
            GoogleConnection.organization_id == org_id, GoogleConnection.is_active.is_(True),
            GoogleConnection.needs_reauth.is_(False), GoogleConnection.customer_id != "",
        )
    )
    protected_campaigns = await db.scalar(
        select(func.count()).select_from(GoogleCampaign)
        .join(GoogleConnection, GoogleConnection.id == GoogleCampaign.connection_id)
        .where(
            GoogleConnection.organization_id == org_id, GoogleConnection.is_active.is_(True),
            GoogleCampaign.protection_enabled.is_(True), GoogleCampaign.status == CampaignStatus.ENABLED,
        )
    )
    missing = [
        name for name, count in (
            ("verified_website", connected_websites), ("google_connection", connected_google_accounts),
            ("protected_campaign", protected_campaigns),
        ) if not count
    ]
    return DashboardOverview(
        range=range_name,
        timezone=period.timezone,
        protection_status="ACTIVE" if not missing else "SETUP_REQUIRED",
        protection_missing=missing,
        clicks=figures["clicks"],
        total_sessions=figures["sessions"],
        suspicious_sessions=figures["suspicious"],
        fraud_sessions=figures["fraud"],
        fraud_rate=figures["fraud_rate"],
        review_sessions=int(review_sessions or 0),
        protected_ips=int(protected_ips or 0),
        average_risk_score=figures["avg_risk"],
        high_confidence_traffic=int(high_confidence_traffic or 0),
        connected_websites=int(connected_websites or 0),
        connected_google_accounts=int(connected_google_accounts or 0),
        protected_campaigns=int(protected_campaigns or 0),
    )


@router.get("/sessions", response_model=list[DashboardSessionSummary])
async def recent_sessions(
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
    limit: int = Query(default=20, ge=1, le=100),
    verdict: Verdict | None = Query(default=None, description="FLAG = the review queue (task 017)"),
) -> list[Session]:
    query = select(Session).where(Session.organization_id == current_user.organization_id)
    if verdict is not None:
        query = query.where(Session.verdict == verdict)
    result = await db.execute(query.order_by(Session.created_at.desc()).limit(limit))
    return list(result.scalars().all())


EVENT_LIMIT = 200
TIMELINE_ACTIONS = (
    "EXCLUSION_QUEUED", "ADD_IP_EXCLUSION", "REMOVE_IP_EXCLUSION", "EXCLUSION_RETRY_SCHEDULED",
    "EXCLUSION_FAILED", "EXCLUSION_SKIPPED", "EXCLUSION_EVICTED", "EXCLUSION_PROMOTED", "EXCLUSION_EXPIRED",
    "EXCLUSION_LIMIT_REACHED", "ADMIN_ACTION_RETRY",
)


def explanation(session: Session, reasons: list[SessionReason]) -> str:
    """Spec §33: "Fraud Risk: 91/100 · Reasons: … · Confidence: 94%"."""
    text = ", ".join(r.description or r.code for r in reasons) or "no rule fired"
    return f"Fraud Risk: {session.risk_score}/100 · Reasons: {text} · Confidence: {session.confidence_score}%"


@router.get("/sessions/{session_id}", response_model=SessionDetail)
async def session_detail(
    session_id: uuid.UUID,
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> SessionDetail:
    session = (
        await db.execute(
            select(Session).where(Session.id == session_id, Session.organization_id == current_user.organization_id)
        )
    ).scalar_one_or_none()
    if session is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found for this organization.")

    reasons = [
        SessionReason(code=e.reason_code, category=e.category, description=e.reason_text,
                      contribution=e.score_contribution, confidence=e.rule_confidence)
        for e in (await db.execute(
            select(FraudEvent).where(FraudEvent.session_id == session.id, FraudEvent.triggered.is_(True))
            .order_by(FraudEvent.score_contribution.desc(), FraudEvent.rule_name)
        )).scalars()
    ]
    events = list((await db.execute(
        select(Event).where(Event.session_id == session.id).order_by(Event.timestamp).limit(EVENT_LIMIT + 1)
    )).scalars())
    campaign = await db.get(GoogleCampaign, session.google_campaign_id) if session.google_campaign_id else None

    exclusions: list[SessionExclusion] = []
    if session.ip_address:
        query = select(Exclusion).where(
            Exclusion.organization_id == current_user.organization_id, Exclusion.ip_address == session.ip_address
        )
        if campaign is not None:
            query = query.where(Exclusion.campaign_id == campaign.campaign_id)
        for exclusion in (await db.execute(query.order_by(Exclusion.created_at))).scalars():
            timeline = [
                ExclusionTimelineEntry(at=row.created_at, action=row.action, result=row.result.value,
                                       google_request_id=row.google_request_id, error=row.error_message)
                for row in (await db.execute(
                    select(AuditLog).where(
                        AuditLog.organization_id == current_user.organization_id,
                        AuditLog.resource_id == str(exclusion.id), AuditLog.action.in_(TIMELINE_ACTIONS),
                    ).order_by(AuditLog.created_at)
                )).scalars()
            ]
            exclusions.append(SessionExclusion(
                id=exclusion.id, campaign_id=exclusion.campaign_id, status=exclusion.status.value,
                google_resource_name=exclusion.google_resource_name, api_request_id=exclusion.api_request_id,
                last_error=exclusion.last_error, created_at=exclusion.created_at, timeline=timeline,
            ))

    paid = bool(session.ad_landing_at or session.gclid or session.gbraid or session.wbraid)
    return SessionDetail(
        id=session.id, created_at=session.created_at, verdict=session.verdict, system_verdict=session.system_verdict,
        client_verdict=session.client_verdict, final_label=session.final_label, risk_score=session.risk_score,
        confidence_score=session.confidence_score, risk_band=session.risk_band, signal_diversity=session.signal_diversity,
        risk_categories=session.risk_categories, explanation=explanation(session, reasons),
        source="paid" if paid else ("organic" if session.referrer else "direct"),
        campaign_name=campaign.name if campaign else None, campaign_id=campaign.campaign_id if campaign else None,
        google_campaign_id=session.google_campaign_id, ad_group_id=session.ad_group_id, keyword=session.keyword,
        match_type=session.match_type, gclid_present=bool(session.gclid), utm_source=session.utm_source,
        utm_campaign=session.utm_campaign, ip_address=str(session.ip_address) if session.ip_address else None,
        country=session.country, region=session.region, city=session.city, asn=session.asn, isp=session.isp,
        is_vpn=session.is_vpn, is_proxy=session.is_proxy, is_tor=session.is_tor, is_datacenter=session.is_datacenter,
        device=session.device, browser=session.browser, os=session.os, language=session.language,
        timezone=session.timezone, landing_page=session.landing_page, referrer=session.referrer,
        clicks={name: int(getattr(session, name) or 0) for name in (
            "clicks_10_seconds", "clicks_30_seconds", "clicks_60_seconds", "clicks_5_minutes", "clicks_1_hour", "clicks_24_hours")},
        session_duration_seconds=session.session_duration_seconds, page_count=session.page_count,
        click_count=session.click_count, interaction_count=session.interaction_count, scroll_depth=session.scroll_depth,
        reasons=reasons,
        events=[SessionEventOut(event_type=e.event_type.value, page_url=e.page_url, timestamp=e.timestamp, payload=e.payload)
                for e in events[:EVENT_LIMIT]],
        events_truncated=len(events) > EVENT_LIMIT,
        exclusions=exclusions,
    )


@router.patch("/sessions/{session_id}/feedback", response_model=DashboardSessionSummary)
async def set_session_feedback(
    session_id: uuid.UUID,
    payload: SessionFeedbackIn,
    request: Request,
    current_user: FeedbackUser,
    db: AsyncSession = Depends(get_db),
) -> Session:
    result = await db.execute(
        select(Session)
        .where(
            Session.id == session_id,
            Session.organization_id == current_user.organization_id,
        )
        .limit(1)
    )
    session = result.scalar_one_or_none()
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found for this organization.",
        )

    previous_label = session.final_label
    was_fraud = counter_label(session.verdict, previous_label)
    session.client_verdict = payload.client_verdict
    session.final_label = (
        Verdict.FRAUD if payload.client_verdict == ClientVerdict.FRAUD else Verdict.SAFE
    )
    # Client feedback moves the session between this org's IP reputation counters (task 020);
    # the reputation rules already read final_label from session history.
    counters = build_feedback_counter_update(
        session, was_fraud=was_fraud, is_fraud=session.final_label == Verdict.FRAUD
    )
    if counters is not None:
        await db.execute(counters)
    audit_service.record(
        db,
        action=AuditAction.SESSION_FEEDBACK,
        result=AuditResult.SUCCESS,
        organization_id=current_user.organization_id,
        user_id=current_user.id,
        resource_type="session",
        resource_id=session.id,
        request=request,
        details={
            "ip": session.ip_address,
            "system_verdict": session.system_verdict,
            "client_verdict": payload.client_verdict,
            "previous_final_label": previous_label,
            "risk": session.risk_score,
            "confidence": session.confidence_score,
        },
    )
    await db.commit()
    await db.refresh(session)
    return session


@router.get("/fraud-events", response_model=list[DashboardFraudEvent])
async def recent_fraud_events(
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
    limit: int = Query(default=20, ge=1, le=100),
) -> list[FraudEvent]:
    result = await db.execute(
        select(FraudEvent)
        .where(
            FraudEvent.organization_id == current_user.organization_id,
            FraudEvent.triggered.is_(True),
        )
        .order_by(FraudEvent.updated_at.desc())
        .limit(limit)
    )
    return list(result.scalars().all())


@router.get("/anomalies", response_model=list[DashboardAnomaly])
async def recent_anomalies(
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
    hours: int = Query(default=24, ge=1, le=24 * 30),
) -> list[dict[str, object]]:
    """Campaign traffic anomalies (task 022) whose window ended in the last `hours`."""
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    rows = (
        await db.execute(
            select(TrafficAnomaly, GoogleCampaign.name, GoogleCampaign.campaign_id)
            .join(GoogleCampaign, GoogleCampaign.id == TrafficAnomaly.google_campaign_id)
            .where(TrafficAnomaly.organization_id == current_user.organization_id, TrafficAnomaly.window_end >= since)
            .order_by(TrafficAnomaly.window_start.desc(), TrafficAnomaly.score.desc())
            .limit(50)
        )
    ).all()
    return [
        {
            "id": anomaly.id, "campaign_name": name, "campaign_id": campaign_id,
            "window_start": anomaly.window_start, "window_end": anomaly.window_end,
            "metric": anomaly.metric, "observed": anomaly.observed, "expected": anomaly.expected,
            "score": anomaly.score, "level": anomaly.level,
        }
        for anomaly, name, campaign_id in rows
    ]


@router.get("/top-ip-reputation", response_model=list[DashboardTopIP])
async def top_ip_reputation(
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
    limit: int = Query(default=10, ge=1, le=25),
) -> list[dict[str, object]]:
    result = await db.execute(
        select(
            Session.ip_address,
            func.max(Session.risk_score),
            func.max(Session.confidence_score),
            func.count(Session.id),
            func.sum(case((Session.verdict == Verdict.FRAUD, 1), else_=0)),
        )
        .where(
            Session.organization_id == current_user.organization_id,
            Session.ip_address.is_not(None),
        )
        .group_by(Session.ip_address)
        .order_by(func.max(Session.risk_score).desc(), func.max(Session.confidence_score).desc())
        .limit(limit)
    )
    rows = result.all()
    return [
        {
            "ip": str(row[0]),
            "risk_score": int(row[1] or 0),
            "confidence": int(row[2] or 0),
            "total_sessions": int(row[3] or 0),
            "fraud_sessions": int(row[4] or 0),
        }
        for row in rows
    ]

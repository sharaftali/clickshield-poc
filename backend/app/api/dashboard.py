from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.dependencies.auth import CurrentUser
from app.models import (
    AuditResult,
    ClientVerdict,
    Exclusion,
    FraudEvent,
    GoogleCampaign,
    Session,
    TrafficAnomaly,
    Verdict,
)
from app.services import audit_service
from app.services.audit_service import AuditAction
from app.services.ip_reputation import build_feedback_counter_update, counter_label
from app.schemas.dashboard import (
    DashboardAnomaly,
    DashboardFraudEvent,
    DashboardOverview,
    DashboardSessionSummary,
    DashboardTopIP,
    SessionFeedbackIn,
)

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])


@router.get("/overview", response_model=DashboardOverview)
async def dashboard_overview(
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> DashboardOverview:
    org_id = current_user.organization_id

    total_sessions = await db.scalar(
        select(func.count()).select_from(Session).where(Session.organization_id == org_id)
    )
    suspicious_sessions = await db.scalar(
        select(func.count())
        .select_from(Session)
        .where(
            Session.organization_id == org_id,
            Session.verdict.in_([Verdict.MONITOR, Verdict.FLAG, Verdict.FRAUD]),
        )
    )
    fraud_sessions = await db.scalar(
        select(func.count())
        .select_from(Session)
        .where(Session.organization_id == org_id, Session.verdict == Verdict.FRAUD)
    )
    review_sessions = await db.scalar(
        select(func.count())
        .select_from(Session)
        .where(
            Session.organization_id == org_id,
            Session.verdict == Verdict.FLAG,
            Session.client_verdict.is_(None),
        )
    )
    protected_ips = await db.scalar(
        select(func.count())
        .select_from(Exclusion)
        .where(
            Exclusion.organization_id == org_id,
            Exclusion.status.in_(["PENDING", "SUBMITTED", "ACTIVE"]),
        )
    )
    avg_risk = await db.scalar(
        select(func.coalesce(func.avg(Session.risk_score), 0))
        .where(Session.organization_id == org_id)
    )
    high_confidence_traffic = await db.scalar(
        select(func.count())
        .select_from(Session)
        .where(
            Session.organization_id == org_id,
            Session.confidence_score >= 80,
            Session.verdict.in_([Verdict.MONITOR, Verdict.FLAG, Verdict.FRAUD]),
        )
    )

    return DashboardOverview(
        total_sessions=int(total_sessions or 0),
        suspicious_sessions=int(suspicious_sessions or 0),
        fraud_sessions=int(fraud_sessions or 0),
        review_sessions=int(review_sessions or 0),
        protected_ips=int(protected_ips or 0),
        average_risk_score=float(avg_risk or 0.0),
        high_confidence_traffic=int(high_confidence_traffic or 0),
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


@router.patch("/sessions/{session_id}/feedback", response_model=DashboardSessionSummary)
async def set_session_feedback(
    session_id: uuid.UUID,
    payload: SessionFeedbackIn,
    request: Request,
    current_user: CurrentUser,
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

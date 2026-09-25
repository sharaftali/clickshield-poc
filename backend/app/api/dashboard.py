from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.dependencies.auth import CurrentUser
from app.models import ClientVerdict, Exclusion, FraudEvent, Session, Verdict
from app.schemas.dashboard import (
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
        protected_ips=int(protected_ips or 0),
        average_risk_score=float(avg_risk or 0.0),
        high_confidence_traffic=int(high_confidence_traffic or 0),
    )


@router.get("/sessions", response_model=list[DashboardSessionSummary])
async def recent_sessions(
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
    limit: int = Query(default=20, ge=1, le=100),
) -> list[Session]:
    result = await db.execute(
        select(Session)
        .where(Session.organization_id == current_user.organization_id)
        .order_by(Session.created_at.desc())
        .limit(limit)
    )
    return list(result.scalars().all())


@router.patch("/sessions/{session_id}/feedback", response_model=DashboardSessionSummary)
async def set_session_feedback(
    session_id: uuid.UUID,
    payload: SessionFeedbackIn,
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

    session.client_verdict = payload.client_verdict
    session.final_label = (
        Verdict.FRAUD if payload.client_verdict == ClientVerdict.FRAUD else Verdict.SAFE
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
        .where(FraudEvent.organization_id == current_user.organization_id)
        .order_by(FraudEvent.created_at.desc())
        .limit(limit)
    )
    return list(result.scalars().all())


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

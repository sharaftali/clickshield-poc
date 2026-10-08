from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.dependencies.auth import CurrentUser
from app.models import ActionStatus, Exclusion, ExclusionStatus, PlatformAction
from app.schemas.protection import (
    ProtectionActionResponse,
    ProtectionExclusionResponse,
    ProtectionQueueStatus,
)

router = APIRouter(prefix="/api/v1/protection", tags=["protection"])

# Exclusions are created automatically from FRAUD verdicts and sent to Google by
# the worker (task 010); these endpoints only report on that pipeline.


@router.get("/exclusions", response_model=list[ProtectionExclusionResponse])
async def list_exclusions(
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> list[Exclusion]:
    result = await db.execute(
        select(Exclusion)
        .where(Exclusion.organization_id == current_user.organization_id)
        .order_by(Exclusion.created_at.desc())
    )
    return list(result.scalars().all())


@router.get("/queue", response_model=ProtectionQueueStatus)
async def queue_status(
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> ProtectionQueueStatus:
    org_id = current_user.organization_id
    action_counts = dict(
        (
            await db.execute(
                select(PlatformAction.status, func.count())
                .where(PlatformAction.organization_id == org_id)
                .group_by(PlatformAction.status)
            )
        ).all()
    )
    exclusion_counts = dict(
        (
            await db.execute(
                select(Exclusion.status, func.count())
                .where(Exclusion.organization_id == org_id)
                .group_by(Exclusion.status)
            )
        ).all()
    )
    overflow = await db.scalar(
        select(func.count())
        .select_from(Exclusion)
        .where(
            Exclusion.organization_id == org_id,
            Exclusion.status == ExclusionStatus.SKIPPED,
            Exclusion.overflow.is_(True),
        )
    )
    return ProtectionQueueStatus(
        auto_protection_enabled=settings.AUTO_PROTECTION_ENABLED,
        dry_run=settings.GOOGLE_ADS_DRY_RUN,
        pending=action_counts.get(ActionStatus.PENDING, 0),
        processing=action_counts.get(ActionStatus.PROCESSING, 0),
        retrying=action_counts.get(ActionStatus.RETRYING, 0),
        failed=action_counts.get(ActionStatus.FAILED, 0),
        succeeded=action_counts.get(ActionStatus.SUCCESS, 0),
        active_exclusions=exclusion_counts.get(ExclusionStatus.ACTIVE, 0),
        overflow_exclusions=int(overflow or 0),
    )


@router.get("/actions", response_model=list[ProtectionActionResponse])
async def recent_actions(
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
    status: ActionStatus | None = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
) -> list[ProtectionActionResponse]:
    query = (
        select(PlatformAction, Exclusion.ip_address, Exclusion.campaign_id)
        .outerjoin(Exclusion, Exclusion.id == PlatformAction.reference_id)
        .where(PlatformAction.organization_id == current_user.organization_id)
        .order_by(PlatformAction.updated_at.desc())
        .limit(limit)
    )
    if status is not None:
        query = query.where(PlatformAction.status == status)
    rows = (await db.execute(query)).all()
    return [
        ProtectionActionResponse(
            id=action.id,
            action_type=action.action_type,
            status=action.status,
            attempts=action.attempts,
            max_attempts=action.max_attempts,
            last_error=action.last_error,
            scheduled_at=action.scheduled_at,
            completed_at=action.completed_at,
            updated_at=action.updated_at,
            ip_address=str(ip) if ip is not None else None,
            campaign_id=campaign_id,
        )
        for action, ip, campaign_id in rows
    ]

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.dependencies.auth import CurrentUser
from app.models import Exclusion
from app.schemas.protection import ProtectionExclusionResponse, ProtectionQueueSummary
from app.services.protection_service import enqueue_high_risk_exclusions
from app.workers.action_worker import ActionWorker

router = APIRouter(prefix="/api/v1/protection", tags=["protection"])


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


@router.post("/reconcile", response_model=ProtectionQueueSummary)
async def reconcile_protection(
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> ProtectionQueueSummary:
    queued = await enqueue_high_risk_exclusions(
        db,
        organization_id=current_user.organization_id,
    )

    worker = ActionWorker()
    metrics = await worker.process_pending(db, organization_id=current_user.organization_id)
    return ProtectionQueueSummary(
        queued=len(queued),
        processed=metrics["processed"],
        successful=metrics["successful"],
        failed=metrics["failed"],
        skipped=metrics["skipped"],
    )


@router.post("/dry-run", response_model=dict[str, int])
async def enqueue_dry_run(
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> dict[str, int]:
    created = await enqueue_high_risk_exclusions(
        db,
        organization_id=current_user.organization_id,
    )
    return {"queued": len(created)}

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.client_ip import ClientIPError, parse_ip
from app.core.database import get_db
from app.dependencies.auth import CurrentUser
from app.models import AuditLog, AuditResult
from app.schemas.audit import AuditLogOut, AuditLogPage

router = APIRouter(prefix="/api/v1/audit-logs", tags=["audit"])

# Read-only by design (spec §44): there are no update or delete endpoints.


@router.get("", response_model=AuditLogPage)
async def list_audit_logs(
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
    action: str | None = Query(default=None, max_length=100),
    result: AuditResult | None = Query(default=None),
    ip: str | None = Query(default=None, max_length=64),
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> AuditLogPage:
    filters = [AuditLog.organization_id == current_user.organization_id]
    if action:
        filters.append(AuditLog.action == action.strip().upper())
    if result is not None:
        filters.append(AuditLog.result == result)
    if ip:
        try:
            filters.append(AuditLog.ip_address == str(parse_ip(ip)))
        except ClientIPError as exc:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid IP filter.") from exc
    if since is not None:
        filters.append(AuditLog.created_at >= since)
    if until is not None:
        filters.append(AuditLog.created_at < until)

    total = await db.scalar(select(func.count()).select_from(AuditLog).where(*filters))
    rows = (
        await db.execute(
            select(AuditLog)
            .where(*filters)
            .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
            .limit(limit)
            .offset(offset)
        )
    ).scalars().all()
    return AuditLogPage(
        items=[AuditLogOut.model_validate(row) for row in rows],
        total=int(total or 0),
        limit=limit,
        offset=offset,
    )


@router.get("/actions", response_model=list[str])
async def list_audit_actions(
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> list[str]:
    """Distinct action names present for this organization (for the filter dropdown)."""
    rows = await db.execute(
        select(AuditLog.action)
        .where(AuditLog.organization_id == current_user.organization_id)
        .distinct()
        .order_by(AuditLog.action)
    )
    return list(rows.scalars().all())

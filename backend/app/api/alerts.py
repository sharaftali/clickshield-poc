"""Alerts of the caller's organization (spec §66, task 028). Platform admins also see platform alerts."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.dependencies.permissions import Permission
from app.models import Alert, AuditResult, Notification, User
from app.services import alert_service, audit_service
from app.services.audit_service import AuditAction

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])
Viewer = Permission("dashboard:view")
AlertManager = Permission("alerts:manage")


class NotificationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    channel: str
    recipient: str
    status: str
    sent_at: datetime | None = None
    error: str | None = None


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID | None = None
    type: str
    severity: str
    title: str
    message: str
    resource_type: str | None = None
    resource_id: str | None = None
    details: dict[str, Any] | None = None
    status: str
    occurrences: int
    first_seen_at: datetime
    last_seen_at: datetime
    acknowledged_at: datetime | None = None
    resolved_at: datetime | None = None
    notifications: list[NotificationOut] = []


class AlertPage(BaseModel):
    items: list[AlertOut]
    total: int


class AlertSummary(BaseModel):
    open: int
    critical: int
    warning: int


def _scope(user: User):
    own = Alert.organization_id == user.organization_id
    return or_(own, Alert.organization_id.is_(None)) if user.is_platform_admin else own


@router.get("", response_model=AlertPage)
async def list_alerts(
    current_user: Viewer,
    db: AsyncSession = Depends(get_db),
    status_filter: Literal["open", "acknowledged", "resolved", "active"] | None = Query(default="active", alias="status"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> AlertPage:
    query = select(Alert).where(_scope(current_user))
    if status_filter == "active":
        query = query.where(Alert.status.in_(alert_service.OPEN_STATUSES))
    elif status_filter:
        query = query.where(Alert.status == status_filter)
    total = int(await db.scalar(select(func.count()).select_from(query.subquery())) or 0)
    alerts = list((await db.execute(query.order_by(Alert.last_seen_at.desc()).limit(limit).offset(offset))).scalars())
    notes: dict[uuid.UUID, list[Notification]] = {}
    if alerts:
        for note in (await db.execute(
            select(Notification).where(Notification.alert_id.in_([a.id for a in alerts])).order_by(Notification.created_at)
        )).scalars():
            notes.setdefault(note.alert_id, []).append(note)
    items = [
        AlertOut.model_validate(alert).model_copy(update={
            "notifications": [NotificationOut.model_validate(n) for n in notes.get(alert.id, [])]
        })
        for alert in alerts
    ]
    return AlertPage(items=items, total=total)


@router.get("/summary", response_model=AlertSummary)
async def alert_summary(current_user: Viewer, db: AsyncSession = Depends(get_db)) -> AlertSummary:
    """Counts for the alert bell."""
    return AlertSummary(**await alert_service.open_counts(
        db, current_user.organization_id, include_platform=current_user.is_platform_admin
    ))


async def _change(db: AsyncSession, user: User, alert_id: uuid.UUID, new_status: str, request: Request) -> Alert:
    alert = (
        await db.execute(select(Alert).where(Alert.id == alert_id, _scope(user)).with_for_update())
    ).scalar_one_or_none()
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found.")
    now = datetime.now(timezone.utc)
    if new_status == "acknowledged" and alert.status == "open":
        alert.status, alert.acknowledged_at, alert.acknowledged_by = "acknowledged", now, user.id
        action = AuditAction.ALERT_ACKNOWLEDGED
    elif new_status == "resolved" and alert.status != "resolved":
        alert.status, alert.resolved_at = "resolved", now
        action = AuditAction.ALERT_RESOLVED
    else:
        return alert
    audit_service.record(
        db, action=action, result=AuditResult.SUCCESS, organization_id=alert.organization_id, user_id=user.id,
        resource_type="alert", resource_id=alert.id, request=request, details={"type": alert.type, "title": alert.title},
    )
    await db.commit()
    await db.refresh(alert)
    return alert


@router.post("/{alert_id}/acknowledge", response_model=AlertOut)
async def acknowledge_alert(
    alert_id: uuid.UUID, request: Request, current_user: AlertManager, db: AsyncSession = Depends(get_db)
) -> Alert:
    return await _change(db, current_user, alert_id, "acknowledged", request)


@router.post("/{alert_id}/resolve", response_model=AlertOut)
async def resolve_alert(
    alert_id: uuid.UUID, request: Request, current_user: AlertManager, db: AsyncSession = Depends(get_db)
) -> Alert:
    return await _change(db, current_user, alert_id, "resolved", request)

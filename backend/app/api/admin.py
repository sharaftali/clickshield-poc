"""
Platform administration (spec §64–65, task 027). Click Shield staff only
(`users.is_platform_admin`, granted with `python -m app.cli grant-platform-admin`).

Read-only across tenants, plus two audited actions: retrying a failed protection
action and editing a global rule. No response model here carries credential
material (tests/test_admin_schemas.py walks them).
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.queue import enqueue_actions
from app.dependencies.permissions import PlatformAdmin
from app.models import (
    ActionStatus,
    ActionType,
    AuditLog,
    AuditResult,
    Exclusion,
    ExclusionStatus,
    GoogleCampaign,
    GoogleConnection,
    Organization,
    PlatformAction,
    Rule,
    Session,
    User,
    Verdict,
    Website,
)
from app.schemas.audit import AuditLogOut, AuditLogPage
from app.schemas.rules import RuleOut
from app.services import audit_service
from app.services.audit_service import AuditAction
from app.services.exclusion_capacity import get_capacity, lock_campaign, sync_exclusion_count
from app.services.health_service import system_health
from app.services.rules import EVALUATORS, validate_params
from app.services.rules.repository import invalidate

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])


class AdminOrganization(BaseModel):
    id: uuid.UUID
    name: str
    slug: str
    protection_mode: str
    is_active: bool
    created_at: datetime
    users: int
    websites: int
    google_connections: int
    sessions_24h: int
    sessions_30d: int
    fraud_30d: int


class AdminUser(BaseModel):
    id: uuid.UUID
    email: str
    full_name: str | None
    role: str
    is_active: bool
    is_platform_admin: bool
    organization_id: uuid.UUID
    organization_name: str
    created_at: datetime


class AdminWebsite(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    organization_name: str
    domain: str
    is_verified: bool
    is_active: bool
    last_event_at: datetime | None
    created_at: datetime


class AdminConnection(BaseModel):
    """Metadata only (spec §64): never the refresh token, encrypted or not."""
    id: uuid.UUID
    organization_id: uuid.UUID
    organization_name: str
    customer_id: str
    login_customer_id: str | None
    google_account_email: str | None
    is_active: bool
    needs_reauth: bool
    auth_error: str | None
    last_refreshed_at: datetime | None
    created_at: datetime


class AdminAction(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    organization_name: str
    action_type: str
    status: str
    attempts: int
    max_attempts: int
    last_error: str | None
    ip_address: str | None
    campaign_id: str | None
    updated_at: datetime


class AdminTraffic(BaseModel):
    organization_id: uuid.UUID
    organization_name: str
    sessions_24h: int
    fraud_24h: int
    fraud_rate_24h: float


class GlobalRuleIn(BaseModel):
    enabled: bool | None = None
    weight: int | None = Field(default=None, ge=0, le=100)
    confidence: int | None = Field(default=None, ge=0, le=100)
    params: dict[str, Any] | None = None


@router.get("/health")
async def health(_: PlatformAdmin, db: AsyncSession = Depends(get_db)) -> dict:
    return await system_health(db)


@router.get("/organizations", response_model=list[AdminOrganization])
async def organizations(_: PlatformAdmin, db: AsyncSession = Depends(get_db)) -> list[AdminOrganization]:
    now = datetime.now(timezone.utc)

    def grouped(query) -> dict:
        return {row[0]: row[1] for row in query}

    users = grouped((await db.execute(select(User.organization_id, func.count()).group_by(User.organization_id))).all())
    sites = grouped((await db.execute(select(Website.organization_id, func.count()).where(Website.is_active.is_(True)).group_by(Website.organization_id))).all())
    conns = grouped((await db.execute(select(GoogleConnection.organization_id, func.count()).where(GoogleConnection.is_active.is_(True)).group_by(GoogleConnection.organization_id))).all())
    traffic = {
        row.organization_id: row for row in (await db.execute(
            select(Session.organization_id,
                   func.count().filter(Session.created_at >= now - timedelta(hours=24)).label("day"),
                   func.count().label("month"),
                   func.count().filter(func.coalesce(Session.final_label, Session.verdict) == Verdict.FRAUD).label("fraud"))
            .where(Session.created_at >= now - timedelta(days=30)).group_by(Session.organization_id)
        )).all()
    }
    out = []
    for org in (await db.execute(select(Organization).order_by(Organization.created_at))).scalars():
        t = traffic.get(org.id)
        out.append(AdminOrganization(
            id=org.id, name=org.name, slug=org.slug, protection_mode=org.protection_mode.value, is_active=org.is_active,
            created_at=org.created_at, users=users.get(org.id, 0), websites=sites.get(org.id, 0),
            google_connections=conns.get(org.id, 0), sessions_24h=t.day if t else 0, sessions_30d=t.month if t else 0,
            fraud_30d=t.fraud if t else 0,
        ))
    return out


@router.get("/users", response_model=list[AdminUser])
async def users(_: PlatformAdmin, db: AsyncSession = Depends(get_db),
                organization_id: uuid.UUID | None = None) -> list[AdminUser]:
    query = select(User, Organization.name).join(Organization, Organization.id == User.organization_id)
    if organization_id:
        query = query.where(User.organization_id == organization_id)
    return [
        AdminUser(id=u.id, email=u.email, full_name=u.full_name, role=u.role.value, is_active=u.is_active,
                  is_platform_admin=u.is_platform_admin, organization_id=u.organization_id, organization_name=name,
                  created_at=u.created_at)
        for u, name in (await db.execute(query.order_by(Organization.name, User.created_at))).all()
    ]


@router.get("/websites", response_model=list[AdminWebsite])
async def websites(_: PlatformAdmin, db: AsyncSession = Depends(get_db)) -> list[AdminWebsite]:
    rows = await db.execute(select(Website, Organization.name).join(Organization, Organization.id == Website.organization_id)
                            .order_by(Organization.name, Website.domain))
    return [AdminWebsite(id=w.id, organization_id=w.organization_id, organization_name=name, domain=w.domain,
                         is_verified=w.is_verified, is_active=w.is_active, last_event_at=w.last_event_at,
                         created_at=w.created_at) for w, name in rows.all()]


@router.get("/connections", response_model=list[AdminConnection])
async def connections(_: PlatformAdmin, db: AsyncSession = Depends(get_db)) -> list[AdminConnection]:
    rows = await db.execute(
        select(GoogleConnection, Organization.name).join(Organization, Organization.id == GoogleConnection.organization_id)
        .order_by(Organization.name, GoogleConnection.created_at)
    )
    return [AdminConnection(id=c.id, organization_id=c.organization_id, organization_name=name, customer_id=c.customer_id,
                            login_customer_id=c.login_customer_id, google_account_email=c.google_account_email,
                            is_active=c.is_active, needs_reauth=c.needs_reauth, auth_error=c.auth_error,
                            last_refreshed_at=c.last_refreshed_at, created_at=c.created_at) for c, name in rows.all()]


@router.get("/traffic", response_model=list[AdminTraffic])
async def traffic(_: PlatformAdmin, db: AsyncSession = Depends(get_db)) -> list[AdminTraffic]:
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    rows = await db.execute(
        select(Session.organization_id, Organization.name, func.count().label("sessions"),
               func.count().filter(func.coalesce(Session.final_label, Session.verdict) == Verdict.FRAUD).label("fraud"))
        .join(Organization, Organization.id == Session.organization_id)
        .where(Session.created_at >= since).group_by(Session.organization_id, Organization.name)
        .order_by(func.count().desc())
    )
    return [AdminTraffic(organization_id=r.organization_id, organization_name=r.name, sessions_24h=r.sessions,
                         fraud_24h=r.fraud, fraud_rate_24h=round(r.fraud / r.sessions, 4) if r.sessions else 0.0)
            for r in rows.all()]


@router.get("/actions", response_model=list[AdminAction])
async def actions(_: PlatformAdmin, db: AsyncSession = Depends(get_db),
                  status_filter: ActionStatus = Query(default=ActionStatus.FAILED, alias="status"),
                  limit: int = Query(default=100, ge=1, le=500)) -> list[AdminAction]:
    rows = await db.execute(
        select(PlatformAction, Organization.name, Exclusion.ip_address, Exclusion.campaign_id)
        .join(Organization, Organization.id == PlatformAction.organization_id)
        .outerjoin(Exclusion, Exclusion.id == PlatformAction.reference_id)
        .where(PlatformAction.status == status_filter)
        .order_by(PlatformAction.updated_at.desc()).limit(limit)
    )
    return [AdminAction(id=a.id, organization_id=a.organization_id, organization_name=name, action_type=a.action_type.value,
                        status=a.status.value, attempts=a.attempts, max_attempts=a.max_attempts, last_error=a.last_error,
                        ip_address=str(ip) if ip else None, campaign_id=campaign, updated_at=a.updated_at)
            for a, name, ip, campaign in rows.all()]


@router.post("/actions/{action_id}/retry", response_model=AdminAction)
async def retry_action(action_id: uuid.UUID, request: Request, admin: PlatformAdmin,
                       db: AsyncSession = Depends(get_db)) -> AdminAction:
    action = (await db.execute(select(PlatformAction).where(PlatformAction.id == action_id).with_for_update())).scalar_one_or_none()
    if action is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Action not found.")
    if action.status != ActionStatus.FAILED:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Only FAILED actions can be retried.")
    exclusion = await db.get(Exclusion, action.reference_id, with_for_update=True) if action.reference_id else None
    if exclusion is not None and action.action_type == ActionType.ADD_IP_EXCLUSION and exclusion.google_campaign_id:
        locked = await lock_campaign(db, exclusion.google_campaign_id, exclusion.organization_id)
        if locked is None or (await get_capacity(db, locked[0])).available <= 0:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="The campaign has no free IP exclusion slot.")
        exclusion.status = ExclusionStatus.PENDING
        exclusion.last_error = None
    previous_error = action.last_error
    action.status, action.attempts, action.scheduled_at = ActionStatus.PENDING, 0, datetime.now(timezone.utc)
    action.completed_at = None
    audit_service.record(
        db, action=AuditAction.ADMIN_ACTION_RETRY, result=AuditResult.PENDING, organization_id=action.organization_id,
        user_id=admin.id, resource_type="exclusion" if exclusion else "platform_action",
        resource_id=exclusion.id if exclusion else action.id, request=request,
        details={"action_id": action.id, "action_type": action.action_type, "previous_error": previous_error,
                 "by_platform_admin": admin.email},
    )
    if exclusion is not None and exclusion.google_campaign_id:
        campaign = await db.get(GoogleCampaign, exclusion.google_campaign_id)
        await sync_exclusion_count(db, campaign)
    await db.commit()
    await db.refresh(action)
    await enqueue_actions([action.id])
    org = await db.get(Organization, action.organization_id)
    return AdminAction(id=action.id, organization_id=action.organization_id, organization_name=org.name,
                       action_type=action.action_type.value, status=action.status.value, attempts=action.attempts,
                       max_attempts=action.max_attempts, last_error=action.last_error,
                       ip_address=str(exclusion.ip_address) if exclusion else None,
                       campaign_id=exclusion.campaign_id if exclusion else None, updated_at=action.updated_at)


@router.get("/rules", response_model=list[RuleOut])
async def global_rules(_: PlatformAdmin, db: AsyncSession = Depends(get_db)) -> list[RuleOut]:
    from app.api.rules import _rule_out

    rows = (await db.execute(select(Rule).order_by(Rule.category, Rule.code))).scalars()
    return [_rule_out(rule, None) for rule in rows if rule.code in EVALUATORS]


@router.patch("/rules/{code}", response_model=RuleOut)
async def update_global_rule(code: str, payload: GlobalRuleIn, request: Request, admin: PlatformAdmin,
                             db: AsyncSession = Depends(get_db)) -> RuleOut:
    """Global rule editor (task 015 → 027). Applies to every organization without an override."""
    from app.api.rules import _rule_out, _summary

    rule = (await db.execute(select(Rule).where(Rule.code == code).with_for_update())).scalar_one_or_none()
    if rule is None or code not in EVALUATORS:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Unknown rule {code!r}.")
    before = _summary(_rule_out(rule, None)) | {"confidence": rule.confidence, "version": rule.version}
    changes = payload.model_dump(exclude_unset=True, exclude_none=True)
    if "params" in changes:
        try:
            changes["params"] = validate_params(code, {**rule.params, **changes["params"]})
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    for key, value in changes.items():
        setattr(rule, key, value)
    rule.version += 1
    rule.updated_by = admin.id
    after = _summary(_rule_out(rule, None)) | {"confidence": rule.confidence, "version": rule.version}
    audit_service.record(
        db, action=AuditAction.ADMIN_RULE_CHANGED, result=AuditResult.SUCCESS, user_id=admin.id,
        resource_type="rule", resource_id=code, request=request,
        details={"scope": "global", "changes": changes, "before": before, "after": after},
    )
    await db.commit()
    invalidate()
    return _rule_out(rule, None)


@router.get("/audit-logs", response_model=AuditLogPage)
async def audit_logs(
    _: PlatformAdmin,
    db: AsyncSession = Depends(get_db),
    organization_id: uuid.UUID | None = None,
    action: str | None = None,
    result: AuditResult | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> AuditLogPage:
    query = select(AuditLog)
    if organization_id:
        query = query.where(AuditLog.organization_id == organization_id)
    if action:
        query = query.where(AuditLog.action == action)
    if result:
        query = query.where(AuditLog.result == result)
    total = int(await db.scalar(select(func.count()).select_from(query.subquery())) or 0)
    rows = (await db.execute(query.order_by(AuditLog.created_at.desc()).limit(limit).offset(offset))).scalars()
    return AuditLogPage(items=[AuditLogOut.model_validate(r) for r in rows], total=total, limit=limit, offset=offset)

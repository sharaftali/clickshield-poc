"""Websites of the caller's organization (spec §7–8, task 023)."""
from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.dependencies.permissions import Permission
from app.models import AuditResult, Website
from app.services import alert_service, audit_service
from app.services.audit_service import AuditAction
from app.services.website_service import normalize_domain, snippet, verify_by_fetch

router = APIRouter(prefix="/api/v1/websites", tags=["websites"])
Viewer = Permission("dashboard:view")
WebsiteManager = Permission("websites:manage")


class WebsiteIn(BaseModel):
    domain: str = Field(..., min_length=3, max_length=255)
    display_name: str | None = Field(default=None, max_length=255)
    require_consent: bool = False

    @field_validator("domain")
    @classmethod
    def clean_domain(cls, value: str) -> str:
        return normalize_domain(value)


class WebsiteUpdateIn(BaseModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=255)
    require_consent: bool | None = None
    enforce_origin: bool | None = None
    allowed_domains: list[str] | None = Field(default=None, max_length=50)

    @field_validator("allowed_domains")
    @classmethod
    def clean_domains(cls, values: list[str] | None) -> list[str] | None:
        if values is None:
            return None
        return sorted({normalize_domain(value) for value in values})


class WebsiteOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    domain: str
    display_name: str
    tracking_token: str
    is_verified: bool
    verified_at: datetime | None = None
    verification_method: str | None = None
    require_consent: bool
    enforce_origin: bool
    allowed_domains: list[str]
    is_active: bool
    last_event_at: datetime | None = None
    created_at: datetime
    snippet: str


class VerifyOut(BaseModel):
    verified: bool
    method: str | None = None
    detail: str
    website: WebsiteOut


def website_out(website: Website) -> WebsiteOut:
    return WebsiteOut.model_validate({**{c: getattr(website, c) for c in WebsiteOut.model_fields if c != "snippet"},
                                      "snippet": snippet(website)})


async def _load(db: AsyncSession, organization_id, website_id: uuid.UUID, *, for_update: bool = False) -> Website:
    query = select(Website).where(Website.id == website_id, Website.organization_id == organization_id)
    if for_update:
        query = query.with_for_update()
    website = (await db.execute(query)).scalar_one_or_none()
    if website is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Website not found.")
    return website


def _audit(db, request, user, website, action, details=None):
    audit_service.record(
        db, action=action, result=AuditResult.SUCCESS, organization_id=user.organization_id, user_id=user.id,
        resource_type="website", resource_id=website.id, request=request,
        details={"domain": website.domain, **(details or {})},
    )


@router.get("", response_model=list[WebsiteOut])
async def list_websites(
    current_user: Viewer,
    db: AsyncSession = Depends(get_db),
    include_deleted: bool = Query(default=False),
) -> list[WebsiteOut]:
    query = select(Website).where(Website.organization_id == current_user.organization_id)
    if not include_deleted:
        query = query.where(Website.is_active.is_(True))
    rows = await db.execute(query.order_by(Website.created_at))
    return [website_out(w) for w in rows.scalars()]


@router.post("", response_model=WebsiteOut, status_code=status.HTTP_201_CREATED)
async def create_website(
    payload: WebsiteIn, request: Request, current_user: WebsiteManager, db: AsyncSession = Depends(get_db)
) -> WebsiteOut:
    exists = await db.scalar(
        select(Website.id).where(
            Website.organization_id == current_user.organization_id,
            Website.domain == payload.domain,
            Website.is_active.is_(True),
        )
    )
    if exists:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"{payload.domain} is already added.")
    website = Website(
        organization_id=current_user.organization_id, domain=payload.domain,
        display_name=payload.display_name or payload.domain, require_consent=payload.require_consent,
        tracking_token=secrets.token_urlsafe(24), is_verified=False, allowed_domains=[], enforce_origin=True,
    )
    db.add(website)
    await db.flush()
    _audit(db, request, current_user, website, AuditAction.WEBSITE_CREATED)
    await db.commit()
    await db.refresh(website)
    return website_out(website)


@router.get("/{website_id}", response_model=WebsiteOut)
async def get_website(website_id: uuid.UUID, current_user: Viewer, db: AsyncSession = Depends(get_db)) -> WebsiteOut:
    return website_out(await _load(db, current_user.organization_id, website_id))


@router.patch("/{website_id}", response_model=WebsiteOut)
async def update_website(
    website_id: uuid.UUID, payload: WebsiteUpdateIn, request: Request, current_user: WebsiteManager,
    db: AsyncSession = Depends(get_db),
) -> WebsiteOut:
    website = await _load(db, current_user.organization_id, website_id, for_update=True)
    changes = payload.model_dump(exclude_unset=True, exclude_none=True)
    for key, value in changes.items():
        setattr(website, key, value)
    _audit(db, request, current_user, website, AuditAction.WEBSITE_UPDATED, {"changes": changes})
    await db.commit()
    await db.refresh(website)
    return website_out(website)


@router.post("/{website_id}/rotate-token", response_model=WebsiteOut)
async def rotate_token(
    website_id: uuid.UUID, request: Request, current_user: WebsiteManager, db: AsyncSession = Depends(get_db)
) -> WebsiteOut:
    """New tracking token; the old one stops working immediately (see website_service)."""
    website = await _load(db, current_user.organization_id, website_id, for_update=True)
    website.tracking_token = secrets.token_urlsafe(24)
    _audit(db, request, current_user, website, AuditAction.WEBSITE_TOKEN_ROTATED)
    await db.commit()
    await db.refresh(website)
    return website_out(website)


@router.post("/{website_id}/verify", response_model=VerifyOut)
async def verify_website(
    website_id: uuid.UUID, request: Request, current_user: WebsiteManager, db: AsyncSession = Depends(get_db)
) -> VerifyOut:
    """Check the home page for the snippet / meta tag (verification (b))."""
    website = await _load(db, current_user.organization_id, website_id, for_update=True)
    result = await verify_by_fetch(website)
    if result.verified:
        if not website.is_verified:
            website.is_verified = True
            website.verified_at = datetime.now(timezone.utc)
            website.verification_method = result.method
            _audit(db, request, current_user, website, AuditAction.WEBSITE_VERIFIED, {"method": result.method})
        await alert_service.resolve(db, dedupe_key=alert_service.website_disconnected_key(website.id))
    elif website.is_verified:
        # It was installed before and isn't any more (spec §66 "Website disconnected").
        await alert_service.raise_alert(
            db, organization_id=website.organization_id, type=alert_service.AlertType.WEBSITE_DISCONNECTED,
            severity="warning", dedupe_key=alert_service.website_disconnected_key(website.id),
            title=f"Tracking snippet not found on {website.domain}",
            message=f"The last check of https://{website.domain}/ didn't find the Click Shield snippet: {result.detail}",
            resource_type="website", resource_id=str(website.id),
        )
    await db.commit()
    await db.refresh(website)
    return VerifyOut(verified=result.verified, method=result.method, detail=result.detail, website=website_out(website))


@router.delete("/{website_id}", response_model=WebsiteOut)
async def delete_website(
    website_id: uuid.UUID, request: Request, current_user: WebsiteManager, db: AsyncSession = Depends(get_db)
) -> WebsiteOut:
    """Soft delete: the token stops working, sessions and history are kept."""
    website = await _load(db, current_user.organization_id, website_id, for_update=True)
    if website.is_active:
        website.is_active = False
        _audit(db, request, current_user, website, AuditAction.WEBSITE_DELETED)
        await db.commit()
        await db.refresh(website)
    return website_out(website)

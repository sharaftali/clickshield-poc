"""
Organization members and invitations (spec §62 RBAC, task 030).

One organization per user for the POC (users.organization_id). Agencies managing
several organizations (§68) need an organization_members table: Phase 2.
Invitations are random tokens; only their sha256 is stored, and they expire
after INVITE_EXPIRY_HOURS.
"""
from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, EmailStr, field_validator
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.core.queue import SEND_EMAIL_JOB, enqueue_job
from app.dependencies.permissions import Permission
from app.models import AuditResult, Organization, OrganizationInvitation, User, UserRole
from app.services import audit_service
from app.services.audit_service import AuditAction

router = APIRouter(prefix="/api/v1/users", tags=["users"])

Viewer = Permission("dashboard:view")
UserManager = Permission("users:manage")


class MemberOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: str
    full_name: str | None = None
    role: UserRole
    is_active: bool
    alert_emails: bool
    created_at: datetime


class InvitationIn(BaseModel):
    email: EmailStr
    role: UserRole = UserRole.MEMBER

    @field_validator("email")
    @classmethod
    def normalize(cls, value: str) -> str:
        return str(value).strip().lower()


class InvitationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: str
    role: UserRole
    expires_at: datetime
    accepted_at: datetime | None = None
    revoked_at: datetime | None = None
    created_at: datetime


class InvitationCreated(InvitationOut):
    # Returned once, so the owner can share it when email isn't configured.
    invite_url: str


class MemberUpdateIn(BaseModel):
    role: UserRole | None = None
    is_active: bool | None = None


class MyPreferencesIn(BaseModel):
    alert_emails: bool


def hash_invite_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def invite_url(token: str) -> str:
    return f"{settings.FRONTEND_APP_URL.rstrip('/')}/accept-invite?token={token}"


async def _active_owner_count(db: AsyncSession, organization_id) -> int:
    return int(await db.scalar(
        select(func.count()).select_from(User).where(
            User.organization_id == organization_id, User.role == UserRole.OWNER, User.is_active.is_(True)
        )
    ) or 0)


@router.get("", response_model=list[MemberOut])
async def list_members(current_user: Viewer, db: AsyncSession = Depends(get_db)) -> list[User]:
    rows = await db.execute(
        select(User).where(User.organization_id == current_user.organization_id).order_by(User.created_at)
    )
    return list(rows.scalars())


@router.patch("/me", response_model=MemberOut)
async def update_my_preferences(
    payload: MyPreferencesIn, current_user: Viewer, db: AsyncSession = Depends(get_db)
) -> User:
    user = await db.get(User, current_user.id)
    user.alert_emails = payload.alert_emails
    await db.commit()
    await db.refresh(user)
    return user


@router.patch("/{user_id}", response_model=MemberOut)
async def update_member(
    user_id: uuid.UUID,
    payload: MemberUpdateIn,
    request: Request,
    current_user: UserManager,
    db: AsyncSession = Depends(get_db),
) -> User:
    user = (
        await db.execute(
            select(User).where(User.id == user_id, User.organization_id == current_user.organization_id).with_for_update()
        )
    ).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found in this organization.")

    loses_owner = user.role == UserRole.OWNER and user.is_active and (
        (payload.role is not None and payload.role != UserRole.OWNER) or payload.is_active is False
    )
    if loses_owner and await _active_owner_count(db, current_user.organization_id) <= 1:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An organization needs at least one active owner. Make someone else owner first.",
        )

    def audit(action: AuditAction, details: dict) -> None:
        audit_service.record(
            db, action=action, result=AuditResult.SUCCESS, organization_id=current_user.organization_id,
            user_id=current_user.id, resource_type="user", resource_id=user.id, request=request,
            details={"email": user.email, **details},
        )

    if payload.role is not None and payload.role != user.role:
        audit(AuditAction.USER_ROLE_CHANGED, {"from": user.role, "to": payload.role})
        user.role = payload.role
    if payload.is_active is not None and payload.is_active != user.is_active:
        audit(AuditAction.USER_ACTIVATED if payload.is_active else AuditAction.USER_DEACTIVATED, {})
        user.is_active = payload.is_active
    await db.commit()
    await db.refresh(user)
    return user


@router.get("/invitations", response_model=list[InvitationOut])
async def list_invitations(current_user: UserManager, db: AsyncSession = Depends(get_db)) -> list[OrganizationInvitation]:
    rows = await db.execute(
        select(OrganizationInvitation)
        .where(
            OrganizationInvitation.organization_id == current_user.organization_id,
            OrganizationInvitation.accepted_at.is_(None),
            OrganizationInvitation.revoked_at.is_(None),
            OrganizationInvitation.expires_at > datetime.now(timezone.utc),
        )
        .order_by(OrganizationInvitation.created_at.desc())
    )
    return list(rows.scalars())


@router.post("/invitations", response_model=InvitationCreated, status_code=status.HTTP_201_CREATED)
async def invite_member(
    payload: InvitationIn,
    request: Request,
    current_user: UserManager,
    db: AsyncSession = Depends(get_db),
) -> InvitationCreated:
    if await db.scalar(select(User.id).where(User.email == payload.email)):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This email already has a Click Shield account (one organization per user for now).",
        )
    now = datetime.now(timezone.utc)
    # A new invitation replaces any open one for the same address.
    for old in (
        await db.execute(
            select(OrganizationInvitation).where(
                OrganizationInvitation.organization_id == current_user.organization_id,
                OrganizationInvitation.email == payload.email,
                OrganizationInvitation.accepted_at.is_(None),
                OrganizationInvitation.revoked_at.is_(None),
            )
        )
    ).scalars():
        old.revoked_at = now

    token = secrets.token_urlsafe(32)
    invitation = OrganizationInvitation(
        organization_id=current_user.organization_id, email=payload.email, role=payload.role,
        token_hash=hash_invite_token(token), expires_at=now + timedelta(hours=settings.INVITE_EXPIRY_HOURS),
        invited_by=current_user.id,
    )
    db.add(invitation)
    await db.flush()
    audit_service.record(
        db, action=AuditAction.USER_INVITED, result=AuditResult.SUCCESS,
        organization_id=current_user.organization_id, user_id=current_user.id,
        resource_type="invitation", resource_id=invitation.id, request=request,
        details={"email": payload.email, "role": payload.role},
    )
    organization = await db.get(Organization, current_user.organization_id)
    await db.commit()
    await db.refresh(invitation)

    url = invite_url(token)
    await enqueue_job(
        SEND_EMAIL_JOB,
        payload.email,
        f"You're invited to {organization.name} on Click Shield",
        f"{current_user.full_name or current_user.email} invited you to join {organization.name} on Click Shield "
        f"as {payload.role.value}.\n\nAccept the invitation (valid {settings.INVITE_EXPIRY_HOURS} hours):\n{url}\n",
    )
    return InvitationCreated(**InvitationOut.model_validate(invitation).model_dump(), invite_url=url)


@router.delete("/invitations/{invitation_id}", response_model=InvitationOut)
async def revoke_invitation(
    invitation_id: uuid.UUID,
    request: Request,
    current_user: UserManager,
    db: AsyncSession = Depends(get_db),
) -> OrganizationInvitation:
    invitation = (
        await db.execute(
            select(OrganizationInvitation).where(
                OrganizationInvitation.id == invitation_id,
                OrganizationInvitation.organization_id == current_user.organization_id,
            )
        )
    ).scalar_one_or_none()
    if invitation is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invitation not found.")
    if invitation.revoked_at is None and invitation.accepted_at is None:
        invitation.revoked_at = datetime.now(timezone.utc)
        audit_service.record(
            db, action=AuditAction.INVITATION_REVOKED, result=AuditResult.SUCCESS,
            organization_id=current_user.organization_id, user_id=current_user.id,
            resource_type="invitation", resource_id=invitation.id, request=request,
            details={"email": invitation.email},
        )
        await db.commit()
        await db.refresh(invitation)
    return invitation


async def find_open_invitation(db: AsyncSession, token: str) -> OrganizationInvitation | None:
    invitation = (
        await db.execute(
            select(OrganizationInvitation).where(OrganizationInvitation.token_hash == hash_invite_token(token))
        )
    ).scalar_one_or_none()
    if (
        invitation is None
        or invitation.accepted_at is not None
        or invitation.revoked_at is not None
        or invitation.expires_at <= datetime.now(timezone.utc)
    ):
        return None
    return invitation


from __future__ import annotations

import re
from datetime import timedelta

from fastapi import HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.core.security import create_token, hash_password, verify_password
from app.models.enums import AuditResult, ProtectionMode, UserRole
from app.models.organization import Organization, User
from app.schemas.auth import (
    AuthResponse,
    AuthenticatedUserResponse,
    InvitePreview,
    OrganizationSummary,
    TokenPair,
    UserPublic,
)
from app.services import audit_service
from app.services.audit_service import AuditAction


def user_public(user: User) -> UserPublic:
    return UserPublic(
        id=str(user.id),
        organization_id=str(user.organization_id),
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        is_active=user.is_active,
        is_platform_admin=bool(user.is_platform_admin),
        alert_emails=bool(user.alert_emails),
    )


def organization_summary(organization: Organization) -> OrganizationSummary:
    return OrganizationSummary(
        id=str(organization.id),
        name=organization.name,
        slug=organization.slug,
        protection_mode=organization.protection_mode,
        is_active=organization.is_active,
    )


def issue_tokens(user: User) -> TokenPair:
    return TokenPair(
        access_token=create_token(str(user.id), "access"),
        refresh_token=create_token(str(user.id), "refresh", expires_delta=timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)),
        expires_in_minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES,
    )


class AuthService:
    @staticmethod
    def _slugify(value: str) -> str:
        slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
        return slug or "organization"

    @staticmethod
    async def _get_user_by_email(db: AsyncSession, email: str) -> User | None:
        result = await db.execute(
            select(User)
            .options(selectinload(User.organization))
            .where(User.email == email)
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def _get_organization_by_slug(db: AsyncSession, slug: str) -> Organization | None:
        result = await db.execute(select(Organization).where(Organization.slug == slug))
        return result.scalar_one_or_none()

    @staticmethod
    async def register(db: AsyncSession, *, full_name: str, email: str, password: str, organization_name: str, organization_slug: str | None, protection_mode: ProtectionMode, request: Request | None = None) -> AuthResponse:
        normalized_email = email.strip().lower()
        normalized_name = full_name.strip()
        if not normalized_name:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Full name is required.")

        if await AuthService._get_user_by_email(db, normalized_email):
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="An account with this email already exists.")

        slug = (organization_slug or organization_name).strip()
        slug = AuthService._slugify(slug)
        if await AuthService._get_organization_by_slug(db, slug):
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Organization slug already exists.")

        organization = Organization(
            name=organization_name.strip(),
            slug=slug,
            protection_mode=protection_mode,
            is_active=True,
        )
        user = User(
            organization=organization,
            email=normalized_email,
            hashed_password=hash_password(password),
            full_name=normalized_name,
            role=UserRole.OWNER,
            is_active=True,
        )

        db.add_all([organization, user])
        await db.flush()
        audit_service.record(
            db,
            action=AuditAction.USER_REGISTER,
            result=AuditResult.SUCCESS,
            organization_id=organization.id,
            user_id=user.id,
            resource_type="user",
            resource_id=user.id,
            request=request,
            details={"email": user.email, "organization_slug": organization.slug},
        )
        # Nothing else commits this request: without it the account was never persisted.
        await db.commit()

        access_token = create_token(str(user.id), "access")
        refresh_token = create_token(str(user.id), "refresh", expires_delta=timedelta(days=7))

        return AuthResponse(
            user=user_public(user),
            organization=organization_summary(organization),
            tokens=TokenPair(
                access_token=access_token,
                refresh_token=refresh_token,
                expires_in_minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES,
            ),
        )

    @staticmethod
    async def login(db: AsyncSession, *, email: str, password: str, request: Request | None = None) -> AuthResponse:
        normalized_email = email.strip().lower()
        user = await AuthService._get_user_by_email(db, normalized_email)

        async def reject(reason: str, detail: str = "Invalid email or password.") -> HTTPException:
            # Commit the audit row before the request fails (spec §44, §62).
            audit_service.record(
                db,
                action=AuditAction.USER_LOGIN_FAILED,
                result=AuditResult.FAILED,
                organization_id=user.organization_id if user is not None else None,
                user_id=user.id if user is not None else None,
                resource_type="user",
                request=request,
                details={"email": normalized_email, "reason": reason},
            )
            await db.commit()
            return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)

        if user is None:
            raise await reject("unknown_email")
        if not verify_password(password, user.hashed_password):
            raise await reject("wrong_password")
        if not user.is_active:
            raise await reject("inactive", "Account is inactive.")

        audit_service.record(
            db,
            action=AuditAction.USER_LOGIN_SUCCESS,
            result=AuditResult.SUCCESS,
            organization_id=user.organization_id,
            user_id=user.id,
            resource_type="user",
            resource_id=user.id,
            request=request,
            details={"email": normalized_email},
        )
        await db.commit()

        await db.refresh(user)
        organization = user.organization
        if organization is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found for this user.")

        access_token = create_token(str(user.id), "access")
        refresh_token = create_token(str(user.id), "refresh", expires_delta=timedelta(days=7))

        return AuthResponse(
            user=user_public(user),
            organization=organization_summary(organization),
            tokens=TokenPair(
                access_token=access_token,
                refresh_token=refresh_token,
                expires_in_minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES,
            ),
        )

    @staticmethod
    async def refresh(db: AsyncSession, *, refresh_token: str) -> TokenPair:
        from app.core.security import decode_token

        payload = decode_token(refresh_token)
        if payload.get("token_type") != "refresh":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token is invalid.")

        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token payload is invalid.")

        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
        if user is None or not user.is_active:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User is no longer active.")

        access_token = create_token(str(user.id), "access")
        new_refresh_token = create_token(str(user.id), "refresh", expires_delta=timedelta(days=7))

        return TokenPair(
            access_token=access_token,
            refresh_token=new_refresh_token,
            expires_in_minutes=60,
        )

    @staticmethod
    async def get_authenticated_user(db: AsyncSession, user: User) -> AuthenticatedUserResponse:
        organization = user.organization
        if organization is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found for this user.")

        return AuthenticatedUserResponse(
            user=user_public(user),
            organization=organization_summary(organization),
        )

    @staticmethod
    async def preview_invitation(db: AsyncSession, token: str) -> InvitePreview:
        from app.api.users import find_open_invitation

        invitation = await find_open_invitation(db, token)
        if invitation is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="This invitation is invalid or has expired.")
        organization = await db.get(Organization, invitation.organization_id)
        return InvitePreview(organization_name=organization.name, email=invitation.email, role=invitation.role)

    @staticmethod
    async def accept_invitation(
        db: AsyncSession, *, token: str, full_name: str, password: str, request: Request | None = None
    ) -> AuthResponse:
        from datetime import datetime, timezone

        from app.api.users import find_open_invitation

        invitation = await find_open_invitation(db, token)
        if invitation is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="This invitation is invalid or has expired.")
        if await AuthService._get_user_by_email(db, invitation.email):
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="An account with this email already exists.")
        organization = await db.get(Organization, invitation.organization_id)
        user = User(
            organization_id=organization.id, email=invitation.email, hashed_password=hash_password(password),
            full_name=full_name.strip(), role=invitation.role, is_active=True,
        )
        db.add(user)
        invitation.accepted_at = datetime.now(timezone.utc)
        await db.flush()
        audit_service.record(
            db, action=AuditAction.INVITATION_ACCEPTED, result=AuditResult.SUCCESS,
            organization_id=organization.id, user_id=user.id, resource_type="invitation",
            resource_id=invitation.id, request=request, details={"email": user.email, "role": user.role},
        )
        await db.commit()
        return AuthResponse(user=user_public(user), organization=organization_summary(organization), tokens=issue_tokens(user))

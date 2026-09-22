from __future__ import annotations

import re
from datetime import timedelta

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.security import create_token, hash_password, verify_password
from app.models.enums import ProtectionMode, UserRole
from app.models.organization import Organization, User
from app.schemas.auth import AuthResponse, AuthenticatedUserResponse, OrganizationSummary, TokenPair, UserPublic


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
    async def register(db: AsyncSession, *, full_name: str, email: str, password: str, organization_name: str, organization_slug: str | None, protection_mode: ProtectionMode) -> AuthResponse:
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

        access_token = create_token(str(user.id), "access")
        refresh_token = create_token(str(user.id), "refresh", expires_delta=timedelta(days=7))

        return AuthResponse(
            user=UserPublic(
                id=str(user.id),
                organization_id=str(user.organization_id),
                email=user.email,
                full_name=user.full_name,
                role=user.role,
                is_active=user.is_active,
            ),
            organization=OrganizationSummary(
                id=str(organization.id),
                name=organization.name,
                slug=organization.slug,
                protection_mode=organization.protection_mode,
                is_active=organization.is_active,
            ),
            tokens=TokenPair(
                access_token=access_token,
                refresh_token=refresh_token,
                expires_in_minutes=60,
            ),
        )

    @staticmethod
    async def login(db: AsyncSession, *, email: str, password: str) -> AuthResponse:
        normalized_email = email.strip().lower()
        user = await AuthService._get_user_by_email(db, normalized_email)
        if user is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password.")
        if not verify_password(password, user.hashed_password):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password.")
        if not user.is_active:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Account is inactive.")

        await db.refresh(user)
        organization = user.organization
        if organization is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found for this user.")

        access_token = create_token(str(user.id), "access")
        refresh_token = create_token(str(user.id), "refresh", expires_delta=timedelta(days=7))

        return AuthResponse(
            user=UserPublic(
                id=str(user.id),
                organization_id=str(user.organization_id),
                email=user.email,
                full_name=user.full_name,
                role=user.role,
                is_active=user.is_active,
            ),
            organization=OrganizationSummary(
                id=str(organization.id),
                name=organization.name,
                slug=organization.slug,
                protection_mode=organization.protection_mode,
                is_active=organization.is_active,
            ),
            tokens=TokenPair(
                access_token=access_token,
                refresh_token=refresh_token,
                expires_in_minutes=60,
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
            user=UserPublic(
                id=str(user.id),
                organization_id=str(user.organization_id),
                email=user.email,
                full_name=user.full_name,
                role=user.role,
                is_active=user.is_active,
            ),
            organization=OrganizationSummary(
                id=str(organization.id),
                name=organization.name,
                slug=organization.slug,
                protection_mode=organization.protection_mode,
                is_active=organization.is_active,
            ),
        )

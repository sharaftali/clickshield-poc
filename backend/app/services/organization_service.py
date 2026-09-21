from __future__ import annotations

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.organization import Organization, User
from app.schemas.organization import OrganizationResponse


class OrganizationService:
    @staticmethod
    async def get_my_organization(db: AsyncSession, user: User) -> OrganizationResponse:
        result = await db.execute(select(Organization).where(Organization.id == user.organization_id))
        organization = result.scalar_one_or_none()
        if organization is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Organization not found.",
            )

        return OrganizationResponse(
            id=str(organization.id),
            name=organization.name,
            slug=organization.slug,
            protection_mode=organization.protection_mode,
            is_active=organization.is_active,
        )

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.dependencies.auth import CurrentUser
from app.schemas.organization import OrganizationResponse
from app.services.organization_service import OrganizationService

router = APIRouter(prefix="/api/v1/organizations", tags=["organizations"])


@router.get("/me", response_model=OrganizationResponse)
async def get_current_organization(
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> OrganizationResponse:
    return await OrganizationService.get_my_organization(db, current_user)

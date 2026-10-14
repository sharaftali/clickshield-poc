from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.dependencies.auth import AdminUser, CurrentUser
from app.schemas.organization import OrganizationResponse, OrganizationUpdateRequest
from app.services.organization_service import OrganizationService

router = APIRouter(prefix="/api/v1/organizations", tags=["organizations"])


@router.get("/me", response_model=OrganizationResponse)
async def get_current_organization(
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> OrganizationResponse:
    return await OrganizationService.get_my_organization(db, current_user)


@router.patch("/me", response_model=OrganizationResponse)
async def update_current_organization(
    payload: OrganizationUpdateRequest,
    request: Request,
    current_user: AdminUser,
    db: AsyncSession = Depends(get_db),
) -> OrganizationResponse:
    """Protection mode and Custom thresholds (spec §54, task 016). Owners / admins only."""
    return await OrganizationService.update_my_organization(db, current_user, payload, request)

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.dependencies.auth import CurrentUser
from app.schemas.auth import AuthResponse, AuthenticatedUserResponse, LoginRequest, RefreshTokenRequest, RegisterRequest, TokenPair
from app.services.auth_service import AuthService

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.post("/register", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
async def register_user(
    payload: RegisterRequest,
    db: AsyncSession = Depends(get_db),
) -> AuthResponse:
    try:
        return await AuthService.register(
            db,
            full_name=payload.full_name,
            email=payload.email,
            password=payload.password,
            organization_name=payload.organization_name,
            organization_slug=payload.organization_slug,
            protection_mode=payload.protection_mode,
        )
    except HTTPException:
        raise


@router.post("/login", response_model=AuthResponse)
async def login_user(
    payload: LoginRequest,
    db: AsyncSession = Depends(get_db),
) -> AuthResponse:
    return await AuthService.login(
        db,
        email=payload.email,
        password=payload.password,
    )


@router.post("/refresh", response_model=TokenPair)
async def refresh_tokens(
    payload: RefreshTokenRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenPair:
    return await AuthService.refresh(db, refresh_token=payload.refresh_token)


@router.get("/me", response_model=AuthenticatedUserResponse)
async def get_current_auth_user(
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> AuthenticatedUserResponse:
    return await AuthService.get_authenticated_user(db, current_user)

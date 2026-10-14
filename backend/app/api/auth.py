from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import rate_limit
from app.core.client_ip import ClientIPError, resolve_client_ip
from app.core.config import settings
from app.core.database import get_db
from app.dependencies.auth import CurrentUser
from app.schemas.auth import (
    AcceptInviteRequest,
    AuthResponse,
    AuthenticatedUserResponse,
    InvitePreview,
    LoginRequest,
    RefreshTokenRequest,
    RegisterRequest,
    TokenPair,
)
from app.services.auth_service import AuthService

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


def _ip(request: Request) -> str:
    try:
        return resolve_client_ip(request)
    except ClientIPError:
        return "unknown"


async def _limit_signups(request: Request) -> None:
    await rate_limit.enforce(f"register:ip:{_ip(request)}", settings.REGISTER_RATE_LIMIT_PER_IP_PER_HOUR, 3600,
                             "Too many sign-ups from this address. Try again later.")


@router.post("/register", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
async def register_user(
    payload: RegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> AuthResponse:
    await _limit_signups(request)
    try:
        return await AuthService.register(
            db,
            full_name=payload.full_name,
            email=payload.email,
            password=payload.password,
            organization_name=payload.organization_name,
            organization_slug=payload.organization_slug,
            protection_mode=payload.protection_mode,
            request=request,
        )
    except HTTPException:
        raise


@router.post("/login", response_model=AuthResponse)
async def login_user(
    payload: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> AuthResponse:
    """Brute-force protection (task 031): per IP per minute, and per email after repeated failures."""
    await rate_limit.enforce(f"login:ip:{_ip(request)}", settings.LOGIN_RATE_LIMIT_PER_IP_PER_MINUTE, 60,
                             "Too many login attempts. Wait a minute and try again.")
    failures_key = f"login:fail:{payload.email}"
    window = settings.LOGIN_FAILURE_WINDOW_SECONDS
    if await rate_limit.peek(failures_key, window) >= settings.LOGIN_FAILURES_PER_EMAIL:
        blocked = await rate_limit.hit(failures_key, settings.LOGIN_FAILURES_PER_EMAIL, window, cost=0)
        raise rate_limit.too_many(blocked, "Too many failed logins for this account. Try again later.")
    try:
        return await AuthService.login(
            db,
            email=payload.email,
            password=payload.password,
            request=request,
        )
    except HTTPException as exc:
        if exc.status_code == status.HTTP_401_UNAUTHORIZED:
            await rate_limit.hit(failures_key, settings.LOGIN_FAILURES_PER_EMAIL, window)
        raise


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


@router.get("/invitations/{token}", response_model=InvitePreview)
async def preview_invitation(token: str, db: AsyncSession = Depends(get_db)) -> InvitePreview:
    """Public: what an invite link is for (task 030)."""
    return await AuthService.preview_invitation(db, token)


@router.post("/accept-invite", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
async def accept_invitation(
    payload: AcceptInviteRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> AuthResponse:
    """Public: create the invited account in the inviting organization and sign in."""
    await _limit_signups(request)
    return await AuthService.accept_invitation(
        db, token=payload.token, full_name=payload.full_name, password=payload.password, request=request
    )

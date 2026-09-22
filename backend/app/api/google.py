from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.crypto import decrypt, encrypt
from app.core.database import get_db
from app.dependencies.auth import CurrentUser
from app.models import GoogleConnection, Organization
from app.schemas.google import GoogleAccountOut, GoogleConnectionOut, SelectCustomerIn
from app.services.google_oauth import (
    build_authorization_url,
    exchange_code_for_tokens,
    fetch_user_email,
    generate_state_token,
    list_accessible_customer_accounts,
    refresh_access_token,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/google", tags=["google"])

_pending_states: dict[str, dict[str, Any]] = {}


@router.get("/connect")
async def google_connect(
    current_user: CurrentUser,
) -> RedirectResponse:
    """Start the Google Ads OAuth flow for the current organization."""
    state = generate_state_token()
    _pending_states[state] = {
        "organization_id": str(current_user.organization_id),
        "user_id": str(current_user.id),
        "created_at": datetime.now(timezone.utc),
    }
    logger.info("Initiating Google OAuth flow for org=%s user=%s", current_user.organization_id, current_user.id)
    return RedirectResponse(build_authorization_url(state=state))


@router.get("/callback")
async def google_callback(
    code: str = Query(...),
    state: str = Query(...),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Complete the OAuth flow and store encrypted refresh token for the selected organization."""
    pending = _pending_states.get(state)
    if not pending:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired OAuth state",
        )
    _pending_states.pop(state, None)

    organization_id = pending.get("organization_id")
    if not organization_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OAuth state is missing the organization context.",
        )

    try:
        tokens = await exchange_code_for_tokens(code)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    access_token = tokens.get("access_token")
    refresh_token = tokens.get("refresh_token")
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Google OAuth did not return a refresh token. Ensure 'offline' access is granted.",
        )

    email = await fetch_user_email(access_token or "") if access_token else None

    result = await db.execute(select(Organization).where(Organization.id == organization_id))
    org = result.scalar_one_or_none()
    if org is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="No organization found for this OAuth flow.",
        )

    existing = await db.execute(
        select(GoogleConnection)
        .where(
            GoogleConnection.organization_id == org.id,
            GoogleConnection.google_account_email == email,
        )
        .limit(1)
    )
    connection = existing.scalar_one_or_none()

    if connection is None:
        connection = GoogleConnection(
            organization_id=org.id,
            refresh_token_encrypted=encrypt(refresh_token),
            customer_id="",
            google_account_email=email,
            is_active=True,
        )
        db.add(connection)
    else:
        connection.refresh_token_encrypted = encrypt(refresh_token)
        connection.google_account_email = email
        connection.is_active = True

    await db.commit()
    await db.refresh(connection)

    logger.info(
        "Google OAuth complete for org=%s, connection=%s, email=%s",
        org.id,
        connection.id,
        email,
    )

    return {
        "status": "ok",
        "connection_id": str(connection.id),
        "google_account_email": email,
        "organization_id": str(org.id),
        "next_step": "POST /api/v1/google/select-customer with customer_id",
    }


@router.get("/accounts", response_model=list[GoogleAccountOut])
async def list_google_accounts(
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> list[GoogleAccountOut]:
    """List accessible Google Ads customer accounts for the current tenant."""
    result = await db.execute(
        select(GoogleConnection)
        .where(GoogleConnection.organization_id == current_user.organization_id)
        .order_by(GoogleConnection.created_at.desc())
    )
    connections = result.scalars().all()

    accounts: list[GoogleAccountOut] = []
    for connection in connections:
        if not connection.refresh_token_encrypted:
            continue
        try:
            refresh_token = decrypt(connection.refresh_token_encrypted)
            access_payload = await refresh_access_token(refresh_token)
            access_token = access_payload.get("access_token")
        except ValueError:
            continue
        if access_token:
            accounts.extend(await list_accessible_customer_accounts(access_token))

    if accounts:
        unique_accounts: dict[str, GoogleAccountOut] = {}
        for account in accounts:
            unique_accounts[account.customer_id] = account
        return list(unique_accounts.values())

    fallback = [
        GoogleAccountOut(
            customer_id=connection.customer_id,
            descriptive_name=connection.google_account_email or "Google Ads connection",
            is_manager=False,
            is_test_account=False,
        )
        for connection in connections
        if connection.customer_id and connection.customer_id.isdigit()
    ]
    return fallback


@router.get("/connections", response_model=list[GoogleConnectionOut])
async def list_connections(
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> list[GoogleConnection]:
    result = await db.execute(
        select(GoogleConnection)
        .where(GoogleConnection.organization_id == current_user.organization_id)
        .order_by(GoogleConnection.created_at.desc())
    )
    return list(result.scalars().all())


@router.post("/select-customer", response_model=GoogleConnectionOut)
async def select_customer(
    payload: SelectCustomerIn,
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> GoogleConnection:
    """Persist the specific Google Ads customer account selected by the user."""
    result = await db.execute(
        select(GoogleConnection)
        .where(
            GoogleConnection.organization_id == current_user.organization_id,
            GoogleConnection.is_active.is_(True),
        )
        .order_by(GoogleConnection.created_at.desc())
        .limit(1)
    )
    connection = result.scalar_one_or_none()

    if connection is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No active Google connection found for this organization. Please connect Google first.",
        )

    connection.customer_id = payload.customer_id
    connection.login_customer_id = payload.login_customer_id
    connection.google_account_email = payload.google_account_email or connection.google_account_email
    connection.is_active = True

    await db.commit()
    await db.refresh(connection)
    return connection


@router.get("/health")
async def google_health() -> dict[str, str]:
    return {"status": "ok", "provider": "google"}

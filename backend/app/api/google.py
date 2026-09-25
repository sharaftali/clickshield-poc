from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from urllib.parse import urlencode
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.crypto import decrypt, encrypt
from app.core.database import get_db
from app.core.security import decode_token, get_user_from_token
from app.dependencies.auth import CurrentUser
from app.models import CampaignStatus, CampaignType, GoogleCampaign, GoogleConnection, Organization
from app.schemas.google import (
    CampaignOut,
    CampaignSyncSummary,
    GoogleAccountOut,
    GoogleConnectionOut,
    SelectCustomerIn,
    UpdateCampaignProtectionIn,
)
from app.services.google_oauth import (
    build_authorization_url,
    exchange_code_for_tokens,
    fetch_user_email,
    generate_state_token,
    list_accessible_customer_accounts,
    list_google_campaigns,
    refresh_access_token,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/google", tags=["google"])

_pending_states: dict[str, dict[str, Any]] = {}


def _google_frontend_redirect(status_value: str, message: str) -> str:
    query = urlencode(
        {
            "google_oauth_status": status_value,
            "google_oauth_message": message,
        }
    )
    return f"{settings.FRONTEND_APP_URL.rstrip('/')}/google?{query}"


async def _resolve_google_connect_user(
    request: Request,
    db: AsyncSession,
):
    authorization = request.headers.get("authorization", "")
    token = ""
    if authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
    if not token:
        token = request.query_params.get("token", "").strip()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Access token is required to connect Google Ads.",
        )

    payload = decode_token(token)
    if payload.get("token_type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Access token is required to connect Google Ads.",
        )

    return await get_user_from_token(db, token)


async def _get_latest_active_connection(
    db: AsyncSession,
    organization_id,
) -> GoogleConnection | None:
    result = await db.execute(
        select(GoogleConnection)
        .where(
            GoogleConnection.organization_id == organization_id,
            GoogleConnection.is_active.is_(True),
        )
        .order_by(GoogleConnection.created_at.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()


def _campaign_supports_ip_exclusion(campaign_type: CampaignType) -> bool:
    return campaign_type not in {CampaignType.PERFORMANCE_MAX, CampaignType.VIDEO}


def _to_campaign_out(campaign: GoogleCampaign) -> CampaignOut:
    return CampaignOut(
        id=campaign.id,
        campaign_id=campaign.campaign_id,
        name=campaign.name,
        campaign_type=campaign.campaign_type.value,
        status=campaign.status.value,
        protection_enabled=campaign.protection_enabled,
        exclusion_count=campaign.exclusion_count,
        supports_ip_exclusion=_campaign_supports_ip_exclusion(campaign.campaign_type),
    )


@router.get("/connect")
async def google_connect(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> RedirectResponse:
    """Start the Google Ads OAuth flow for the current organization."""
    current_user = await _resolve_google_connect_user(request, db)
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
) -> RedirectResponse:
    """Complete the OAuth flow and store encrypted refresh token for the selected organization."""
    pending = _pending_states.get(state)
    if not pending:
        return RedirectResponse(
            _google_frontend_redirect(
                "error",
                "Invalid or expired Google OAuth state. Please connect again.",
            ),
            status_code=status.HTTP_302_FOUND,
        )
    _pending_states.pop(state, None)

    organization_id = pending.get("organization_id")
    if not organization_id:
        return RedirectResponse(
            _google_frontend_redirect(
                "error",
                "Google OAuth state is missing organization context. Please retry.",
            ),
            status_code=status.HTTP_302_FOUND,
        )

    try:
        tokens = await exchange_code_for_tokens(code)
    except ValueError as exc:
        return RedirectResponse(
            _google_frontend_redirect("error", str(exc)),
            status_code=status.HTTP_302_FOUND,
        )

    access_token = tokens.get("access_token")
    refresh_token = tokens.get("refresh_token")
    if not refresh_token:
        return RedirectResponse(
            _google_frontend_redirect(
                "error",
                "Google OAuth did not return a refresh token. Ensure offline access is granted.",
            ),
            status_code=status.HTTP_302_FOUND,
        )

    email = await fetch_user_email(access_token or "") if access_token else None

    result = await db.execute(select(Organization).where(Organization.id == organization_id))
    org = result.scalar_one_or_none()
    if org is None:
        return RedirectResponse(
            _google_frontend_redirect(
                "error",
                "No organization was found for this Google OAuth flow.",
            ),
            status_code=status.HTTP_302_FOUND,
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

    return RedirectResponse(
        _google_frontend_redirect(
            "success",
            "Google Ads connected successfully. Select a customer account to continue protection setup.",
        ),
        status_code=status.HTTP_302_FOUND,
    )


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
    connection = await _get_latest_active_connection(db, current_user.organization_id)

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


@router.post("/campaigns/sync", response_model=CampaignSyncSummary)
async def sync_campaigns(
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> CampaignSyncSummary:
    connection = await _get_latest_active_connection(db, current_user.organization_id)
    if connection is None or not connection.customer_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Select a Google Ads customer account before syncing campaigns.",
        )

    try:
        refresh_token = decrypt(connection.refresh_token_encrypted)
        token_payload = await refresh_access_token(refresh_token)
        access_token = token_payload.get("access_token")
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Google Ads access token could not be refreshed.",
        )

    try:
        remote_campaigns = await list_google_campaigns(
            access_token=access_token,
            customer_id=connection.customer_id,
            login_customer_id=connection.login_customer_id,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    result = await db.execute(
        select(GoogleCampaign).where(GoogleCampaign.connection_id == connection.id)
    )
    existing_campaigns = {
        campaign.campaign_id: campaign
        for campaign in result.scalars().all()
    }

    created = 0
    updated = 0
    seen_campaign_ids: set[str] = set()

    for remote_campaign in remote_campaigns:
        campaign_id = str(remote_campaign["campaign_id"])
        seen_campaign_ids.add(campaign_id)
        campaign = existing_campaigns.get(campaign_id)
        if campaign is None:
            campaign = GoogleCampaign(
                connection_id=connection.id,
                campaign_id=campaign_id,
                name=str(remote_campaign["name"]),
                campaign_type=CampaignType(str(remote_campaign["campaign_type"])),
                status=CampaignStatus(str(remote_campaign["status"])),
                protection_enabled=bool(remote_campaign["supports_ip_exclusion"]),
            )
            db.add(campaign)
            created += 1
            continue

        campaign.name = str(remote_campaign["name"])
        campaign.campaign_type = CampaignType(str(remote_campaign["campaign_type"]))
        campaign.status = CampaignStatus(str(remote_campaign["status"]))
        if not _campaign_supports_ip_exclusion(campaign.campaign_type):
            campaign.protection_enabled = False
        updated += 1

    removed = 0
    for campaign in existing_campaigns.values():
        if campaign.campaign_id not in seen_campaign_ids:
            campaign.status = CampaignStatus.REMOVED
            campaign.protection_enabled = False
            removed += 1

    await db.commit()
    return CampaignSyncSummary(
        synced=len(remote_campaigns),
        created=created,
        updated=updated,
        removed=removed,
    )


@router.get("/campaigns", response_model=list[CampaignOut])
async def list_campaigns(
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> list[CampaignOut]:
    connection = await _get_latest_active_connection(db, current_user.organization_id)
    if connection is None:
        return []

    result = await db.execute(
        select(GoogleCampaign)
        .where(GoogleCampaign.connection_id == connection.id)
        .order_by(
            GoogleCampaign.protection_enabled.desc(),
            GoogleCampaign.status.asc(),
            GoogleCampaign.name.asc(),
        )
    )
    return [_to_campaign_out(campaign) for campaign in result.scalars().all()]


@router.patch("/campaigns/{campaign_row_id}/protection", response_model=CampaignOut)
async def update_campaign_protection(
    campaign_row_id: uuid.UUID,
    payload: UpdateCampaignProtectionIn,
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> CampaignOut:
    result = await db.execute(
        select(GoogleCampaign)
        .join(GoogleConnection, GoogleConnection.id == GoogleCampaign.connection_id)
        .where(
            GoogleCampaign.id == campaign_row_id,
            GoogleConnection.organization_id == current_user.organization_id,
        )
        .limit(1)
    )
    campaign = result.scalar_one_or_none()
    if campaign is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Campaign was not found for this organization.",
        )

    if payload.protection_enabled and not _campaign_supports_ip_exclusion(campaign.campaign_type):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This Google Ads campaign type does not support IP exclusions.",
        )

    campaign.protection_enabled = payload.protection_enabled
    await db.commit()
    await db.refresh(campaign)
    return _to_campaign_out(campaign)


@router.get("/health")
async def google_health() -> dict[str, str]:
    return {"status": "ok", "provider": "google"}

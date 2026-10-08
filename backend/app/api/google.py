from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from urllib.parse import urlencode
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.crypto import decrypt, encrypt
from app.core.database import get_db
from app.core.security import decode_token, get_user_from_token
from app.dependencies.auth import CurrentUser
from app.models import (
    AuditResult,
    CampaignStatus,
    CampaignType,
    Exclusion,
    ExclusionStatus,
    GoogleCampaign,
    GoogleConnection,
    Organization,
)
from app.schemas.google import (
    CampaignOut,
    CampaignSyncSummary,
    GoogleAccountOut,
    GoogleConnectionOut,
    SelectCustomerIn,
    UpdateCampaignProtectionIn,
)
from app.services import audit_service
from app.services.audit_service import AuditAction
from app.services.exclusion_capacity import campaign_limit
from app.services.google_oauth import (
    GoogleAuthError,
    build_authorization_url,
    count_ip_exclusions_by_campaign,
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
    limit = campaign_limit()
    used = int(campaign.exclusion_count or 0) + int(campaign.external_exclusion_count or 0)
    return CampaignOut(
        id=campaign.id,
        campaign_id=campaign.campaign_id,
        name=campaign.name,
        campaign_type=campaign.campaign_type.value,
        status=campaign.status.value,
        protection_enabled=campaign.protection_enabled,
        exclusion_count=campaign.exclusion_count,
        external_exclusion_count=campaign.external_exclusion_count,
        exclusion_used=used,
        exclusion_limit=limit,
        supports_ip_exclusion=_campaign_supports_ip_exclusion(campaign.campaign_type),
    )


def _audit_connect_failure(db: AsyncSession, pending: dict[str, Any] | None, message: str, request: Request) -> None:
    organization_id = (pending or {}).get("organization_id")
    user_id = (pending or {}).get("user_id")
    audit_service.record(
        db,
        action=AuditAction.GOOGLE_CONNECT,
        result=AuditResult.FAILED,
        organization_id=uuid.UUID(organization_id) if organization_id else None,
        user_id=uuid.UUID(user_id) if user_id else None,
        resource_type="google_connection",
        request=request,
        error=message,
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
    request: Request,
    code: str = Query(...),
    state: str = Query(...),
    db: AsyncSession = Depends(get_db),
) -> RedirectResponse:
    """Complete the OAuth flow and store encrypted refresh token for the selected organization."""
    pending = _pending_states.get(state)
    if not pending:
        _audit_connect_failure(db, None, "Invalid or expired OAuth state", request)
        await db.commit()
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
        _audit_connect_failure(db, pending, str(exc), request)
        await db.commit()
        return RedirectResponse(
            _google_frontend_redirect("error", str(exc)),
            status_code=status.HTTP_302_FOUND,
        )

    access_token = tokens.get("access_token")
    refresh_token = tokens.get("refresh_token")
    if not refresh_token:
        _audit_connect_failure(db, pending, "Google did not return a refresh token", request)
        await db.commit()
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
        # A fresh grant clears any earlier revoked/expired-token state.
        connection.needs_reauth = False
        connection.auth_error = None

    await db.flush()
    audit_service.record(
        db,
        action=AuditAction.GOOGLE_CONNECT,
        result=AuditResult.SUCCESS,
        organization_id=org.id,
        user_id=uuid.UUID(pending["user_id"]) if pending.get("user_id") else None,
        resource_type="google_connection",
        resource_id=connection.id,
        request=request,
        details={"email": email},
    )
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
    request: Request,
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

    previous_customer_id = connection.customer_id
    connection.customer_id = payload.customer_id
    connection.login_customer_id = payload.login_customer_id
    connection.google_account_email = payload.google_account_email or connection.google_account_email
    connection.is_active = True

    audit_service.record(
        db,
        action=AuditAction.GOOGLE_SELECT_CUSTOMER,
        result=AuditResult.SUCCESS,
        organization_id=current_user.organization_id,
        user_id=current_user.id,
        resource_type="google_connection",
        resource_id=connection.id,
        request=request,
        details={
            "customer_id": payload.customer_id,
            "login_customer_id": payload.login_customer_id,
            "previous_customer_id": previous_customer_id or None,
        },
    )
    await db.commit()
    await db.refresh(connection)
    return connection


@router.post("/campaigns/sync", response_model=CampaignSyncSummary)
async def sync_campaigns(
    request: Request,
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> CampaignSyncSummary:
    connection = await _get_latest_active_connection(db, current_user.organization_id)
    if connection is None or not connection.customer_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Select a Google Ads customer account before syncing campaigns.",
        )

    def audit_sync(result: AuditResult, *, error: str | None = None, details: dict | None = None) -> None:
        audit_service.record(
            db,
            action=AuditAction.GOOGLE_CAMPAIGN_SYNC,
            result=result,
            organization_id=current_user.organization_id,
            user_id=current_user.id,
            resource_type="google_connection",
            resource_id=connection.id,
            request=request,
            details={"customer_id": connection.customer_id, **(details or {})},
            error=error,
        )

    try:
        refresh_token = decrypt(connection.refresh_token_encrypted)
        token_payload = await refresh_access_token(refresh_token)
        access_token = token_payload.get("access_token")
    except ValueError as exc:
        if isinstance(exc, GoogleAuthError) and exc.permanent:
            connection.needs_reauth = True
            connection.auth_error = str(exc)[:1000]
        audit_sync(AuditResult.FAILED, error=str(exc))
        await db.commit()
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
        audit_sync(AuditResult.FAILED, error=str(exc))
        await db.commit()
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
            existing_campaigns[campaign_id] = campaign
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

    # IP exclusions the advertiser added by hand share the per-campaign limit (task 012).
    external_counted = await _refresh_external_exclusion_counts(
        db, connection, access_token, list(existing_campaigns.values())
    )

    audit_sync(
        AuditResult.SUCCESS,
        details={"synced": len(remote_campaigns), "created": created, "updated": updated,
                 "removed": removed, "external_exclusions_counted": external_counted},
    )
    await db.commit()
    return CampaignSyncSummary(
        synced=len(remote_campaigns),
        created=created,
        updated=updated,
        removed=removed,
    )


async def _refresh_external_exclusion_counts(
    db: AsyncSession,
    connection: GoogleConnection,
    access_token: str,
    campaigns: list[GoogleCampaign],
) -> bool:
    """external = IP exclusions in Google − Click Shield's ACTIVE ones. False if Google can't be read."""
    try:
        in_google = await count_ip_exclusions_by_campaign(
            access_token=access_token,
            customer_id=connection.customer_id,
            login_customer_id=connection.login_customer_id,
        )
    except ValueError as exc:
        logger.warning("Keeping previous external IP exclusion counts: %s", exc)
        return False

    await db.flush()
    ours = dict(
        (
            await db.execute(
                select(Exclusion.campaign_id, func.count())
                .where(
                    Exclusion.organization_id == connection.organization_id,
                    Exclusion.google_customer_id == connection.customer_id,
                    Exclusion.status == ExclusionStatus.ACTIVE,
                )
                .group_by(Exclusion.campaign_id)
            )
        ).all()
    )
    for campaign in campaigns:
        campaign.external_exclusion_count = max(
            0, in_google.get(campaign.campaign_id, 0) - int(ours.get(campaign.campaign_id, 0))
        )
    return True


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
    request: Request,
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

    previous = campaign.protection_enabled
    campaign.protection_enabled = payload.protection_enabled
    audit_service.record(
        db,
        action=AuditAction.CAMPAIGN_PROTECTION_TOGGLED,
        result=AuditResult.SUCCESS,
        organization_id=current_user.organization_id,
        user_id=current_user.id,
        resource_type="campaign",
        resource_id=campaign.id,
        request=request,
        details={"campaign_id": campaign.campaign_id, "campaign_name": campaign.name,
                 "protection_enabled": payload.protection_enabled, "previous": previous},
    )
    await db.commit()
    await db.refresh(campaign)
    return _to_campaign_out(campaign)


@router.get("/health")
async def google_health() -> dict[str, str]:
    return {"status": "ok", "provider": "google"}

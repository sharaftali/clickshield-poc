from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from urllib.parse import urlencode
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.core.crypto import decrypt, encrypt
from app.core.database import get_db
from app.core.redis import get_redis
from app.dependencies.auth import CurrentUser
from app.dependencies.permissions import Permission
from app.models import (
    AuditResult,
    CampaignStatus,
    CampaignType,
    Exclusion,
    ExclusionStatus,
    GoogleCampaign,
    GoogleCampaignLocation,
    GoogleConnection,
    Organization,
)
from app.schemas.google import (
    CampaignLocationOut,
    CampaignOut,
    CampaignSyncSummary,
    GoogleAccountOut,
    GoogleCompleteIn,
    GoogleConnectionOut,
    SelectCustomerIn,
    UpdateCampaignProtectionIn,
)
from app.services import alert_service, audit_service
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
    pkce_pair,
    list_campaign_locations,
    list_google_campaigns,
    refresh_access_token,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/google", tags=["google"])
GoogleManager = Permission("google:manage")
ProtectionManager = Permission("protection:manage")

OAUTH_STATE_PREFIX = "oauth_state:"


class OAuthStateUnavailable(RuntimeError):
    pass


async def save_oauth_state(state: str, data: dict[str, Any]) -> None:
    """Redis, TTL OAUTH_STATE_TTL_SECONDS (task 033): survives restarts, works across workers."""
    try:
        await get_redis().set(OAUTH_STATE_PREFIX + state, json.dumps(data), ex=settings.OAUTH_STATE_TTL_SECONDS)
    except Exception as exc:  # no in-memory fallback: it would break with several workers
        raise OAuthStateUnavailable(str(exc)) from exc


async def _consume_oauth_state(state: str) -> dict[str, Any] | None:
    """Atomically read and delete (GETDEL): a state works once. None = unknown or expired."""
    try:
        raw = await get_redis().getdel(OAUTH_STATE_PREFIX + state)
    except Exception as exc:
        raise OAuthStateUnavailable(str(exc)) from exc
    return json.loads(raw) if raw else None


def _google_frontend_redirect(status_value: str, message: str) -> str:
    query = urlencode(
        {
            "google_oauth_status": status_value,
            "google_oauth_message": message,
        }
    )
    return f"{settings.FRONTEND_APP_URL.rstrip('/')}/google?{query}"


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


def _to_campaign_out(campaign: GoogleCampaign, locations: list[GoogleCampaignLocation] | None = None) -> CampaignOut:
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
        geo_target_type=campaign.geo_target_type,
        locations=[CampaignLocationOut.model_validate(location) for location in locations or []],
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


@router.post("/connect")
async def google_connect(
    request: Request,
    current_user: GoogleManager,
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    """Start the Google Ads OAuth flow (task 033). Authenticated with the normal Authorization
    header; the frontend then navigates to the returned URL. No JWT ever appears in a URL."""
    state = generate_state_token()
    verifier, challenge = pkce_pair()
    try:
        await save_oauth_state(state, {
            "organization_id": str(current_user.organization_id),
            "user_id": str(current_user.id),
            "code_verifier": verifier,
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
    except OAuthStateUnavailable as exc:
        logger.error("Cannot start Google OAuth: Redis unavailable (%s)", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Google connection is temporarily unavailable (state store down). Please try again shortly.",
        ) from exc
    audit_service.record(
        db, action=AuditAction.GOOGLE_CONNECT_STARTED, result=AuditResult.PENDING,
        organization_id=current_user.organization_id, user_id=current_user.id,
        resource_type="google_connection", request=request,
    )
    await db.commit()
    logger.info("Initiating Google OAuth flow for org=%s user=%s", current_user.organization_id, current_user.id)
    return {"authorization_url": build_authorization_url(state=state, code_challenge=challenge)}


class OAuthCompletionError(Exception):
    """The OAuth flow can't finish. The message is safe to show the user."""


async def _store_connection(db: AsyncSession, request: Request, pending: dict[str, Any], code: str) -> GoogleConnection:
    """Exchange the authorization code and save the encrypted refresh token for the state's organization.

    `pending` must already be verified to belong to the caller. Audits failures itself and
    raises OAuthCompletionError; never logs the code or any token.
    """
    organization_id = pending.get("organization_id")
    if not organization_id:
        raise OAuthCompletionError("Google OAuth state is missing organization context. Please retry.")

    try:
        tokens = await exchange_code_for_tokens(code, pending.get("code_verifier"))
    except ValueError as exc:
        _audit_connect_failure(db, pending, str(exc), request)
        await db.commit()
        raise OAuthCompletionError(str(exc)) from exc

    access_token = tokens.get("access_token")
    refresh_token = tokens.get("refresh_token")
    if not refresh_token:
        _audit_connect_failure(db, pending, "Google did not return a refresh token", request)
        await db.commit()
        raise OAuthCompletionError("Google OAuth did not return a refresh token. Ensure offline access is granted.")

    email = await fetch_user_email(access_token or "") if access_token else None

    result = await db.execute(select(Organization).where(Organization.id == organization_id))
    org = result.scalar_one_or_none()
    if org is None:
        raise OAuthCompletionError("No organization was found for this Google OAuth flow.")

    # Reuse the connection of the same Google account. Without an email we can't tell
    # which account this is: create a new connection rather than overwrite another one.
    connection = None
    if email:
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
    await alert_service.resolve(db, dedupe_key=alert_service.auth_expired_key(connection.id))
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
    return connection


@router.post("/complete")
async def google_complete(
    payload: GoogleCompleteIn,
    request: Request,
    current_user: GoogleManager,
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    """Finish the Google Ads OAuth flow (SEC-01). The dashboard receives Google's redirect and
    posts `code` + `state` here with the user's Bearer token. The state must belong to that
    user and organization, so a consent link started by someone else can't attach a victim's
    Google account to the attacker's organization."""
    caller = {"organization_id": str(current_user.organization_id), "user_id": str(current_user.id)}
    try:
        pending = await _consume_oauth_state(payload.state)
    except OAuthStateUnavailable as exc:
        logger.error("Cannot complete Google OAuth: Redis unavailable (%s)", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Google connection is temporarily unavailable (state store down). Please try again shortly.",
        ) from exc
    if not pending:
        _audit_connect_failure(db, caller, "Invalid or expired OAuth state", request)
        await db.commit()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired Google OAuth state.")

    if pending.get("user_id") != caller["user_id"] or pending.get("organization_id") != caller["organization_id"]:
        # The state is already consumed, so the code is wasted too. Never log the code or state.
        logger.warning(
            "SECURITY: Google OAuth completion refused: the state was started by a different user or "
            "organization (completing user=%s, organization=%s)", current_user.id, current_user.organization_id,
        )
        _audit_connect_failure(db, caller, "OAuth state belongs to a different user or organization", request)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This Google connection was started by a different user. Please connect again from your own session.",
        )

    try:
        connection = await _store_connection(db, request, pending, payload.code)
    except OAuthCompletionError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return {"status": "success", "connection_id": str(connection.id)}


@router.get("/callback")
async def google_callback(
    request: Request,
    code: str = Query(...),
    state: str = Query(...),
    db: AsyncSession = Depends(get_db),
) -> RedirectResponse:
    """Legacy redirect target (replaced by POST /complete in the next commit)."""
    try:
        pending = await _consume_oauth_state(state)
    except OAuthStateUnavailable:
        return RedirectResponse(
            _google_frontend_redirect("error", "Google connection is temporarily unavailable. Please connect again."),
            status_code=status.HTTP_302_FOUND,
        )
    if not pending:
        return RedirectResponse(
            _google_frontend_redirect("error", "Invalid or expired Google OAuth state. Please connect again."),
            status_code=status.HTTP_302_FOUND,
        )
    try:
        await _store_connection(db, request, pending, code)
    except OAuthCompletionError as exc:
        return RedirectResponse(_google_frontend_redirect("error", str(exc)), status_code=status.HTTP_302_FOUND)
    return RedirectResponse(
        _google_frontend_redirect(
            "success", "Google Ads connected successfully. Select a customer account to continue protection setup."
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
    current_user: GoogleManager,
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
    current_user: GoogleManager,
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
            await alert_service.raise_alert(
                db, organization_id=connection.organization_id, type=alert_service.AlertType.AUTH_EXPIRED,
                severity="critical", dedupe_key=alert_service.auth_expired_key(connection.id),
                title="Google Ads authorization expired",
                message="Google rejected the stored authorization. Reconnect Google Ads to keep protection running.",
                resource_type="google_connection", resource_id=str(connection.id), details={"error": str(exc)[:500]},
            )
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
                geo_target_type=remote_campaign.get("geo_target_type"),
            )
            db.add(campaign)
            existing_campaigns[campaign_id] = campaign
            created += 1
            continue

        campaign.name = str(remote_campaign["name"])
        campaign.campaign_type = CampaignType(str(remote_campaign["campaign_type"]))
        campaign.status = CampaignStatus(str(remote_campaign["status"]))
        campaign.geo_target_type = remote_campaign.get("geo_target_type")
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

    # Location targeting feeds the GEO_ANOMALY rule (task 018).
    locations_synced = await _sync_campaign_locations(
        db, connection, access_token, list(existing_campaigns.values())
    )

    audit_sync(
        AuditResult.SUCCESS,
        details={"synced": len(remote_campaigns), "created": created, "updated": updated,
                 "removed": removed, "external_exclusions_counted": external_counted,
                 "locations_synced": locations_synced},
    )
    await db.commit()
    return CampaignSyncSummary(
        synced=len(remote_campaigns),
        created=created,
        updated=updated,
        removed=removed,
    )


async def _sync_campaign_locations(
    db: AsyncSession,
    connection: GoogleConnection,
    access_token: str,
    campaigns: list[GoogleCampaign],
) -> bool:
    """Replace each campaign's stored location targets. False (previous targets kept) if Google can't be read."""
    try:
        remote = await list_campaign_locations(
            access_token=access_token,
            customer_id=connection.customer_id,
            login_customer_id=connection.login_customer_id,
        )
    except ValueError as exc:
        logger.warning("Keeping previous campaign location targets: %s", exc)
        return False

    await db.flush()
    ids = [campaign.id for campaign in campaigns]
    if ids:
        await db.execute(delete(GoogleCampaignLocation).where(GoogleCampaignLocation.campaign_id.in_(ids)))
    for campaign in campaigns:
        for location in remote.get(campaign.campaign_id, []):
            db.add(GoogleCampaignLocation(campaign_id=campaign.id, **location))
    return True


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
        .options(selectinload(GoogleCampaign.locations))
        .where(GoogleCampaign.connection_id == connection.id)
        .order_by(
            GoogleCampaign.protection_enabled.desc(),
            GoogleCampaign.status.asc(),
            GoogleCampaign.name.asc(),
        )
    )
    return [_to_campaign_out(campaign, campaign.locations) for campaign in result.scalars().all()]


@router.patch("/campaigns/{campaign_row_id}/protection", response_model=CampaignOut)
async def update_campaign_protection(
    campaign_row_id: uuid.UUID,
    payload: UpdateCampaignProtectionIn,
    request: Request,
    current_user: ProtectionManager,
    db: AsyncSession = Depends(get_db),
) -> CampaignOut:
    result = await db.execute(
        select(GoogleCampaign)
        .options(selectinload(GoogleCampaign.locations))
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
    locations = list(campaign.locations)
    await db.commit()
    await db.refresh(campaign)
    return _to_campaign_out(campaign, locations)


@router.get("/health")
async def google_health() -> dict[str, str]:
    return {"status": "ok", "provider": "google"}

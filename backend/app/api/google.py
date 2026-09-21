from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.crypto import encrypt
from app.core.database import get_db
from app.models import GoogleConnection
from app.schemas.google import GoogleConnectionOut, SelectCustomerIn
from app.services.google_oauth import (
    build_authorization_url,
    exchange_code_for_tokens,
    fetch_user_email,
    generate_state_token,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/google", tags=["google"])


# ---- In-memory state store (POC only) ----
# In Phase 2, store state in Redis with a TTL, tied to the user session.
_pending_states: dict[str, dict] = {}


@router.get("/connect")
async def google_connect() -> RedirectResponse:
    """
    Step 1: Redirect the user to Google's consent screen.
    The state token is stored in-memory and verified on callback.
    """
    state = generate_state_token()
    _pending_states[state] = {"created": True}
    url = build_authorization_url(state=state)
    logger.info("Initiating Google OAuth flow (state=%s...)", state[:8])
    return RedirectResponse(url)


@router.get("/callback")
async def google_callback(
    code: str = Query(...),
    state: str = Query(...),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Step 2: Google redirects back here with code + state.
    Exchange code → tokens, encrypt refresh_token, store connection.
    """
    if state not in _pending_states:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired OAuth state",
        )
    _pending_states.pop(state, None)

    try:
        tokens = await exchange_code_for_tokens(code)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc

    access_token = tokens["access_token"]
    refresh_token = tokens["refresh_token"]

    email = await fetch_user_email(access_token)

    # POC: single-org app — grab the first organization.
    # Phase 2: tie state to an authenticated user session.
    from app.models import Organization

    result = await db.execute(select(Organization).limit(1))
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="No organization found — seed the DB first",
        )

    # Create a placeholder GoogleConnection. The real customer_id is
    # set later via /select-customer, once we list accessible accounts.
    connection = GoogleConnection(
        organization_id=org.id,
        refresh_token_encrypted=encrypt(refresh_token),
        customer_id="",  # set on next step
        google_account_email=email,
    )
    db.add(connection)
    await db.commit()
    await db.refresh(connection)

    logger.info(
        "Google OAuth complete for org=%s, connection=%s, email=%s",
        org.id, connection.id, email,
    )

    return {
        "status": "ok",
        "connection_id": str(connection.id),
        "google_account_email": email,
        "next_step": "POST /api/v1/google/select-customer with customer_id",
    }


@router.get("/connections", response_model=list[GoogleConnectionOut])
async def list_connections(
    db: AsyncSession = Depends(get_db),
) -> list[GoogleConnection]:
    result = await db.execute(
        select(GoogleConnection).order_by(GoogleConnection.created_at.desc())
    )
    return list(result.scalars().all())

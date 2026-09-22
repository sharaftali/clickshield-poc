"""
Google OAuth 2.0 flow for Google Ads API access.

Per spec §34–36: OAuth 2.0 via Google Cloud project credentials.
Developer tokens are legacy — access is now tied to the Cloud project.
"""
from __future__ import annotations

import logging
import secrets
from urllib.parse import urlencode

import httpx

from app.core.config import settings
from app.schemas.google import GoogleAccountOut

logger = logging.getLogger(__name__)

# Google OAuth endpoints
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"
GOOGLE_CUSTOMERS_URL = "https://googleads.googleapis.com/v18/customers:listAccessibleCustomers"

# Scopes required for Google Ads API
GOOGLE_ADS_SCOPE = "https://www.googleapis.com/auth/adwords"
OPENID_SCOPE = "openid email"


def build_authorization_url(state: str) -> str:
    """Build the URL to redirect the user to Google's consent screen."""
    params = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "redirect_uri": settings.GOOGLE_OAUTH_REDIRECT_URI,
        "response_type": "code",
        "scope": f"{GOOGLE_ADS_SCOPE} {OPENID_SCOPE}",
        "access_type": "offline",
        "prompt": "consent",
        "state": state,
    }
    return f"{GOOGLE_AUTH_URL}?{urlencode(params)}"


def generate_state_token() -> str:
    """Opaque CSRF state — store in session/cookie before redirect."""
    return secrets.token_urlsafe(32)


async def exchange_code_for_tokens(code: str) -> dict:
    """Exchange the authorization code for access + refresh tokens."""
    data = {
        "code": code,
        "client_id": settings.GOOGLE_CLIENT_ID,
        "client_secret": settings.GOOGLE_CLIENT_SECRET,
        "redirect_uri": settings.GOOGLE_OAUTH_REDIRECT_URI,
        "grant_type": "authorization_code",
    }

    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(GOOGLE_TOKEN_URL, data=data)
        if resp.status_code != 200:
            logger.error(
                "Google token exchange failed: %s %s",
                resp.status_code,
                resp.text,
            )
            raise ValueError(f"Google OAuth failed: {resp.text}")
        payload = resp.json()

    if "refresh_token" not in payload and "access_token" not in payload:
        raise ValueError("Google OAuth response did not include a usable token pair.")

    return payload


async def refresh_access_token(refresh_token: str) -> dict:
    """Exchange a stored refresh token for a fresh access token."""
    data = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "client_secret": settings.GOOGLE_CLIENT_SECRET,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
    }

    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(GOOGLE_TOKEN_URL, data=data)
        if resp.status_code != 200:
            raise ValueError(f"Failed to refresh Google OAuth token: {resp.text}")
        return resp.json()


async def fetch_user_email(access_token: str) -> str | None:
    """Fetch the Google account email for display purposes."""
    headers = {"Authorization": f"Bearer {access_token}"}
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(GOOGLE_USERINFO_URL, headers=headers)
            if resp.status_code == 200:
                return resp.json().get("email")
    except Exception as exc:
        logger.warning("Failed to fetch Google user email: %s", exc)
    return None


async def list_accessible_customer_accounts(access_token: str) -> list[GoogleAccountOut]:
    """List the Google Ads customer accounts available to the authorized user."""
    if not access_token:
        return []

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.get(GOOGLE_CUSTOMERS_URL, headers=headers)
            if resp.status_code != 200:
                logger.warning("Google ads customer listing failed: %s %s", resp.status_code, resp.text)
                return []
            payload = resp.json()
    except Exception as exc:
        logger.warning("Failed to list accessible Google Ads customers: %s", exc)
        return []

    resource_names = payload.get("resourceNames", [])
    accounts: list[GoogleAccountOut] = []
    for resource_name in resource_names:
        match = str(resource_name).strip()
        customer_id = match.split("/", 1)[1] if match.startswith("customers/") else match
        if customer_id.isdigit():
            accounts.append(
                GoogleAccountOut(
                    customer_id=customer_id,
                    descriptive_name=f"Google Ads customer {customer_id}",
                    is_manager=False,
                    is_test_account=False,
                )
            )
    return accounts

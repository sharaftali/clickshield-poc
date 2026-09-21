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

logger = logging.getLogger(__name__)

# Google OAuth endpoints
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"

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
        "access_type": "offline",       # required for refresh_token
        "prompt": "consent",            # force refresh_token issuance
        "state": state,
    }
    return f"{GOOGLE_AUTH_URL}?{urlencode(params)}"


def generate_state_token() -> str:
    """Opaque CSRF state — store in session/cookie before redirect."""
    return secrets.token_urlsafe(32)


async def exchange_code_for_tokens(code: str) -> dict:
    """
    Exchange the authorization code for access + refresh tokens.
    Returns a dict with: access_token, refresh_token, expires_in, scope.
    """
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

    if "refresh_token" not in payload:
        raise ValueError(
            "No refresh_token returned. Ensure access_type=offline and "
            "prompt=consent, and that the user has not already granted access "
            "without revocation."
        )

    return payload


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

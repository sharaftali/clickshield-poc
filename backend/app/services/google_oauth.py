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

from app.models.enums import CampaignStatus, CampaignType
from app.core.config import settings
from app.schemas.google import GoogleAccountOut

logger = logging.getLogger(__name__)

# Google OAuth endpoints
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"

# Scopes required for Google Ads API
GOOGLE_ADS_SCOPE = "https://www.googleapis.com/auth/adwords"
OPENID_SCOPE = "openid email"


def _google_ads_api_version() -> str:
    version = str(settings.GOOGLE_ADS_API_VERSION).strip()
    return version if version.startswith("v") else f"v{version}"


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

    try:
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
    except httpx.HTTPError as exc:
        logger.warning("Google token exchange network failure: %s", exc)
        raise ValueError("Google OAuth token exchange failed due to a network error.") from exc

    if "refresh_token" not in payload and "access_token" not in payload:
        raise ValueError("Google OAuth response did not include a usable token pair.")

    return payload


class GoogleAuthError(ValueError):
    """Token refresh failed.

    permanent=True means retrying cannot help (revoked/expired grant, bad client
    credentials): the connection needs the user to re-authorize (spec §66
    "Authentication expired"). permanent=False is a network/5xx problem.
    """

    def __init__(self, message: str, *, permanent: bool, error_code: str | None = None) -> None:
        super().__init__(message)
        self.permanent = permanent
        self.error_code = error_code


# OAuth token-endpoint errors that retrying will never fix (RFC 6749 §5.2).
_PERMANENT_TOKEN_ERRORS = {"invalid_grant", "invalid_client", "unauthorized_client", "unsupported_grant_type"}


def classify_token_error(status_code: int, body: dict | None) -> GoogleAuthError:
    error_code = str((body or {}).get("error") or "") or None
    description = (body or {}).get("error_description") or ""
    if error_code in _PERMANENT_TOKEN_ERRORS:
        permanent = True
    else:
        permanent = not (status_code == 429 or status_code >= 500)
    detail = f"{error_code}: {description}".strip(": ") if error_code else f"HTTP {status_code}"
    return GoogleAuthError(
        f"Failed to refresh Google OAuth token ({detail})",
        permanent=permanent,
        error_code=error_code,
    )


async def refresh_access_token(refresh_token: str) -> dict:
    """Exchange a stored refresh token for a fresh access token. Raises GoogleAuthError."""
    data = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "client_secret": settings.GOOGLE_CLIENT_SECRET,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(GOOGLE_TOKEN_URL, data=data)
    except httpx.HTTPError as exc:
        logger.warning("Google token refresh network failure: %s", exc)
        raise GoogleAuthError(
            "Failed to refresh Google OAuth token due to a network error.", permanent=False
        ) from exc

    try:
        payload = resp.json()
    except ValueError:
        payload = None

    if resp.status_code != 200:
        raise classify_token_error(resp.status_code, payload if isinstance(payload, dict) else None)
    if not isinstance(payload, dict) or not payload.get("access_token"):
        raise GoogleAuthError("Google OAuth token response had no access_token.", permanent=False)
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


async def list_accessible_customer_accounts(access_token: str) -> list[GoogleAccountOut]:
    """List the Google Ads customer accounts available to the authorized user."""
    if not access_token:
        return []

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    customers_url = (
        f"https://googleads.googleapis.com/{_google_ads_api_version()}/"
        "customers:listAccessibleCustomers"
    )

    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.get(customers_url, headers=headers)
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


def _normalize_campaign_type(value: str | None) -> CampaignType | None:
    mapping = {
        "SEARCH": CampaignType.SEARCH,
        "DISPLAY": CampaignType.DISPLAY,
        "SHOPPING": CampaignType.SHOPPING,
        "VIDEO": CampaignType.VIDEO,
        "PERFORMANCE_MAX": CampaignType.PERFORMANCE_MAX,
    }
    return mapping.get((value or "").strip().upper())


def _normalize_campaign_status(value: str | None) -> CampaignStatus:
    mapping = {
        "ENABLED": CampaignStatus.ENABLED,
        "PAUSED": CampaignStatus.PAUSED,
        "REMOVED": CampaignStatus.REMOVED,
    }
    return mapping.get((value or "").strip().upper(), CampaignStatus.PAUSED)


async def list_google_campaigns(
    *,
    access_token: str,
    customer_id: str,
    login_customer_id: str | None = None,
) -> list[dict[str, str | bool]]:
    if not access_token or not customer_id:
        return []

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "developer-token": settings.GOOGLE_DEVELOPER_TOKEN or "",
    }
    if login_customer_id:
        headers["login-customer-id"] = login_customer_id
    headers = {key: value for key, value in headers.items() if value}

    payload = {
        "query": (
            "SELECT "
            "campaign.id, "
            "campaign.name, "
            "campaign.status, "
            "campaign.advertising_channel_type, "
            "campaign.geo_target_type_setting.positive_geo_target_type "
            "FROM campaign "
            "ORDER BY campaign.name"
        )
    }
    url = (
        f"https://googleads.googleapis.com/{_google_ads_api_version()}/customers/"
        f"{customer_id}/googleAds:searchStream"
    )

    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.post(url, headers=headers, json=payload)
            if resp.status_code != 200:
                logger.warning("Google Ads campaign listing failed: %s %s", resp.status_code, resp.text)
                raise ValueError(f"Failed to fetch Google Ads campaigns: {resp.text}")
            payload = resp.json()
    except httpx.HTTPError as exc:
        logger.warning("Failed to fetch Google Ads campaigns: %s", exc)
        raise ValueError("Failed to fetch Google Ads campaigns from Google.") from exc

    campaigns: list[dict[str, str | bool]] = []
    for batch in payload if isinstance(payload, list) else []:
        for row in batch.get("results", []):
            campaign = row.get("campaign") or {}
            campaign_type = _normalize_campaign_type(campaign.get("advertisingChannelType"))
            if campaign_type is None:
                continue

            campaign_id = str(campaign.get("id", "")).strip()
            if not campaign_id.isdigit():
                continue

            campaigns.append(
                {
                    "campaign_id": campaign_id,
                    "name": str(campaign.get("name") or f"Campaign {campaign_id}").strip(),
                    "campaign_type": campaign_type.value,
                    "status": _normalize_campaign_status(campaign.get("status")).value,
                    "supports_ip_exclusion": campaign_type not in {CampaignType.PERFORMANCE_MAX, CampaignType.VIDEO},
                    "geo_target_type": (campaign.get("geoTargetTypeSetting") or {}).get("positiveGeoTargetType"),
                }
            )
    return campaigns


async def count_ip_exclusions_by_campaign(
    *,
    access_token: str,
    customer_id: str,
    login_customer_id: str | None = None,
) -> dict[str, int]:
    """Negative IP_BLOCK criteria per campaign id, as Google holds them (spec §39).

    Includes the advertiser's own exclusions and Click Shield's ACTIVE ones.
    Raises ValueError if Google can't be queried.
    """
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    if settings.GOOGLE_DEVELOPER_TOKEN:
        headers["developer-token"] = settings.GOOGLE_DEVELOPER_TOKEN
    if login_customer_id:
        headers["login-customer-id"] = login_customer_id
    payload = {
        "query": (
            "SELECT campaign.id, campaign_criterion.criterion_id "
            "FROM campaign_criterion "
            "WHERE campaign_criterion.type = 'IP_BLOCK' "
            "AND campaign_criterion.negative = TRUE"
        )
    }
    url = (
        f"https://googleads.googleapis.com/{_google_ads_api_version()}/customers/"
        f"{customer_id}/googleAds:searchStream"
    )
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.post(url, headers=headers, json=payload)
    except httpx.HTTPError as exc:
        raise ValueError("Failed to count Google Ads IP exclusions.") from exc
    if resp.status_code != 200:
        logger.warning("Google Ads IP exclusion count failed: %s %s", resp.status_code, resp.text)
        raise ValueError(f"Failed to count Google Ads IP exclusions: {resp.text}")

    counts: dict[str, int] = {}
    body = resp.json()
    for batch in body if isinstance(body, list) else []:
        for row in batch.get("results", []):
            campaign_id = str((row.get("campaign") or {}).get("id", "")).strip()
            if campaign_id:
                counts[campaign_id] = counts.get(campaign_id, 0) + 1
    return counts


def _ads_headers(access_token: str, login_customer_id: str | None) -> dict[str, str]:
    headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
    if settings.GOOGLE_DEVELOPER_TOKEN:
        headers["developer-token"] = settings.GOOGLE_DEVELOPER_TOKEN
    if login_customer_id:
        headers["login-customer-id"] = login_customer_id
    return headers


async def _search_stream(access_token: str, customer_id: str, login_customer_id: str | None, query: str) -> list[dict]:
    url = (
        f"https://googleads.googleapis.com/{_google_ads_api_version()}/customers/"
        f"{customer_id}/googleAds:searchStream"
    )
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.post(url, headers=_ads_headers(access_token, login_customer_id), json={"query": query})
    except httpx.HTTPError as exc:
        raise ValueError("Google Ads query failed due to a network error.") from exc
    if resp.status_code != 200:
        logger.warning("Google Ads query failed: %s %s", resp.status_code, resp.text)
        raise ValueError(f"Google Ads query failed: {resp.text}")
    body = resp.json()
    return [row for batch in (body if isinstance(body, list) else []) for row in batch.get("results", [])]


# geo_target_constant rows rarely change: resolve each once per process.
_geo_constant_cache: dict[str, dict[str, str | None]] = {}


def _geo_region(constant: dict) -> str | None:
    """State-level name for a geo target (canonical name "Dallas,Texas,United States" → Texas)."""
    target_type = (constant.get("targetType") or "").casefold()
    if target_type == "country":
        return None
    if target_type in {"state", "province", "region", "territory", "prefecture", "governorate", "autonomous community"}:
        return constant.get("name")
    parts = [part.strip() for part in (constant.get("canonicalName") or "").split(",") if part.strip()]
    return parts[-2] if len(parts) >= 3 else None


async def resolve_geo_target_constants(
    resource_names: list[str], *, access_token: str, customer_id: str, login_customer_id: str | None = None
) -> dict[str, dict[str, str | None]]:
    missing = sorted({name for name in resource_names if name and name not in _geo_constant_cache})
    for start in range(0, len(missing), 500):
        chunk = missing[start:start + 500]
        quoted = ", ".join(f"'{name}'" for name in chunk if name.startswith("geoTargetConstants/") and name.split("/", 1)[1].isdigit())
        if not quoted:
            continue
        rows = await _search_stream(
            access_token, customer_id, login_customer_id,
            "SELECT geo_target_constant.resource_name, geo_target_constant.name, "
            "geo_target_constant.country_code, geo_target_constant.target_type, "
            "geo_target_constant.canonical_name "
            f"FROM geo_target_constant WHERE geo_target_constant.resource_name IN ({quoted})",
        )
        for row in rows:
            constant = row.get("geoTargetConstant") or {}
            _geo_constant_cache[constant.get("resourceName")] = {
                "name": constant.get("name"),
                "country_code": (constant.get("countryCode") or "").upper() or None,
                "target_type": constant.get("targetType"),
                "region": _geo_region(constant),
            }
    return {name: _geo_constant_cache[name] for name in resource_names if name in _geo_constant_cache}


async def list_campaign_locations(
    *, access_token: str, customer_id: str, login_customer_id: str | None = None
) -> dict[str, list[dict]]:
    """Location targets per campaign id (spec §18, task 018): positive and negative
    LOCATION criteria resolved to country / region, plus PROXIMITY targets by their
    address's country. Raises ValueError if Google can't be read."""
    rows = await _search_stream(
        access_token, customer_id, login_customer_id,
        "SELECT campaign.id, campaign_criterion.criterion_id, campaign_criterion.type, "
        "campaign_criterion.negative, campaign_criterion.location.geo_target_constant, "
        "campaign_criterion.proximity.address.country_code, campaign_criterion.proximity.address.city_name "
        "FROM campaign_criterion "
        "WHERE campaign_criterion.type IN ('LOCATION', 'PROXIMITY') AND campaign_criterion.status != 'REMOVED'",
    )
    constants = await resolve_geo_target_constants(
        [((row.get("campaignCriterion") or {}).get("location") or {}).get("geoTargetConstant") for row in rows],
        access_token=access_token, customer_id=customer_id, login_customer_id=login_customer_id,
    )
    by_campaign: dict[str, list[dict]] = {}
    for row in rows:
        campaign_id = str((row.get("campaign") or {}).get("id", "")).strip()
        criterion = row.get("campaignCriterion") or {}
        if not campaign_id:
            continue
        criterion_type = criterion.get("type") or "LOCATION"
        if criterion_type == "PROXIMITY":
            address = (criterion.get("proximity") or {}).get("address") or {}
            location = {
                "geo_target_constant": None,
                "country_code": (address.get("countryCode") or "").upper() or None,
                "region": None,
                "name": address.get("cityName") or "Radius target",
                "target_type": "Proximity",
            }
        else:
            constant_name = (criterion.get("location") or {}).get("geoTargetConstant")
            resolved = constants.get(constant_name, {})
            location = {
                "geo_target_constant": constant_name,
                "country_code": resolved.get("country_code"),
                "region": resolved.get("region"),
                "name": resolved.get("name"),
                "target_type": resolved.get("target_type"),
            }
        by_campaign.setdefault(campaign_id, []).append({
            "criterion_id": str(criterion.get("criterionId") or ""),
            "criterion_type": criterion_type,
            "negative": bool(criterion.get("negative")),
            **location,
        })
    return by_campaign

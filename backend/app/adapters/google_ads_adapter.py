from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class GoogleAdsApiResult:
    ok: bool
    resource_name: str | None = None
    api_request_id: str | None = None
    message: str | None = None


class GoogleAdsAdapter:
    """Thin adapter around Google's Ads API.

    When credentials are absent, this adapter intentionally falls back to a dry-run
    response so local development and smoke testing can continue without a live
    Google Ads sandbox. Production deployments should provide valid OAuth access.
    """

    def __init__(
        self,
        *,
        customer_id: str,
        access_token: str | None,
        login_customer_id: str | None = None,
        api_version: str | None = None,
    ) -> None:
        self.customer_id = customer_id or "0000000000"
        self.access_token = access_token
        self.login_customer_id = login_customer_id
        self.api_version = api_version or settings.GOOGLE_ADS_API_VERSION

    def _build_headers(self) -> dict[str, str]:
        headers = {
            "Authorization": f"Bearer {self.access_token or ''}",
            "Content-Type": "application/json",
            "developer-token": settings.GOOGLE_DEVELOPER_TOKEN or "",
        }
        if self.login_customer_id:
            headers["login-customer-id"] = self.login_customer_id
        return {key: value for key, value in headers.items() if value}

    async def create_ip_exclusion(
        self,
        *,
        campaign_id: str,
        ip_address: str,
        reason: str | None = None,
    ) -> GoogleAdsApiResult:
        if not self.access_token or not settings.GOOGLE_CLIENT_ID:
            resource_name = (
                f"customers/{self.customer_id}/campaigns/{campaign_id}/ipSettings/"
                f"{uuid.uuid4().hex[:12]}"
            )
            return GoogleAdsApiResult(
                ok=True,
                resource_name=resource_name,
                api_request_id=f"dry-run-{uuid.uuid4().hex[:12]}",
                message="Google Ads dry-run: credentials are not configured; action recorded without external API call.",
            )

        payload: dict[str, Any] = {
            "operations": [
                {
                    "create": {
                        "campaignId": campaign_id,
                        "ipAddress": ip_address,
                        "reason": reason or "High-risk traffic flagged by Click Shield",
                    }
                }
            ]
        }

        url = (
            f"https://googleads.googleapis.com/{self.api_version}/customers/"
            f"{self.customer_id}:mutate"
        )

        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                response = await client.post(
                    url,
                    headers=self._build_headers(),
                    json=payload,
                )
            if response.status_code >= 400:
                logger.warning(
                    "Google Ads exclusion mutation failed: %s %s",
                    response.status_code,
                    response.text,
                )
                return GoogleAdsApiResult(
                    ok=False,
                    message=f"Google Ads API error: {response.status_code} {response.text}",
                )

            data = response.json()
            result = (data.get("results") or [{}])[0]
            resource_name = result.get("resourceName")
            request_id = response.headers.get("X-Goog-Request-Id")
            return GoogleAdsApiResult(
                ok=True,
                resource_name=resource_name,
                api_request_id=request_id,
                message="Google Ads exclusion created successfully.",
            )
        except Exception as exc:  # pragma: no cover - external API edge case
            logger.exception("Google Ads exclusion request raised an unexpected exception")
            return GoogleAdsApiResult(
                ok=False,
                message=f"Google Ads adapter failure: {exc}",
            )

    async def remove_ip_exclusion(
        self,
        *,
        campaign_id: str,
        ip_address: str,
        resource_name: str | None = None,
    ) -> GoogleAdsApiResult:
        if not self.access_token or not settings.GOOGLE_CLIENT_ID:
            return GoogleAdsApiResult(
                ok=True,
                resource_name=resource_name or f"customers/{self.customer_id}/campaigns/{campaign_id}/ipSettings/dry-run-removal",
                api_request_id=f"dry-run-remove-{uuid.uuid4().hex[:12]}",
                message="Google Ads dry-run: removal simulated without remote API access.",
            )

        payload: dict[str, Any] = {
            "operations": [
                {
                    "remove": {
                        "resourceName": resource_name or (
                            f"customers/{self.customer_id}/campaigns/{campaign_id}/ipSettings/"
                            f"{uuid.uuid4().hex[:12]}"
                        )
                    }
                }
            ]
        }

        url = (
            f"https://googleads.googleapis.com/{self.api_version}/customers/"
            f"{self.customer_id}:mutate"
        )

        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                response = await client.post(
                    url,
                    headers=self._build_headers(),
                    json=payload,
                )
            if response.status_code >= 400:
                logger.warning(
                    "Google Ads exclusion removal failed: %s %s",
                    response.status_code,
                    response.text,
                )
                return GoogleAdsApiResult(
                    ok=False,
                    message=f"Google Ads API error: {response.status_code} {response.text}",
                )
            return GoogleAdsApiResult(
                ok=True,
                resource_name=resource_name,
                api_request_id=response.headers.get("X-Goog-Request-Id"),
                message="Google Ads exclusion removed successfully.",
            )
        except Exception as exc:  # pragma: no cover
            logger.exception("Google Ads exclusion removal raised an unexpected exception")
            return GoogleAdsApiResult(
                ok=False,
                message=f"Google Ads adapter failure: {exc}",
            )

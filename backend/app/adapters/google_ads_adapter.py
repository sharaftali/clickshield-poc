"""
Google Ads adapter — IP exclusions as negative IP_BLOCK campaign criteria.

Per spec §37 / §40 / §41 / §44. Uses the Google Ads REST interface over httpx
(same style as app/services/google_oauth.py):

    POST /{version}/customers/{cid}/campaignCriteria:mutate
        {"operations": [{"create": {"campaign": "customers/{cid}/campaigns/{id}",
                                    "negative": true,
                                    "ipBlock": {"ipAddress": "203.0.113.7"}}}]}
    POST /{version}/customers/{cid}/campaignCriteria:mutate
        {"operations": [{"remove": "customers/{cid}/campaignCriteria/{id}~{criterion}"}]}
    POST /{version}/customers/{cid}/googleAds:search      (lookup / verify)

Every failure is returned as a GoogleAdsApiResult with ok=False, a `retryable`
flag and an `error_category`, so the action worker can decide between retry
and permanent failure (task 008) without parsing Google's error payloads.
"""
from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

GOOGLE_ADS_API_BASE = "https://googleads.googleapis.com"
REQUEST_TIMEOUT_SECONDS = 20.0

# customers/{customer_id}/campaignCriteria/{campaign_id}~{criterion_id}
CAMPAIGN_CRITERION_RESOURCE_RE = re.compile(r"^customers/(\d+)/campaignCriteria/(\d+)~(\d+)$")


class ErrorCategory(StrEnum):
    TRANSIENT = "transient"              # retry with backoff
    NETWORK = "network"                  # retry with backoff
    AUTH = "auth"                        # token invalid/revoked — needs re-auth
    PERMISSION = "permission"            # account/customer access problem
    INVALID_REQUEST = "invalid_request"  # bad IP, bad IDs, malformed request
    UNSUPPORTED = "unsupported"          # campaign type can't take IP exclusions
    LIMIT = "limit"                      # criterion/resource count limit reached
    DUPLICATE = "duplicate"              # criterion already exists
    NOT_FOUND = "not_found"              # resource doesn't exist
    UNKNOWN = "unknown"


# Error codes are "<errorCode oneof key>.<enum value>", e.g. "criterionError.INVALID_IP_ADDRESS".
# Values taken from google.ads.googleads.v21.errors.
RETRYABLE_ERROR_CODES = frozenset(
    {
        "internalError.INTERNAL_ERROR",
        "internalError.TRANSIENT_ERROR",
        "internalError.DEADLINE_EXCEEDED",
        "quotaError.RESOURCE_EXHAUSTED",
        "quotaError.RESOURCE_TEMPORARILY_EXHAUSTED",
        "databaseError.CONCURRENT_MODIFICATION",
        # The worker refreshes the access token on every run, so a retry gets a new one.
        "authenticationError.OAUTH_TOKEN_EXPIRED",
    }
)
DUPLICATE_ERROR_CODES = frozenset(
    {"mutateError.RESOURCE_ALREADY_EXISTS", "distinctError.DUPLICATE_ELEMENT"}
)
NOT_FOUND_ERROR_CODES = frozenset(
    {"mutateError.RESOURCE_NOT_FOUND", "requestError.RESOURCE_NOT_FOUND"}
)
UNSUPPORTED_ERROR_CODES = frozenset(
    {
        "criterionError.CANNOT_ADD_CRITERIA_TYPE",
        "criterionError.CANNOT_EXCLUDE_CRITERIA_TYPE",
        "campaignCriterionError.CANNOT_EXCLUDE_CRITERIA_TYPE",
        "campaignCriterionError.OPERATOR_NOT_SUPPORTED_FOR_CRITERION_TYPE",
    }
)
_CATEGORY_BY_ERROR_KIND = {
    "authenticationError": ErrorCategory.AUTH,
    "authorizationError": ErrorCategory.PERMISSION,
    "resourceCountLimitExceededError": ErrorCategory.LIMIT,
}


@dataclass(slots=True)
class GoogleAdsApiResult:
    ok: bool
    resource_name: str | None = None
    api_request_id: str | None = None
    message: str | None = None
    # Failure details (meaningful only when ok=False)
    retryable: bool = False
    error_category: ErrorCategory | None = None
    error_code: str | None = None
    # Create only: the criterion already existed in Google and was adopted (spec §41)
    already_existed: bool = False


class _CallFailed(Exception):
    def __init__(self, result: GoogleAdsApiResult) -> None:
        super().__init__(result.message)
        self.result = result


def normalize_ip_block(value: str) -> str:
    """Return the IP (or CIDR) in the form sent to Google; raise ValueError if invalid."""
    network = ipaddress.ip_network(str(value).strip(), strict=False)
    if network.num_addresses == 1:
        address = network.network_address
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            return str(address.ipv4_mapped)
        return str(address)
    return str(network)


def _same_ip_block(stored: str | None, target: str) -> bool:
    if not stored:
        return False
    try:
        return normalize_ip_block(stored) == target
    except ValueError:
        return False


def _digits(value: str | None) -> str:
    return (value or "").replace("-", "").strip()


def classify_error_codes(
    codes: list[str], http_status: int | None
) -> tuple[ErrorCategory, bool]:
    """Map Google Ads error codes (or the bare HTTP status) to (category, retryable)."""
    if codes:
        permanent = [code for code in codes if code not in RETRYABLE_ERROR_CODES]
        if not permanent:
            return ErrorCategory.TRANSIENT, True
        code = permanent[0]
        if code in DUPLICATE_ERROR_CODES:
            return ErrorCategory.DUPLICATE, False
        if code in NOT_FOUND_ERROR_CODES:
            return ErrorCategory.NOT_FOUND, False
        if code in UNSUPPORTED_ERROR_CODES:
            return ErrorCategory.UNSUPPORTED, False
        return _CATEGORY_BY_ERROR_KIND.get(code.split(".", 1)[0], ErrorCategory.INVALID_REQUEST), False

    if http_status == 429 or (http_status is not None and http_status >= 500):
        return ErrorCategory.TRANSIENT, True
    if http_status == 401:
        return ErrorCategory.AUTH, False
    if http_status == 403:
        return ErrorCategory.PERMISSION, False
    if http_status is not None and 400 <= http_status < 500:
        return ErrorCategory.INVALID_REQUEST, False
    return ErrorCategory.UNKNOWN, False


def _parse_google_ads_failure(error: dict[str, Any]) -> tuple[list[str], list[str], str | None]:
    """Extract (error codes, messages, request id) from a google.rpc.Status-shaped dict."""
    codes: list[str] = []
    messages: list[str] = []
    request_id: str | None = None
    for detail in error.get("details") or []:
        if not isinstance(detail, dict) or not str(detail.get("@type", "")).endswith("GoogleAdsFailure"):
            continue
        request_id = detail.get("requestId") or request_id
        for item in detail.get("errors") or []:
            for kind, value in (item.get("errorCode") or {}).items():
                codes.append(f"{kind}.{value}")
            if item.get("message"):
                messages.append(str(item["message"]))
    if not messages and error.get("message"):
        messages.append(str(error["message"]))
    return codes, messages, request_id


class GoogleAdsAdapter:
    """Thin adapter around the Google Ads API for campaign IP exclusions.

    Never reports success without a real Google response. Dry-run for local
    development is handled by the action worker (GOOGLE_ADS_DRY_RUN), not here.
    """

    def __init__(
        self,
        *,
        customer_id: str,
        access_token: str | None,
        login_customer_id: str | None = None,
        api_version: str | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.customer_id = _digits(customer_id)
        self.access_token = access_token
        self.login_customer_id = _digits(login_customer_id) or None
        version = str(api_version or settings.GOOGLE_ADS_API_VERSION).strip()
        self.api_version = version if version.startswith("v") else f"v{version}"
        self._transport = transport  # injectable for tests

    # ---- public API -------------------------------------------------------

    async def create_ip_exclusion(
        self,
        *,
        campaign_id: str,
        ip_address: str,
        reason: str | None = None,
    ) -> GoogleAdsApiResult:
        """Exclude an IP from a campaign. `reason` is kept in Click Shield only — Google has no such field."""
        try:
            campaign_resource = self._campaign_resource(campaign_id)
            ip_value = self._ip_block_or_fail(ip_address)
            body, request_id = await self._post(
                "campaignCriteria:mutate",
                {
                    "operations": [
                        {
                            "create": {
                                "campaign": campaign_resource,
                                "negative": True,
                                "ipBlock": {"ipAddress": ip_value},
                            }
                        }
                    ]
                },
                action="create IP exclusion",
            )
        except _CallFailed as failed:
            if failed.result.error_category == ErrorCategory.DUPLICATE:
                return await self._adopt_existing(campaign_id, ip_address, failed.result)
            return failed.result

        resource_name = ((body.get("results") or [{}])[0] or {}).get("resourceName")
        if not resource_name:
            return GoogleAdsApiResult(
                ok=False,
                api_request_id=request_id,
                error_category=ErrorCategory.UNKNOWN,
                message="Google Ads accepted the request but returned no criterion resource name.",
            )
        return GoogleAdsApiResult(
            ok=True,
            resource_name=resource_name,
            api_request_id=request_id,
            message="Google Ads IP exclusion created.",
        )

    async def remove_ip_exclusion(
        self,
        *,
        campaign_id: str,
        ip_address: str,
        resource_name: str | None = None,
    ) -> GoogleAdsApiResult:
        """Remove an IP exclusion. Removing one that no longer exists counts as success."""
        try:
            if not self._is_own_criterion(resource_name):
                # Never invent a resource name: look the criterion up by IP instead.
                found = await self.find_ip_exclusion(campaign_id=campaign_id, ip_address=ip_address)
                if not found.ok:
                    return found
                if not found.resource_name:
                    return GoogleAdsApiResult(
                        ok=True,
                        api_request_id=found.api_request_id,
                        message="IP exclusion is not present in Google Ads; nothing to remove.",
                    )
                resource_name = found.resource_name

            _, request_id = await self._post(
                "campaignCriteria:mutate",
                {"operations": [{"remove": resource_name}]},
                action="remove IP exclusion",
            )
        except _CallFailed as failed:
            if failed.result.error_category == ErrorCategory.NOT_FOUND:
                return GoogleAdsApiResult(
                    ok=True,
                    resource_name=resource_name,
                    api_request_id=failed.result.api_request_id,
                    message="IP exclusion was already removed from Google Ads.",
                )
            return failed.result

        return GoogleAdsApiResult(
            ok=True,
            resource_name=resource_name,
            api_request_id=request_id,
            message="Google Ads IP exclusion removed.",
        )

    async def find_ip_exclusion(self, *, campaign_id: str, ip_address: str) -> GoogleAdsApiResult:
        """Look up an existing negative IP_BLOCK criterion.

        ok=True with resource_name set when found, ok=True with resource_name=None
        when absent, ok=False when the lookup itself failed.
        """
        try:
            campaign_digits = self._campaign_id_or_fail(campaign_id)
            target = self._ip_block_or_fail(ip_address)
            rows, request_id = await self._search(
                "SELECT campaign_criterion.resource_name, campaign_criterion.ip_block.ip_address "
                "FROM campaign_criterion "
                f"WHERE campaign.id = {campaign_digits} "
                "AND campaign_criterion.type = 'IP_BLOCK' "
                "AND campaign_criterion.negative = TRUE",
                action="look up IP exclusions",
            )
        except _CallFailed as failed:
            return failed.result

        for row in rows:
            criterion = row.get("campaignCriterion") or {}
            if _same_ip_block((criterion.get("ipBlock") or {}).get("ipAddress"), target):
                return GoogleAdsApiResult(
                    ok=True,
                    resource_name=criterion.get("resourceName"),
                    api_request_id=request_id,
                    message="IP exclusion found in Google Ads.",
                )
        return GoogleAdsApiResult(
            ok=True, api_request_id=request_id, message="IP exclusion not found in Google Ads."
        )

    async def verify_exclusion(self, resource_name: str) -> GoogleAdsApiResult:
        """Read the criterion back from Google (spec §37 "Verify result")."""
        if not self._is_own_criterion(resource_name):
            return GoogleAdsApiResult(
                ok=False,
                error_category=ErrorCategory.INVALID_REQUEST,
                message=f"Not a campaign criterion resource name for customer {self.customer_id}: {resource_name!r}",
            )
        try:
            rows, request_id = await self._search(
                "SELECT campaign_criterion.resource_name, campaign_criterion.negative, "
                "campaign_criterion.ip_block.ip_address "
                "FROM campaign_criterion "
                f"WHERE campaign_criterion.resource_name = '{resource_name}'",
                action="verify IP exclusion",
            )
        except _CallFailed as failed:
            return failed.result

        criterion = (rows[0].get("campaignCriterion") or {}) if rows else {}
        if criterion.get("negative") is True and (criterion.get("ipBlock") or {}).get("ipAddress"):
            return GoogleAdsApiResult(
                ok=True,
                resource_name=resource_name,
                api_request_id=request_id,
                message="IP exclusion verified in Google Ads.",
            )
        return GoogleAdsApiResult(
            ok=False,
            resource_name=resource_name,
            api_request_id=request_id,
            error_category=ErrorCategory.NOT_FOUND,
            message="IP exclusion was not found in Google Ads on read-back.",
        )

    # ---- internals ----------------------------------------------------------

    async def _adopt_existing(
        self, campaign_id: str, ip_address: str, duplicate: GoogleAdsApiResult
    ) -> GoogleAdsApiResult:
        """Google says the criterion already exists: adopt it instead of failing (spec §41)."""
        found = await self.find_ip_exclusion(campaign_id=campaign_id, ip_address=ip_address)
        if not found.ok:
            return found
        if not found.resource_name:
            return duplicate
        return GoogleAdsApiResult(
            ok=True,
            resource_name=found.resource_name,
            api_request_id=duplicate.api_request_id or found.api_request_id,
            message="IP was already excluded in Google Ads; existing exclusion adopted.",
            already_existed=True,
        )

    def _headers(self) -> dict[str, str]:
        headers = {
            "Authorization": f"Bearer {self.access_token or ''}",
            "Content-Type": "application/json",
        }
        # Optional since the developer-token sunset (spec §35); sent only if configured.
        if settings.GOOGLE_DEVELOPER_TOKEN:
            headers["developer-token"] = settings.GOOGLE_DEVELOPER_TOKEN
        if self.login_customer_id:
            headers["login-customer-id"] = self.login_customer_id
        return headers

    def _customer_or_fail(self) -> str:
        if not self.customer_id.isdigit():
            raise _CallFailed(
                GoogleAdsApiResult(
                    ok=False,
                    error_category=ErrorCategory.INVALID_REQUEST,
                    message=f"Invalid Google Ads customer ID: {self.customer_id!r}",
                )
            )
        return self.customer_id

    def _campaign_id_or_fail(self, campaign_id: str) -> str:
        value = _digits(campaign_id)
        if not value.isdigit():
            raise _CallFailed(
                GoogleAdsApiResult(
                    ok=False,
                    error_category=ErrorCategory.INVALID_REQUEST,
                    message=f"Invalid Google Ads campaign ID: {campaign_id!r}",
                )
            )
        return value

    def _campaign_resource(self, campaign_id: str) -> str:
        return f"customers/{self._customer_or_fail()}/campaigns/{self._campaign_id_or_fail(campaign_id)}"

    @staticmethod
    def _ip_block_or_fail(ip_address: str) -> str:
        try:
            return normalize_ip_block(ip_address)
        except ValueError:
            raise _CallFailed(
                GoogleAdsApiResult(
                    ok=False,
                    error_category=ErrorCategory.INVALID_REQUEST,
                    message=f"Invalid IP address for exclusion: {ip_address!r}",
                )
            ) from None

    def _is_own_criterion(self, resource_name: str | None) -> bool:
        match = CAMPAIGN_CRITERION_RESOURCE_RE.match(resource_name or "")
        return bool(match) and match.group(1) == self.customer_id

    async def _search(self, query: str, *, action: str) -> tuple[list[dict[str, Any]], str | None]:
        rows: list[dict[str, Any]] = []
        request_id: str | None = None
        page_token: str | None = None
        while True:
            payload: dict[str, Any] = {"query": query}
            if page_token:
                payload["pageToken"] = page_token
            body, request_id = await self._post("googleAds:search", payload, action=action)
            rows.extend(body.get("results") or [])
            page_token = body.get("nextPageToken")
            if not page_token:
                return rows, request_id

    async def _post(
        self, path: str, payload: dict[str, Any], *, action: str
    ) -> tuple[dict[str, Any], str | None]:
        if not self.access_token:
            raise _CallFailed(
                GoogleAdsApiResult(
                    ok=False,
                    error_category=ErrorCategory.AUTH,
                    message=f"No Google access token available ({action}).",
                )
            )
        url = f"{GOOGLE_ADS_API_BASE}/{self.api_version}/customers/{self._customer_or_fail()}/{path}"
        try:
            async with httpx.AsyncClient(
                timeout=REQUEST_TIMEOUT_SECONDS, transport=self._transport
            ) as client:
                response = await client.post(url, headers=self._headers(), json=payload)
        except httpx.HTTPError as exc:
            logger.warning("Google Ads %s: network error: %s", action, exc)
            raise _CallFailed(
                GoogleAdsApiResult(
                    ok=False,
                    retryable=True,
                    error_category=ErrorCategory.NETWORK,
                    message=f"Network error calling Google Ads ({action}): {exc}",
                )
            ) from exc

        request_id = response.headers.get("request-id")
        try:
            body = response.json()
        except ValueError:
            body = None

        if response.status_code >= 400:
            error = body.get("error") if isinstance(body, dict) else None
            raise _CallFailed(
                self._failure_result(
                    error if isinstance(error, dict) else {},
                    http_status=response.status_code,
                    request_id=request_id,
                    action=action,
                    fallback_text=response.text,
                )
            )
        if not isinstance(body, dict):
            raise _CallFailed(
                GoogleAdsApiResult(
                    ok=False,
                    api_request_id=request_id,
                    error_category=ErrorCategory.UNKNOWN,
                    message=f"Google Ads returned a non-JSON response ({action}).",
                )
            )
        # Only set when partialFailure=true, which we never send — but never treat it as success.
        if body.get("partialFailureError"):
            raise _CallFailed(
                self._failure_result(
                    body["partialFailureError"],
                    http_status=None,
                    request_id=request_id,
                    action=action,
                    fallback_text="partial failure",
                )
            )
        return body, request_id

    @staticmethod
    def _failure_result(
        error: dict[str, Any],
        *,
        http_status: int | None,
        request_id: str | None,
        action: str,
        fallback_text: str,
    ) -> GoogleAdsApiResult:
        codes, messages, failure_request_id = _parse_google_ads_failure(error)
        category, retryable = classify_error_codes(codes, http_status)
        request_id = request_id or failure_request_id
        detail = "; ".join(messages) or fallback_text[:500]
        status_text = f"HTTP {http_status}" if http_status else "error"
        logger.warning(
            "Google Ads %s failed: %s codes=%s request_id=%s category=%s retryable=%s",
            action, status_text, codes, request_id, category, retryable,
        )
        return GoogleAdsApiResult(
            ok=False,
            api_request_id=request_id,
            retryable=retryable,
            error_category=category,
            error_code=codes[0] if codes else None,
            message=f"Google Ads API {status_text} ({action}): {detail}",
        )

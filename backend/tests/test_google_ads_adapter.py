"""Task 002: IP exclusions use the real CampaignCriterionService request shape."""
from __future__ import annotations

import json
from collections.abc import Callable

import httpx
import pytest

from app.adapters.google_ads_adapter import (
    ErrorCategory,
    GoogleAdsAdapter,
    classify_error_codes,
    normalize_ip_block,
)
from app.core.config import settings

CID = "1234567890"
CAMPAIGN = "555"
CRITERION = f"customers/{CID}/campaignCriteria/{CAMPAIGN}~777"
MUTATE_URL = f"https://googleads.googleapis.com/v21/customers/{CID}/campaignCriteria:mutate"
SEARCH_URL = f"https://googleads.googleapis.com/v21/customers/{CID}/googleAds:search"


@pytest.fixture(autouse=True)
def google_configured(monkeypatch):
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_ID", "client-id")
    monkeypatch.setattr(settings, "GOOGLE_DEVELOPER_TOKEN", None)
    monkeypatch.setattr(settings, "GOOGLE_ADS_API_VERSION", "v21")


class Recorder:
    def __init__(self, handler: Callable[[httpx.Request], httpx.Response]):
        self.requests: list[httpx.Request] = []
        self._handler = handler

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self._handler(request)

    def body(self, index: int) -> dict:
        return json.loads(self.requests[index].content)


def adapter(handler, **kwargs) -> tuple[GoogleAdsAdapter, Recorder]:
    recorder = Recorder(handler)
    return (
        GoogleAdsAdapter(
            customer_id=kwargs.pop("customer_id", CID),
            access_token="access-token",
            transport=httpx.MockTransport(recorder),
            **kwargs,
        ),
        recorder,
    )


def google_failure(status: int, *codes: tuple[str, str], request_id: str = "req-err") -> httpx.Response:
    return httpx.Response(
        status,
        json={
            "error": {
                "code": status,
                "message": "Request contains an invalid argument.",
                "details": [
                    {
                        "@type": "type.googleapis.com/google.ads.googleads.v21.errors.GoogleAdsFailure",
                        "errors": [{"errorCode": {kind: value}, "message": f"{kind} {value}"} for kind, value in codes],
                        "requestId": request_id,
                    }
                ],
            }
        },
    )


def search_rows(*ips_and_names: tuple[str, str]) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "results": [
                {"campaignCriterion": {"resourceName": name, "ipBlock": {"ipAddress": ip}}}
                for ip, name in ips_and_names
            ]
        },
        headers={"request-id": "req-search"},
    )


# ---- create ---------------------------------------------------------------

async def test_create_sends_negative_ip_block_criterion():
    ads, rec = adapter(
        lambda r: httpx.Response(200, json={"results": [{"resourceName": CRITERION}]}, headers={"request-id": "req-1"}),
        login_customer_id="999-888-7777",
    )
    result = await ads.create_ip_exclusion(campaign_id=CAMPAIGN, ip_address="203.0.113.7", reason="velocity")

    assert result.ok and result.resource_name == CRITERION and result.api_request_id == "req-1"
    request = rec.requests[0]
    assert str(request.url) == MUTATE_URL
    assert rec.body(0) == {
        "operations": [
            {
                "create": {
                    "campaign": f"customers/{CID}/campaigns/{CAMPAIGN}",
                    "negative": True,
                    "ipBlock": {"ipAddress": "203.0.113.7"},
                }
            }
        ]
    }
    assert request.headers["authorization"] == "Bearer access-token"
    assert request.headers["login-customer-id"] == "9998887777"
    assert "developer-token" not in request.headers


async def test_create_ipv6_and_normalizes_ipv4_mapped():
    ads, rec = adapter(lambda r: httpx.Response(200, json={"results": [{"resourceName": CRITERION}]}))
    assert (await ads.create_ip_exclusion(campaign_id=CAMPAIGN, ip_address="2001:db8::7")).ok
    assert (await ads.create_ip_exclusion(campaign_id=CAMPAIGN, ip_address="::ffff:203.0.113.7/128")).ok
    assert rec.body(0)["operations"][0]["create"]["ipBlock"]["ipAddress"] == "2001:db8::7"
    assert rec.body(1)["operations"][0]["create"]["ipBlock"]["ipAddress"] == "203.0.113.7"


async def test_create_duplicate_adopts_existing_criterion():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("campaignCriteria:mutate"):
            return google_failure(400, ("mutateError", "RESOURCE_ALREADY_EXISTS"), request_id="req-dup")
        return search_rows(("10.9.9.9", f"customers/{CID}/campaignCriteria/{CAMPAIGN}~1"), ("203.0.113.7", CRITERION))

    ads, rec = adapter(handler)
    result = await ads.create_ip_exclusion(campaign_id=CAMPAIGN, ip_address="203.0.113.7")

    assert result.ok and result.already_existed
    assert result.resource_name == CRITERION
    assert result.api_request_id == "req-dup"
    assert len(rec.requests) == 2 and str(rec.requests[1].url) == SEARCH_URL
    query = rec.body(1)["query"]
    assert f"campaign.id = {CAMPAIGN}" in query and "'IP_BLOCK'" in query and "negative = TRUE" in query


async def test_create_invalid_ip_never_calls_google():
    ads, rec = adapter(lambda r: pytest.fail("no HTTP call expected"))
    result = await ads.create_ip_exclusion(campaign_id=CAMPAIGN, ip_address="not-an-ip")
    assert not result.ok and not result.retryable
    assert result.error_category == ErrorCategory.INVALID_REQUEST
    assert rec.requests == []


@pytest.mark.parametrize("customer_id", ["", "abc"])
async def test_create_invalid_customer_never_calls_google(customer_id):
    ads, rec = adapter(lambda r: pytest.fail("no HTTP call expected"), customer_id=customer_id)
    result = await ads.create_ip_exclusion(campaign_id=CAMPAIGN, ip_address="203.0.113.7")
    assert not result.ok and result.error_category == ErrorCategory.INVALID_REQUEST


@pytest.mark.parametrize(
    ("response", "category", "retryable", "code"),
    [
        (google_failure(400, ("criterionError", "INVALID_IP_ADDRESS")), ErrorCategory.INVALID_REQUEST, False, "criterionError.INVALID_IP_ADDRESS"),
        (google_failure(400, ("criterionError", "CANNOT_ADD_CRITERIA_TYPE")), ErrorCategory.UNSUPPORTED, False, "criterionError.CANNOT_ADD_CRITERIA_TYPE"),
        (google_failure(400, ("resourceCountLimitExceededError", "RESOURCE_LIMIT")), ErrorCategory.LIMIT, False, "resourceCountLimitExceededError.RESOURCE_LIMIT"),
        (google_failure(401, ("authenticationError", "OAUTH_TOKEN_REVOKED")), ErrorCategory.AUTH, False, "authenticationError.OAUTH_TOKEN_REVOKED"),
        (google_failure(403, ("authorizationError", "USER_PERMISSION_DENIED")), ErrorCategory.PERMISSION, False, "authorizationError.USER_PERMISSION_DENIED"),
        (google_failure(400, ("requestError", "RESOURCE_NOT_FOUND")), ErrorCategory.NOT_FOUND, False, "requestError.RESOURCE_NOT_FOUND"),
        (google_failure(429, ("quotaError", "RESOURCE_TEMPORARILY_EXHAUSTED")), ErrorCategory.TRANSIENT, True, "quotaError.RESOURCE_TEMPORARILY_EXHAUSTED"),
        (google_failure(500, ("internalError", "TRANSIENT_ERROR")), ErrorCategory.TRANSIENT, True, "internalError.TRANSIENT_ERROR"),
        (httpx.Response(503, text="Service Unavailable"), ErrorCategory.TRANSIENT, True, None),
        (httpx.Response(429, text="Too Many Requests"), ErrorCategory.TRANSIENT, True, None),
    ],
)
async def test_create_failures_are_classified(response, category, retryable, code):
    ads, _ = adapter(lambda r: response)
    result = await ads.create_ip_exclusion(campaign_id=CAMPAIGN, ip_address="203.0.113.7")
    assert not result.ok
    assert result.error_category == category
    assert result.retryable is retryable
    assert result.error_code == code
    if code:
        assert result.api_request_id == "req-err"


async def test_create_network_error_is_retryable():
    def handler(request):
        raise httpx.ConnectTimeout("timed out", request=request)

    ads, _ = adapter(handler)
    result = await ads.create_ip_exclusion(campaign_id=CAMPAIGN, ip_address="203.0.113.7")
    assert not result.ok and result.retryable and result.error_category == ErrorCategory.NETWORK


async def test_create_success_without_resource_name_is_not_success():
    ads, _ = adapter(lambda r: httpx.Response(200, json={"results": []}))
    result = await ads.create_ip_exclusion(campaign_id=CAMPAIGN, ip_address="203.0.113.7")
    assert not result.ok and result.error_category == ErrorCategory.UNKNOWN


async def test_create_partial_failure_payload_is_not_success():
    ads, _ = adapter(
        lambda r: httpx.Response(
            200,
            json={
                "results": [{}],
                "partialFailureError": {
                    "code": 3,
                    "message": "partial",
                    "details": [
                        {
                            "@type": "type.googleapis.com/google.ads.googleads.v21.errors.GoogleAdsFailure",
                            "errors": [{"errorCode": {"criterionError": "INVALID_IP_ADDRESS"}}],
                        }
                    ],
                },
            },
        )
    )
    result = await ads.create_ip_exclusion(campaign_id=CAMPAIGN, ip_address="203.0.113.7")
    assert not result.ok and result.error_code == "criterionError.INVALID_IP_ADDRESS"


# ---- remove ---------------------------------------------------------------

async def test_remove_with_stored_resource_name():
    ads, rec = adapter(lambda r: httpx.Response(200, json={"results": [{"resourceName": CRITERION}]}, headers={"request-id": "req-rm"}))
    result = await ads.remove_ip_exclusion(campaign_id=CAMPAIGN, ip_address="203.0.113.7", resource_name=CRITERION)
    assert result.ok and result.api_request_id == "req-rm"
    assert len(rec.requests) == 1
    assert rec.body(0) == {"operations": [{"remove": CRITERION}]}


@pytest.mark.parametrize(
    "stored",
    [
        None,
        # Fake names written by the old adapter / dry-run must never be sent to Google
        f"customers/{CID}/campaigns/{CAMPAIGN}/ipSettings/abc123",
        # Criterion of a different customer
        f"customers/1111111111/campaignCriteria/{CAMPAIGN}~777",
    ],
)
async def test_remove_without_valid_resource_name_looks_it_up(stored):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("googleAds:search"):
            return search_rows(("203.0.113.7", CRITERION))
        return httpx.Response(200, json={"results": [{"resourceName": CRITERION}]})

    ads, rec = adapter(handler)
    result = await ads.remove_ip_exclusion(campaign_id=CAMPAIGN, ip_address="203.0.113.7", resource_name=stored)
    assert result.ok and result.resource_name == CRITERION
    assert [str(r.url) for r in rec.requests] == [SEARCH_URL, MUTATE_URL]
    assert rec.body(1) == {"operations": [{"remove": CRITERION}]}


async def test_remove_when_absent_in_google_is_success_without_mutate():
    ads, rec = adapter(lambda r: search_rows())
    result = await ads.remove_ip_exclusion(campaign_id=CAMPAIGN, ip_address="203.0.113.7")
    assert result.ok and result.resource_name is None
    assert len(rec.requests) == 1


async def test_remove_already_gone_is_success():
    ads, _ = adapter(lambda r: google_failure(400, ("mutateError", "RESOURCE_NOT_FOUND")))
    result = await ads.remove_ip_exclusion(campaign_id=CAMPAIGN, ip_address="203.0.113.7", resource_name=CRITERION)
    assert result.ok


async def test_remove_transient_failure_is_retryable():
    ads, _ = adapter(lambda r: httpx.Response(503, text="unavailable"))
    result = await ads.remove_ip_exclusion(campaign_id=CAMPAIGN, ip_address="203.0.113.7", resource_name=CRITERION)
    assert not result.ok and result.retryable


# ---- verify / lookup ------------------------------------------------------

async def test_verify_exclusion():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"results": [{"campaignCriterion": {"resourceName": CRITERION, "negative": True, "ipBlock": {"ipAddress": "203.0.113.7"}}}]},
            headers={"request-id": "req-v"},
        )

    ads, rec = adapter(handler)
    result = await ads.verify_exclusion(CRITERION)
    assert result.ok and result.api_request_id == "req-v"
    assert f"campaign_criterion.resource_name = '{CRITERION}'" in rec.body(0)["query"]


async def test_verify_missing_criterion_fails():
    ads, _ = adapter(lambda r: httpx.Response(200, json={"results": []}))
    result = await ads.verify_exclusion(CRITERION)
    assert not result.ok and result.error_category == ErrorCategory.NOT_FOUND


async def test_verify_rejects_foreign_resource_name_without_query():
    ads, rec = adapter(lambda r: pytest.fail("no HTTP call expected"))
    result = await ads.verify_exclusion("customers/1/campaignCriteria/2~3' OR 1=1")
    assert not result.ok and rec.requests == []


async def test_find_follows_pagination():
    pages = iter(
        [
            httpx.Response(200, json={"results": [{"campaignCriterion": {"resourceName": "x", "ipBlock": {"ipAddress": "10.0.0.1"}}}], "nextPageToken": "p2"}),
            search_rows(("203.0.113.7", CRITERION)),
        ]
    )
    ads, rec = adapter(lambda r: next(pages))
    result = await ads.find_ip_exclusion(campaign_id=CAMPAIGN, ip_address="203.0.113.7")
    assert result.ok and result.resource_name == CRITERION
    assert rec.body(1)["pageToken"] == "p2"


# ---- helpers --------------------------------------------------------------

def test_mixed_retryable_and_permanent_codes_are_permanent():
    category, retryable = classify_error_codes(
        ["internalError.TRANSIENT_ERROR", "criterionError.INVALID_IP_ADDRESS"], 400
    )
    assert category == ErrorCategory.INVALID_REQUEST and not retryable


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("203.0.113.7", "203.0.113.7"), ("203.0.113.7/32", "203.0.113.7"), ("2001:DB8::7", "2001:db8::7"), ("203.0.113.0/24", "203.0.113.0/24")],
)
def test_normalize_ip_block(raw, expected):
    assert normalize_ip_block(raw) == expected


@pytest.mark.parametrize("client_id", ["", "client-id"])
async def test_no_access_token_never_reports_success(monkeypatch, client_id):
    # Task 003: no dry-run fallback in the adapter, whatever the config says.
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_ID", client_id)
    recorder = Recorder(lambda r: pytest.fail("no HTTP call expected"))
    ads = GoogleAdsAdapter(customer_id=CID, access_token=None, transport=httpx.MockTransport(recorder))
    for result in (
        await ads.create_ip_exclusion(campaign_id=CAMPAIGN, ip_address="203.0.113.7"),
        await ads.remove_ip_exclusion(campaign_id=CAMPAIGN, ip_address="203.0.113.7", resource_name=CRITERION),
    ):
        assert not result.ok
        assert result.error_category == ErrorCategory.AUTH
        assert result.resource_name is None and result.api_request_id is None
    assert recorder.requests == []

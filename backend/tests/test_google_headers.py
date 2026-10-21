"""Google Ads request headers (developer-token optional, login-customer-id), error logging and manager lookup."""
from __future__ import annotations

import logging

import httpx
import pytest

from app.adapters.google_ads_adapter import GoogleAdsAdapter, GoogleApiError, ads_error_from_response, build_ads_headers
from app.core.config import Settings, settings
from app.services import google_oauth

MANAGER, CLIENT = "2627436323", "7936082600"


def test_developer_token_is_not_a_required_setting():
    assert Settings.model_fields["GOOGLE_DEVELOPER_TOKEN"].default is None
    assert Settings.model_fields["GOOGLE_DEVELOPER_TOKEN"].is_required() is False


def test_no_developer_token_header_when_unset(monkeypatch):
    monkeypatch.setattr(settings, "GOOGLE_DEVELOPER_TOKEN", None)
    headers = build_ads_headers("tok")
    assert "developer-token" not in headers and "login-customer-id" not in headers
    assert headers["Authorization"] == "Bearer tok"
    monkeypatch.setattr(settings, "GOOGLE_DEVELOPER_TOKEN", "")
    assert "developer-token" not in build_ads_headers("tok")


def test_developer_token_header_only_when_set(monkeypatch):
    monkeypatch.setattr(settings, "GOOGLE_DEVELOPER_TOKEN", "dev-token-value")
    assert build_ads_headers("tok")["developer-token"] == "dev-token-value"


def test_login_customer_id_is_digits_only(monkeypatch):
    monkeypatch.setattr(settings, "GOOGLE_DEVELOPER_TOKEN", None)
    assert build_ads_headers("tok", "262-743-6323")["login-customer-id"] == MANAGER
    assert "login-customer-id" not in build_ads_headers("tok", "")
    assert "login-customer-id" not in build_ads_headers("tok", None)


async def test_adapter_sends_login_customer_id_and_no_developer_token(monkeypatch):
    monkeypatch.setattr(settings, "GOOGLE_DEVELOPER_TOKEN", None)
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"results": [{"resourceName": f"customers/{CLIENT}/campaignCriteria/9~8"}]},
                              headers={"request-id": "rid-1"})

    adapter = GoogleAdsAdapter(customer_id=CLIENT, access_token="tok", login_customer_id=MANAGER,
                               transport=httpx.MockTransport(handler))
    result = await adapter.create_ip_exclusion(campaign_id="24375109859", ip_address="203.0.113.7")
    assert result.ok and result.api_request_id == "rid-1"
    assert seen[0].headers["login-customer-id"] == MANAGER and "developer-token" not in seen[0].headers
    assert str(seen[0].url).startswith("https://googleads.googleapis.com/") and f"/customers/{CLIENT}/" in str(seen[0].url)


async def test_adapter_without_manager_sends_no_login_customer_id(monkeypatch):
    monkeypatch.setattr(settings, "GOOGLE_DEVELOPER_TOKEN", None)
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"results": []})

    await GoogleAdsAdapter(customer_id=CLIENT, access_token="tok", transport=httpx.MockTransport(handler)).find_ip_exclusion(
        campaign_id="1", ip_address="203.0.113.7")
    assert "login-customer-id" not in seen[0].headers


class CapturingClient:
    """Stands in for httpx.AsyncClient in google_oauth; records headers of every call."""

    calls: list[dict] = []
    response = httpx.Response(200, json=[])

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, url, headers=None, **kwargs):
        CapturingClient.calls.append({"url": url, "headers": headers})
        return CapturingClient.response

    async def post(self, url, headers=None, **kwargs):
        CapturingClient.calls.append({"url": url, "headers": headers})
        return CapturingClient.response


@pytest.fixture
def capture(monkeypatch):
    CapturingClient.calls = []
    CapturingClient.response = httpx.Response(200, json=[])
    monkeypatch.setattr(google_oauth.httpx, "AsyncClient", CapturingClient)
    monkeypatch.setattr(settings, "GOOGLE_DEVELOPER_TOKEN", None)
    return CapturingClient


async def test_every_oauth_side_google_call_uses_the_shared_headers(capture):
    capture.response = httpx.Response(200, json={"resourceNames": [f"customers/{MANAGER}"]})
    await google_oauth.fetch_accessible_customer_ids("tok")
    capture.response = httpx.Response(200, json=[])
    await google_oauth.list_google_campaigns(access_token="tok", customer_id=CLIENT, login_customer_id=MANAGER)
    await google_oauth.count_ip_exclusions_by_campaign(access_token="tok", customer_id=CLIENT, login_customer_id=MANAGER)
    await google_oauth.list_campaign_locations(access_token="tok", customer_id=CLIENT, login_customer_id=MANAGER)
    assert len(capture.calls) == 4
    listing, *with_manager = capture.calls
    assert "login-customer-id" not in listing["headers"]  # listAccessibleCustomers is never sent as a manager
    for call in capture.calls:
        assert "developer-token" not in call["headers"]
    for call in with_manager:
        assert call["headers"]["login-customer-id"] == MANAGER


async def test_developer_token_still_sent_when_configured(capture, monkeypatch):
    monkeypatch.setattr(settings, "GOOGLE_DEVELOPER_TOKEN", "dev-token-value")
    await google_oauth.list_google_campaigns(access_token="tok", customer_id=CLIENT)
    assert capture.calls[0]["headers"]["developer-token"] == "dev-token-value"


def test_failed_ads_call_is_logged_with_request_id_code_and_customer_but_no_secret(caplog):
    response = httpx.Response(
        403,
        json=[{"error": {"code": 403, "message": "The caller does not have permission", "details": [{
            "@type": "type.googleapis.com/google.ads.googleads.v24.errors.GoogleAdsFailure",
            "errors": [{"errorCode": {"authorizationError": "USER_PERMISSION_DENIED"}, "message": "User doesn't have permission."}],
            "requestId": "body-request-id"}]}}],
        headers={"request-id": "hdr-request-id"},
    )
    with caplog.at_level(logging.WARNING):
        error = ads_error_from_response(response, customer_id=CLIENT, action="list campaigns")
    assert isinstance(error, GoogleApiError) and isinstance(error, ValueError)
    assert error.code == "authorizationError.USER_PERMISSION_DENIED" and error.request_id == "hdr-request-id"
    assert "authorizationError.USER_PERMISSION_DENIED" in str(error) and "hdr-request-id" in str(error)
    line = next(r.getMessage() for r in caplog.records if "list campaigns failed" in r.getMessage())
    assert CLIENT in line and "hdr-request-id" in line and "USER_PERMISSION_DENIED" in line
    assert "Bearer" not in line


async def test_adapter_failure_log_names_the_customer(caplog):
    def handler(request):
        return httpx.Response(400, json={"error": {"message": "bad", "details": [{
            "@type": "type.googleapis.com/google.ads.googleads.v24.errors.GoogleAdsFailure",
            "errors": [{"errorCode": {"criterionError": "INVALID_IP_ADDRESS"}, "message": "bad ip"}]}]}},
            headers={"request-id": "rid-9"})

    adapter = GoogleAdsAdapter(customer_id=CLIENT, access_token="secret-access-token", transport=httpx.MockTransport(handler))
    with caplog.at_level(logging.WARNING):
        result = await adapter.create_ip_exclusion(campaign_id="1", ip_address="203.0.113.7")
    assert not result.ok and result.error_code == "criterionError.INVALID_IP_ADDRESS" and result.api_request_id == "rid-9"
    text = " ".join(r.getMessage() for r in caplog.records)
    assert f"customer_id={CLIENT}" in text and "rid-9" in text and "secret-access-token" not in text


# ---- resolving the manager account ----------------------------------------------------

async def test_resolve_login_customer_id(monkeypatch):
    async def accessible(token):
        return accessible.ids

    queried = []

    async def search(token, customer_id, login_customer_id, query):
        queried.append((customer_id, login_customer_id, query))
        if customer_id == "1111111111":
            raise GoogleApiError("not a manager")
        return [{"customerClient": {"id": CLIENT}}] if customer_id == MANAGER else []

    monkeypatch.setattr(google_oauth, "fetch_accessible_customer_ids", accessible)
    monkeypatch.setattr(google_oauth, "_search_stream", search)

    accessible.ids = [CLIENT]  # reached directly: no manager header
    assert await google_oauth.resolve_login_customer_id("tok", CLIENT) is None and queried == []

    accessible.ids = ["1111111111", MANAGER]  # first one isn't a manager: skipped, the second owns the client
    assert await google_oauth.resolve_login_customer_id("tok", CLIENT) == MANAGER
    assert all(login == customer for customer, login, _ in queried)  # the manager is also the login-customer-id
    assert f"customer_client.id = {CLIENT}" in queried[-1][2]

    accessible.ids = ["1111111111"]
    assert await google_oauth.resolve_login_customer_id("tok", CLIENT) is None


# ---- API version ----------------------------------------------------------------------

def test_default_api_version_is_v24():
    assert Settings.model_fields["GOOGLE_ADS_API_VERSION"].default == "v24"


async def test_every_google_ads_url_uses_the_configured_version(capture, monkeypatch):
    monkeypatch.setattr(settings, "GOOGLE_ADS_API_VERSION", "24")  # a bare number is normalised to v24
    capture.response = httpx.Response(200, json={"resourceNames": []})
    await google_oauth.fetch_accessible_customer_ids("tok")
    capture.response = httpx.Response(200, json=[])
    await google_oauth.list_google_campaigns(access_token="tok", customer_id=CLIENT)
    await google_oauth.count_ip_exclusions_by_campaign(access_token="tok", customer_id=CLIENT)
    await google_oauth.list_campaign_locations(access_token="tok", customer_id=CLIENT)
    urls = [call["url"] for call in capture.calls]
    assert len(urls) == 4 and all("googleads.googleapis.com/v24/" in url for url in urls), urls
    assert urls[0].endswith("/v24/customers:listAccessibleCustomers")
    assert all(url.endswith("/googleAds:searchStream") for url in urls[1:])


async def test_adapter_urls_use_the_configured_version(monkeypatch):
    monkeypatch.setattr(settings, "GOOGLE_ADS_API_VERSION", "v24")
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, json={"results": [{"resourceName": f"customers/{CLIENT}/campaignCriteria/9~8"}]})

    adapter = GoogleAdsAdapter(customer_id=CLIENT, access_token="tok", transport=httpx.MockTransport(handler))
    await adapter.create_ip_exclusion(campaign_id="1", ip_address="203.0.113.7")
    await adapter.find_ip_exclusion(campaign_id="1", ip_address="203.0.113.7")
    assert seen == [f"https://googleads.googleapis.com/v24/customers/{CLIENT}/campaignCriteria:mutate",
                    f"https://googleads.googleapis.com/v24/customers/{CLIENT}/googleAds:search"]

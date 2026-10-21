"""Manager (MCC) id stored on the connection, and the `google-smoke` live-check command (mocked Google)."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.adapters.google_ads_adapter import GoogleAdsApiResult, GoogleApiError
from app.api import google as google_api
from app.core.config import settings
from app.models import GoogleConnection
from app.services import google_smoke
from app.services.audit_service import AuditAction

MANAGER, CLIENT, CAMPAIGN = "2627436323", "7936082600", "24375109859"
CRITERION = f"customers/{CLIENT}/campaignCriteria/{CAMPAIGN}~111"


async def stored(world) -> GoogleConnection:
    async with world.sessionmaker() as db:
        return await db.get(GoogleConnection, world.connection.id)


@pytest.fixture
def derive(monkeypatch):
    """Google side of select-customer: refresh works, the manager lookup answers `derive.manager`."""
    state = SimpleNamespace(manager=None, calls=[])

    async def fake_refresh(refresh_token):
        return {"access_token": "access-token"}

    async def fake_resolve(access_token, customer_id):
        state.calls.append(customer_id)
        if isinstance(state.manager, Exception):
            raise state.manager
        return state.manager

    monkeypatch.setattr(google_api, "refresh_access_token", fake_refresh)
    monkeypatch.setattr(google_api, "resolve_login_customer_id", fake_resolve)
    return state


# ---- select-customer stores the manager ---------------------------------------------------

async def test_select_customer_stores_an_explicit_manager_without_asking_google(world, derive):
    async with world.api() as client:
        response = await client.post("/api/v1/google/select-customer", json={"customer_id": CLIENT, "login_customer_id": MANAGER})
    assert response.status_code == 200 and response.json()["login_customer_id"] == MANAGER
    assert derive.calls == []
    connection = await stored(world)
    assert (connection.customer_id, connection.login_customer_id) == (CLIENT, MANAGER)


async def test_select_customer_derives_the_manager_from_the_hierarchy(world, derive):
    derive.manager = MANAGER
    async with world.api() as client:
        response = await client.post("/api/v1/google/select-customer", json={"customer_id": CLIENT})
    assert response.status_code == 200 and response.json()["login_customer_id"] == MANAGER
    assert derive.calls == [CLIENT]
    assert (await stored(world)).login_customer_id == MANAGER
    audit = [a for a in await world.audit(AuditAction.GOOGLE_SELECT_CUSTOMER)]
    assert audit[-1].details["login_customer_id"] == MANAGER


async def test_directly_accessible_customer_has_no_manager_and_clears_an_old_one(world, derive):
    async with world.sessionmaker() as db:
        connection = await db.get(GoogleConnection, world.connection.id)
        connection.login_customer_id = MANAGER
        await db.commit()
    derive.manager = None
    async with world.api() as client:
        assert (await client.post("/api/v1/google/select-customer", json={"customer_id": CLIENT})).status_code == 200
    assert (await stored(world)).login_customer_id is None


async def test_manager_lookup_failure_does_not_block_selecting_the_customer(world, derive):
    derive.manager = GoogleApiError("Google Ads API HTTP 500", status=500)
    async with world.api() as client:
        response = await client.post("/api/v1/google/select-customer", json={"customer_id": CLIENT})
    assert response.status_code == 200 and response.json()["customer_id"] == CLIENT
    assert (await stored(world)).login_customer_id is None


async def test_campaign_sync_uses_the_stored_manager(world, monkeypatch):
    async with world.sessionmaker() as db:
        connection = await db.get(GoogleConnection, world.connection.id)
        connection.customer_id, connection.login_customer_id = CLIENT, MANAGER
        await db.commit()
    seen = {}

    async def fake_refresh(refresh_token):
        return {"access_token": "access-token"}

    async def fake_campaigns(**kwargs):
        seen.update(kwargs)
        return []

    async def no_locations(**kwargs):
        return {}

    async def no_counts(**kwargs):
        return {}

    monkeypatch.setattr(google_api, "refresh_access_token", fake_refresh)
    monkeypatch.setattr(google_api, "list_google_campaigns", fake_campaigns)
    monkeypatch.setattr(google_api, "list_campaign_locations", no_locations)
    monkeypatch.setattr(google_api, "count_ip_exclusions_by_campaign", no_counts)
    async with world.api() as client:
        response = await client.post("/api/v1/google/campaigns/sync")
    assert response.status_code == 200, response.text
    assert seen["customer_id"] == CLIENT and seen["login_customer_id"] == MANAGER


# ---- google-smoke -------------------------------------------------------------------------

class FakeAdapter:
    instances: list["FakeAdapter"] = []
    create_result = GoogleAdsApiResult(ok=True, resource_name=CRITERION, api_request_id="rid-create")
    verify_result = GoogleAdsApiResult(ok=True, resource_name=CRITERION, api_request_id="rid-verify")
    remove_result = GoogleAdsApiResult(ok=True, resource_name=CRITERION, message="Google Ads IP exclusion removed.")

    def __init__(self, **kwargs):
        self.kwargs, self.calls = kwargs, []
        FakeAdapter.instances.append(self)

    async def create_ip_exclusion(self, **kwargs):
        self.calls.append(("create", kwargs))
        return FakeAdapter.create_result

    async def verify_exclusion(self, resource_name):
        self.calls.append(("verify", resource_name))
        return FakeAdapter.verify_result

    async def remove_ip_exclusion(self, **kwargs):
        self.calls.append(("remove", kwargs))
        return FakeAdapter.remove_result


@pytest.fixture
def smoke(world, monkeypatch):
    """Everything the smoke command asks of Google, answered locally."""
    FakeAdapter.instances = []
    FakeAdapter.create_result = GoogleAdsApiResult(ok=True, resource_name=CRITERION, api_request_id="rid-create")
    FakeAdapter.verify_result = GoogleAdsApiResult(ok=True, resource_name=CRITERION, api_request_id="rid-verify")
    FakeAdapter.remove_result = GoogleAdsApiResult(ok=True, resource_name=CRITERION, message="Google Ads IP exclusion removed.")
    state = {"accessible": [MANAGER], "campaigns": [{"campaign_id": CAMPAIGN, "name": "Test search", "campaign_type": "SEARCH",
                                                      "status": "ENABLED"}], "refresh_error": None, "list_error": None}
    seen = {}

    async def fake_refresh(refresh_token):
        seen["refresh_token"] = refresh_token
        if state["refresh_error"]:
            raise state["refresh_error"]
        return {"access_token": "SECRET-ACCESS-TOKEN"}

    async def fake_accessible(access_token):
        return state["accessible"]

    async def fake_campaigns(**kwargs):
        seen["campaigns"] = kwargs
        if state["list_error"]:
            raise state["list_error"]
        return state["campaigns"]

    async def fake_resolve(access_token, customer_id):
        seen["resolved"] = customer_id
        return MANAGER

    monkeypatch.setattr(google_smoke, "refresh_access_token", fake_refresh)
    monkeypatch.setattr(google_smoke, "fetch_accessible_customer_ids", fake_accessible)
    monkeypatch.setattr(google_smoke, "list_google_campaigns", fake_campaigns)
    monkeypatch.setattr(google_smoke, "resolve_login_customer_id", fake_resolve)
    monkeypatch.setattr(google_smoke, "GoogleAdsAdapter", FakeAdapter)
    state["seen"] = seen
    return state


async def point_connection_at_the_test_hierarchy(world):
    async with world.sessionmaker() as db:
        connection = await db.get(GoogleConnection, world.connection.id)
        connection.customer_id, connection.login_customer_id = CLIENT, MANAGER
        await db.commit()


async def run(world, **kwargs) -> tuple[int, str]:
    lines: list[str] = []
    code = await google_smoke.run_smoke(str(world.connection.id), CAMPAIGN, session_factory=world.sessionmaker,
                                        out=lines.append, **kwargs)
    return code, "\n".join(lines)


async def test_smoke_walks_every_step_and_cleans_up(world, smoke):
    await point_connection_at_the_test_hierarchy(world)
    code, output = await run(world, cleanup=True)
    assert code == 0, output
    for step in ("load connection", "refresh access token", "(a) list accessible customers", "(b) list campaigns",
                 "(c) add IP exclusion", "(d) read back", "(e) remove IP exclusion"):
        assert f"[OK]   {step}" in output, output
    assert "[FAIL]" not in output and "all steps passed" in output
    assert f"customer {CLIENT}, login-customer-id {MANAGER}" in output and CRITERION in output
    adapter = FakeAdapter.instances[0]
    assert adapter.kwargs == {"customer_id": CLIENT, "access_token": "SECRET-ACCESS-TOKEN", "login_customer_id": MANAGER}
    assert [c[0] for c in adapter.calls] == ["create", "verify", "remove"]
    assert adapter.calls[0][1]["ip_address"] == "203.0.113.7" and adapter.calls[0][1]["campaign_id"] == CAMPAIGN
    assert smoke["seen"]["campaigns"]["login_customer_id"] == MANAGER
    assert smoke["seen"]["refresh_token"] == "refresh-token"  # decrypted from the stored value


async def test_smoke_never_prints_tokens(world, smoke):
    await point_connection_at_the_test_hierarchy(world)
    _, output = await run(world, cleanup=True)
    assert "SECRET-ACCESS-TOKEN" not in output and "refresh-token" not in output
    assert world.connection.refresh_token_encrypted not in output


async def test_smoke_without_cleanup_leaves_the_exclusion_and_says_so(world, smoke):
    await point_connection_at_the_test_hierarchy(world)
    code, output = await run(world, ip="198.51.100.9")
    assert code == 0
    assert [c[0] for c in FakeAdapter.instances[0].calls] == ["create", "verify"]
    assert "198.51.100.9 stays excluded" in output and "--cleanup" in output


async def test_smoke_reports_google_error_code_message_and_request_id(world, smoke):
    await point_connection_at_the_test_hierarchy(world)
    FakeAdapter.create_result = GoogleAdsApiResult(
        ok=False, error_code="authorizationError.USER_PERMISSION_DENIED", api_request_id="rid-denied",
        message="Google Ads API HTTP 403 (create IP exclusion): User doesn't have permission to access customer.")
    code, output = await run(world, cleanup=True)
    assert code == 1
    assert "[FAIL] (c) add IP exclusion" in output
    assert "authorizationError.USER_PERMISSION_DENIED" in output and "rid-denied" in output and "doesn't have permission" in output
    assert [c[0] for c in FakeAdapter.instances[0].calls] == ["create"]  # nothing to read back or remove
    assert "[SKIP] (e)" in output and "FAILED" in output


async def test_smoke_cleans_up_even_when_the_read_back_fails(world, smoke):
    await point_connection_at_the_test_hierarchy(world)
    FakeAdapter.verify_result = GoogleAdsApiResult(ok=False, error_code="x.NOT_FOUND", api_request_id="rid-v", message="gone")
    code, output = await run(world, cleanup=True)
    assert code == 1 and "[FAIL] (d) read back" in output and "[OK]   (e) remove IP exclusion" in output


async def test_smoke_reports_a_failing_google_listing_and_stops_before_changing_anything(world, smoke):
    await point_connection_at_the_test_hierarchy(world)
    smoke["list_error"] = GoogleApiError("Google Ads API HTTP 403 [authorizationError.CUSTOMER_NOT_ENABLED] (list campaigns): nope",
                                         status=403, code="authorizationError.CUSTOMER_NOT_ENABLED", request_id="rid-list")
    code, output = await run(world)
    assert code == 1 and "[FAIL] (b) list campaigns" in output
    assert "authorizationError.CUSTOMER_NOT_ENABLED" in output and "rid-list" in output
    assert FakeAdapter.instances == []


async def test_smoke_fails_when_the_campaign_is_not_in_the_customer(world, smoke):
    await point_connection_at_the_test_hierarchy(world)
    smoke["campaigns"] = [{"campaign_id": "999", "name": "Other", "campaign_type": "SEARCH", "status": "ENABLED"}]
    code, output = await run(world)
    assert code == 1 and f"none has id {CAMPAIGN}" in output and FakeAdapter.instances == []


async def test_smoke_reports_a_rejected_refresh_token(world, smoke):
    from app.services.google_oauth import GoogleAuthError

    await point_connection_at_the_test_hierarchy(world)
    smoke["refresh_error"] = GoogleAuthError("Failed to refresh Google OAuth token (invalid_grant: Token has been revoked.)",
                                             permanent=True, error_code="invalid_grant")
    code, output = await run(world)
    assert code == 1 and "[FAIL] refresh access token - invalid_grant" in output


async def test_smoke_refuses_to_run_in_dry_run(world, smoke, monkeypatch):
    monkeypatch.setattr(settings, "GOOGLE_ADS_DRY_RUN", True)
    code, output = await run(world)
    assert code == 2 and "GOOGLE_ADS_DRY_RUN=true" in output and "GOOGLE_ADS_DRY_RUN=false" in output
    assert FakeAdapter.instances == [] and "refresh_token" not in smoke["seen"]


async def test_smoke_customer_override_looks_up_the_manager(world, smoke):
    code, output = await run(world, customer_id=CLIENT)
    assert code == 0, output
    assert smoke["seen"]["resolved"] == CLIENT and FakeAdapter.instances[0].kwargs["login_customer_id"] == MANAGER


async def test_smoke_accepts_a_campaign_row_id_and_rejects_unknown_connections(world, smoke):
    await point_connection_at_the_test_hierarchy(world)
    lines: list[str] = []
    code = await google_smoke.run_smoke(str(world.connection.id), str(world.campaign.id), session_factory=world.sessionmaker,
                                        out=lines.append)
    assert code == 1  # the fixture campaign (555) isn't in Google's answer, but the row id was resolved
    assert "none has id 555" in "\n".join(lines)
    lines.clear()
    assert await google_smoke.run_smoke("00000000-0000-0000-0000-000000000000", CAMPAIGN, session_factory=world.sessionmaker,
                                        out=lines.append) == 1
    assert "no connection" in lines[0]

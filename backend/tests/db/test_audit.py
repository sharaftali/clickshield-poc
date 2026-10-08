"""Task 011: audit trail — written for every action, readable per tenant only, never holds secrets."""
from __future__ import annotations

import httpx
from sqlalchemy import select

from app.adapters.google_ads_adapter import ErrorCategory, GoogleAdsApiResult
from app.main import app
from app.models import AuditResult, Organization, User
from app.services.audit_service import REDACTED, SENSITIVE_KEY_PARTS, AuditAction
from app.services.protection_service import enqueue_exclusion_for_session


def anonymous_client(ip: str = "198.51.100.40") -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=(ip, 53000)), base_url="http://test")


async def queue_exclusion(world, ip: str):
    session = await world.fraud_session(ip)
    async with world.sessionmaker() as db:
        result = await enqueue_exclusion_for_session(db, session)
        await db.commit()
    return result


def walk_keys(value):
    if isinstance(value, dict):
        for key, item in value.items():
            yield key, item
            yield from walk_keys(item)
    elif isinstance(value, list):
        for item in value:
            yield from walk_keys(item)


# ---- what gets written ------------------------------------------------------

async def test_exclusion_lifecycle_is_audited_like_spec_44(world):
    await queue_exclusion(world, "198.51.100.41")
    await world.run_worker()

    [queued] = await world.audit(AuditAction.EXCLUSION_QUEUED)
    [added] = await world.audit(AuditAction.ADD_IP_EXCLUSION)
    # Spec §44 example: action, IP, risk, confidence, campaign, timestamp, API result, Google request id.
    assert added.details["ip"] == "198.51.100.41"
    assert added.details["risk"] == 92 and added.details["confidence"] == 95
    assert added.details["campaign_id"] == "555"
    assert added.result == AuditResult.SUCCESS and added.google_request_id == "req-1"
    assert added.created_at is not None
    assert queued.organization_id == world.organization.id and queued.user_id is None  # system action


async def test_permanent_google_failure_is_audited(world):
    world.google_results = [GoogleAdsApiResult(
        ok=False, retryable=False, error_category=ErrorCategory.INVALID_REQUEST,
        error_code="criterionError.INVALID_IP_ADDRESS", message="bad ip", api_request_id="req-bad",
    )]
    await queue_exclusion(world, "198.51.100.42")
    await world.run_worker()
    [failed] = await world.audit(AuditAction.EXCLUSION_FAILED)
    assert failed.result == AuditResult.FAILED
    assert failed.details["error_code"] == "criterionError.INVALID_IP_ADDRESS"
    assert failed.google_request_id == "req-bad"


async def test_register_persists_the_account_and_is_audited(world):
    payload = {"full_name": "New Owner", "email": "new.owner@clickshield-tests.io", "password": "Correct-Horse-1",
               "organization_name": "New Org", "protection_mode": "balanced"}
    async with anonymous_client() as client:
        response = await client.post("/api/v1/auth/register", json=payload)
        assert response.status_code == 201, response.text
        token = response.json()["tokens"]["access_token"]
        # Regression: registration used to be rolled back (no commit) — the new account must work.
        me = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert me.status_code == 200, me.text

    [registered] = await world.audit(AuditAction.USER_REGISTER)
    assert registered.details["email"] == "new.owner@clickshield-tests.io"
    assert str(registered.ip_address) == "198.51.100.40"


async def test_login_success_and_failures_are_audited_with_actor_ip(world):
    async with world.sessionmaker() as db:
        user = (await db.execute(select(User).where(User.id == world.user.id))).scalar_one()
    async with anonymous_client("198.51.100.43") as client:
        assert (await client.post("/api/v1/auth/login", json={"email": user.email, "password": "wrong-password"})).status_code == 401
        assert (await client.post("/api/v1/auth/login", json={"email": "nobody@clickshield-tests.io", "password": "x" * 10})).status_code == 401
        assert (await client.post("/api/v1/auth/login", json={"email": user.email, "password": "Correct-Horse-1"})).status_code == 200

    failures = await world.audit(AuditAction.USER_LOGIN_FAILED)
    assert [f.details["reason"] for f in failures] == ["wrong_password", "unknown_email"]
    assert failures[0].organization_id == world.organization.id
    assert failures[1].organization_id is None  # unknown email: no tenant
    assert all(str(f.ip_address) == "198.51.100.43" for f in failures)
    [success] = await world.audit(AuditAction.USER_LOGIN_SUCCESS)
    assert success.user_id == world.user.id


async def test_feedback_and_campaign_toggle_are_audited(world):
    session = await world.fraud_session("198.51.100.44")
    async with world.api() as client:
        r1 = await client.patch(f"/api/v1/dashboard/sessions/{session.id}/feedback", json={"client_verdict": "legitimate"})
        r2 = await client.patch(f"/api/v1/google/campaigns/{world.campaign.id}/protection", json={"protection_enabled": False})
    assert r1.status_code == 200 and r2.status_code == 200
    [feedback] = await world.audit(AuditAction.SESSION_FEEDBACK)
    [toggle] = await world.audit(AuditAction.CAMPAIGN_PROTECTION_TOGGLED)
    assert feedback.details["client_verdict"] == "legitimate" and feedback.user_id == world.user.id
    assert toggle.details == {"campaign_id": "555", "campaign_name": "Emergency Plumbing",
                              "protection_enabled": False, "previous": True}


# ---- reading it back --------------------------------------------------------

async def test_audit_api_is_tenant_scoped(world, make_tenant):
    await queue_exclusion(world, "198.51.100.45")
    _, other_user, *_ = await make_tenant("Globex")

    async with world.api() as mine:
        own = (await mine.get("/api/v1/audit-logs")).json()
    async with world.api(other_user) as theirs:
        other = (await theirs.get("/api/v1/audit-logs")).json()
        assert (await theirs.get("/api/v1/audit-logs/actions")).json() == []

    assert own["total"] >= 1 and other == {"items": [], "total": 0, "limit": 50, "offset": 0}


async def test_audit_api_filters_and_paginates(world):
    for i in range(3):
        await queue_exclusion(world, f"198.51.100.5{i}")
    async with world.api() as client:
        page = (await client.get("/api/v1/audit-logs", params={"action": "exclusion_queued", "limit": 2})).json()
        rest = (await client.get("/api/v1/audit-logs", params={"action": "EXCLUSION_QUEUED", "limit": 2, "offset": 2})).json()
        bad_ip = await client.get("/api/v1/audit-logs", params={"ip": "not-an-ip"})
    assert page["total"] == 3 and len(page["items"]) == 2 and len(rest["items"]) == 1
    assert bad_ip.status_code == 422


async def test_audit_api_has_no_write_endpoints(world):
    async with world.api() as client:
        for method in ("post", "put", "patch", "delete"):
            response = await getattr(client, method)("/api/v1/audit-logs")
            assert response.status_code == 405


# ---- secrets ----------------------------------------------------------------

async def test_no_secret_values_are_stored_in_any_audit_row(world):
    async with anonymous_client() as client:
        await client.post("/api/v1/auth/register", json={
            "full_name": "Secret Tester", "email": "secret@clickshield-tests.io", "password": "Super-Secret-Pass-9",
            "organization_name": "Secretive"})
        await client.post("/api/v1/auth/login", json={"email": "secret@clickshield-tests.io", "password": "Super-Secret-Pass-9"})
    await queue_exclusion(world, "198.51.100.46")
    await world.run_worker()

    rows = await world.audit()
    assert rows
    for row in rows:
        for key, value in walk_keys(row.details or {}):
            if any(part in key.lower() for part in SENSITIVE_KEY_PARTS):
                assert value == REDACTED, (row.action, key)
        flat = repr(row.details) + repr(row.error_message)
        assert "Super-Secret-Pass-9" not in flat
        assert "refresh-token" not in flat  # the stored Google refresh token
    async with world.sessionmaker() as db:
        assert (await db.execute(select(Organization).where(Organization.slug.like("secretive%")))).scalar_one()

"""Tasks 023 (websites, verification, Origin), 024 (attribution, automation signals) and 031 (limits)."""
from __future__ import annotations

import json
from datetime import datetime, timezone

import httpx
from sqlalchemy import select

from app.core.config import settings
from app.main import app
from app.models import FraudEvent, Website
from app.services.audit_service import AuditAction
from tests.conftest import HUMAN_UA


def event(token: str, **extra) -> dict:
    return {"site_token": token, "visitor_token": "v_p3_visitor_01", "session_token": extra.pop("session", "s_p3_session_01"),
            "event_type": extra.pop("event_type", "page_view"), "page_url": "https://example.test/",
            "timestamp": datetime.now(timezone.utc).isoformat(), **extra}


async def post_track(body, *, origin: str | None, ip: str = "198.51.100.200", content_type="application/json", user_agent=HUMAN_UA):
    headers = {"user-agent": user_agent, "content-type": content_type}
    if origin:
        headers["origin"] = origin
    transport = httpx.ASGITransport(app=app, client=(ip, 51000))
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.post("/api/v1/track", content=json.dumps(body), headers=headers)


async def create_site(world, domain="example.test", **extra) -> dict:
    async with world.api() as client:
        response = await client.post("/api/v1/websites", json={"domain": domain, **extra})
    assert response.status_code == 201, response.text
    return response.json()


# ---- task 023 --------------------------------------------------------------------

async def test_add_website_install_and_get_verified_by_first_event(world):
    site = await create_site(world, "HTTPS://Example.test/landing", display_name="Example")
    assert site["domain"] == "example.test" and site["is_verified"] is False
    assert f'data-site-id="{site["tracking_token"]}"' in site["snippet"]

    # Before verification nothing is scored; the first event from the site's own origin verifies it.
    first = await post_track({"events": [event(site["tracking_token"])]}, origin="https://www.example.test")
    assert first.status_code == 200 and first.json()["status"] == "verified"
    async with world.api() as client:
        detail = (await client.get(f"/api/v1/websites/{site['id']}")).json()
    assert detail["is_verified"] and detail["verification_method"] == "first_event"
    assert [a.action for a in await world.audit(AuditAction.WEBSITE_VERIFIED)] == ["WEBSITE_VERIFIED"]

    scored = await post_track({"events": [event(site["tracking_token"])]}, origin="https://example.test")
    assert scored.json()["status"] == "ok" and scored.json()["session_id"]


async def test_unverified_site_rejects_foreign_or_missing_origin(world):
    site = await create_site(world)
    for origin in ("https://evil.test", None):
        response = await post_track({"events": [event(site["tracking_token"])]}, origin=origin)
        assert response.status_code == 403
    async with world.api() as client:
        assert (await client.get(f"/api/v1/websites/{site['id']}")).json()["is_verified"] is False


async def test_token_used_from_another_site_is_rejected(world):
    response = await post_track({"events": [event(world.website.tracking_token)]}, origin="https://evil.test")
    assert response.status_code == 403 and "not allowed" in response.json()["detail"]


async def test_origin_check_can_be_turned_off_per_website(world):
    async with world.api() as client:
        await client.patch(f"/api/v1/websites/{world.website.id}", json={"enforce_origin": False})
    response = await post_track({"events": [event(world.website.tracking_token)]}, origin="https://elsewhere.test")
    assert response.status_code == 200


async def test_missing_origin_is_accepted_but_flagged_as_automation(world):
    response = await post_track({"events": [event(world.website.tracking_token)]}, origin=None)
    assert response.status_code == 200
    async with world.sessionmaker() as db:
        reasons = set((await db.execute(
            select(FraudEvent.reason_code).where(FraudEvent.session_id == response.json()["session_id"])
        )).scalars())
    assert "AUTOMATION_SIGNAL" in reasons


async def test_token_rotation_invalidates_the_old_token_immediately(world):
    old = world.website.tracking_token
    async with world.api() as client:
        rotated = (await client.post(f"/api/v1/websites/{world.website.id}/rotate-token")).json()
    assert rotated["tracking_token"] != old
    origin = f"https://{world.website.domain}"
    assert (await post_track({"events": [event(old)]}, origin=origin)).status_code == 400
    assert (await post_track({"events": [event(rotated["tracking_token"])]}, origin=origin)).status_code == 200
    assert await world.audit(AuditAction.WEBSITE_TOKEN_ROTATED)


async def test_deleted_website_stops_tracking_and_is_hidden(world):
    async with world.api() as client:
        assert (await client.delete(f"/api/v1/websites/{world.website.id}")).json()["is_active"] is False
        listed = (await client.get("/api/v1/websites")).json()
    assert listed == []
    response = await post_track({"events": [event(world.website.tracking_token)]}, origin=f"https://{world.website.domain}")
    assert response.status_code == 400


async def test_websites_are_tenant_scoped(world, make_tenant):
    _org, other_user, other_site, _c, _cmp = await make_tenant("Other")
    async with world.api() as client:
        assert (await client.get(f"/api/v1/websites/{other_site.id}")).status_code == 404
        assert (await client.post(f"/api/v1/websites/{other_site.id}/rotate-token")).status_code == 404
        assert [w["id"] for w in (await client.get("/api/v1/websites")).json()] == [str(world.website.id)]


async def test_verify_endpoint_with_mocked_page(world, monkeypatch):
    site = await create_site(world, "fetched.test")
    from app.api import websites as websites_api
    from app.services.website_service import VerifyResult

    async def fake_verify(website, **_):
        return VerifyResult(True, "meta_tag", "Verification meta tag found.")

    monkeypatch.setattr(websites_api, "verify_by_fetch", fake_verify)
    async with world.api() as client:
        result = (await client.post(f"/api/v1/websites/{site['id']}/verify")).json()
    assert result["verified"] and result["website"]["verification_method"] == "meta_tag"


# ---- task 024 (backend side) ---------------------------------------------------------

async def test_sendbeacon_text_plain_body_and_new_attribution_fields(world):
    body = {"events": [
        event(world.website.tracking_token, event_type="ad_landing", wbraid="WB1", adgroup_id="123", keyword="plumber",
              matchtype="e", utm_source="google",
              payload={"automation": {"webdriver": True, "headless": False, "no_languages": False, "tiny_viewport": False}}),
        event(world.website.tracking_token, event_type="form_submit"),
    ]}
    response = await post_track(body, origin=f"https://{world.website.domain}", content_type="text/plain")
    assert response.status_code == 200
    [session] = await world.sessions("198.51.100.200")
    assert (session.wbraid, session.ad_group_id, session.keyword, session.match_type) == ("WB1", "123", "plumber", "e")
    assert session.ad_landing_at is not None  # wbraid = paid click
    async with world.sessionmaker() as db:
        rows = {r.reason_code: r for r in (await db.execute(
            select(FraudEvent).where(FraudEvent.session_id == session.id, FraudEvent.triggered.is_(True)))).scalars()}
    assert "navigator.webdriver" in rows["AUTOMATION_SIGNAL"].reason_text
    # A submitted form is a human action: no bounce rule despite the short session.
    assert "UNUSUAL_SESSION" not in rows


# ---- task 031 --------------------------------------------------------------------------

async def test_track_rate_limit_per_ip_returns_429_and_feeds_scoring(world, monkeypatch):
    monkeypatch.setattr(settings, "TRACKING_RATE_LIMIT_PER_MINUTE", 3)
    origin = f"https://{world.website.domain}"
    statuses = [(await post_track({"events": [event(world.website.tracking_token, session=f"s_rl_session_{i:02d}")]},
                                  origin=origin, ip="198.51.100.210")).status_code for i in range(4)]
    assert statuses == [200, 200, 200, 429]
    monkeypatch.setattr(settings, "TRACKING_RATE_LIMIT_PER_MINUTE", 300)
    limited = await post_track({"events": [event(world.website.tracking_token, session="s_rl_session_99")]},
                               origin=origin, ip="198.51.100.210")
    async with world.sessionmaker() as db:
        reason = await db.scalar(select(FraudEvent.reason_text).where(
            FraudEvent.session_id == limited.json()["session_id"], FraudEvent.reason_code == "AUTOMATION_SIGNAL"))
    assert "rate-limited" in reason


async def test_track_keeps_working_when_redis_is_down(world, fake_redis):
    fake_redis.down = True
    response = await post_track({"events": [event(world.website.tracking_token)]}, origin=f"https://{world.website.domain}")
    assert response.status_code == 200


async def test_login_is_limited_per_email_after_failures(world):
    transport = httpx.ASGITransport(app=app, client=("198.51.100.230", 52000))
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        codes = [(await client.post("/api/v1/auth/login", json={"email": world.user.email, "password": "wrong-pass-1"})).status_code
                 for _ in range(6)]
        good = await client.post("/api/v1/auth/login", json={"email": world.user.email, "password": "Correct-Horse-1"})
    assert codes[:5] == [401] * 5 and codes[5] == 429
    assert good.status_code == 429 and "retry-after" in good.headers


async def test_register_is_limited_per_ip(world, monkeypatch):
    monkeypatch.setattr(settings, "REGISTER_RATE_LIMIT_PER_IP_PER_HOUR", 2)
    transport = httpx.ASGITransport(app=app, client=("198.51.100.231", 52000))
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        codes = [(await client.post("/api/v1/auth/register", json={
            "full_name": "Rita R", "email": f"rita{i}@limits-tests.io", "password": "Secret-Pass-1",
            "organization_name": f"Rita Org {i}"})).status_code for i in range(3)]
    assert codes == [201, 201, 429]


async def test_website_row_is_touched_at_most_once_a_minute(world):
    origin = f"https://{world.website.domain}"
    await post_track({"events": [event(world.website.tracking_token)]}, origin=origin)
    async with world.sessionmaker() as db:
        first = (await db.get(Website, world.website.id)).last_event_at
    await post_track({"events": [event(world.website.tracking_token)]}, origin=origin)
    async with world.sessionmaker() as db:
        assert (await db.get(Website, world.website.id)).last_event_at == first

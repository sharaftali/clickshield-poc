"""Tasks 030 (RBAC, members, invitations), 033 (OAuth state in Redis) and 027 (platform admin, health)."""
from __future__ import annotations

import uuid
from urllib.parse import parse_qs, urlsplit

import httpx
from sqlalchemy import select

from app.api import google as google_api
from app.core.security import hash_password
from app.main import app
from app.models import ActionStatus, ExclusionStatus, GoogleConnection, PlatformAction, User, UserRole
from app.services.audit_service import AuditAction


async def add_user(world, role: UserRole, *, platform_admin: bool = False) -> User:
    async with world.sessionmaker() as db:
        user = User(organization_id=world.organization.id, email=f"{role.value}-{uuid.uuid4().hex[:6]}@acme-tests.io",
                    hashed_password=hash_password("Correct-Horse-1"), full_name=role.value.title(), role=role,
                    is_platform_admin=platform_admin)
        db.add(user)
        await db.commit()
        return user


# ---- task 030 -----------------------------------------------------------------------

async def test_member_can_read_and_give_feedback_but_not_configure(world):
    member = await add_user(world, UserRole.MEMBER)
    session = await world.fraud_session("198.51.100.240")
    async with world.api(member) as client:
        assert (await client.get("/api/v1/dashboard/overview")).status_code == 200
        assert (await client.get("/api/v1/websites")).status_code == 200
        feedback = await client.patch(f"/api/v1/dashboard/sessions/{session.id}/feedback", json={"client_verdict": "legitimate"})
        assert feedback.status_code == 200
        forbidden = [
            await client.patch(f"/api/v1/google/campaigns/{world.campaign.id}/protection", json={"protection_enabled": False}),
            await client.post("/api/v1/google/campaigns/sync"),
            await client.post("/api/v1/google/connect"),
            await client.post("/api/v1/websites", json={"domain": "new.test"}),
            await client.post(f"/api/v1/websites/{world.website.id}/rotate-token"),
            await client.patch("/api/v1/rules/VPN_DETECTED", json={"weight": 1}),
            await client.patch("/api/v1/organizations/me", json={"timezone": "Europe/Berlin"}),
            await client.post("/api/v1/users/invitations", json={"email": "x@acme-tests.io"}),
            await client.post("/api/v1/privacy/erase", json={"ip": "198.51.100.240"}),
        ]
    assert [r.status_code for r in forbidden] == [403] * len(forbidden)
    assert "member" in forbidden[0].json()["detail"]


async def test_admin_can_configure_but_not_manage_users(world):
    admin = await add_user(world, UserRole.ADMIN)
    async with world.api(admin) as client:
        toggled = await client.patch(f"/api/v1/google/campaigns/{world.campaign.id}/protection", json={"protection_enabled": False})
        invite = await client.post("/api/v1/users/invitations", json={"email": "y@acme-tests.io"})
    assert toggled.status_code == 200 and invite.status_code == 403


async def test_owner_invites_member_who_joins_with_member_rights(world):
    async with world.api() as client:
        created = await client.post("/api/v1/users/invitations", json={"email": "Bob@Acme-Tests.io", "role": "member"})
    assert created.status_code == 201
    token = parse_qs(urlsplit(created.json()["invite_url"]).query)["token"][0]
    assert world.emails and world.emails[0][0] == "bob@acme-tests.io" and token in world.emails[0][2]

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as anonymous:
        preview = await anonymous.get(f"/api/v1/auth/invitations/{token}")
        joined = await anonymous.post("/api/v1/auth/accept-invite", json={"token": token, "full_name": "Bob B", "password": "Secret-Pass-9"})
        replay = await anonymous.post("/api/v1/auth/accept-invite", json={"token": token, "full_name": "Bob B", "password": "Secret-Pass-9"})
    assert preview.json()["organization_name"] == world.organization.name
    assert joined.status_code == 201 and joined.json()["user"]["role"] == "member"
    assert joined.json()["organization"]["id"] == str(world.organization.id)
    assert replay.status_code == 404

    headers = {"Authorization": f"Bearer {joined.json()['tokens']['access_token']}"}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test", headers=headers) as bob:
        assert (await bob.get("/api/v1/dashboard/sessions")).status_code == 200
        assert (await bob.patch("/api/v1/organizations/me", json={"protection_mode": "aggressive"})).status_code == 403
    actions = {a.action for a in await world.audit()}
    assert {AuditAction.USER_INVITED, AuditAction.INVITATION_ACCEPTED} <= actions


async def test_last_owner_cannot_be_demoted_or_deactivated(world):
    async with world.api() as client:
        demote = await client.patch(f"/api/v1/users/{world.user.id}", json={"role": "admin"})
        deactivate = await client.patch(f"/api/v1/users/{world.user.id}", json={"is_active": False})
    assert demote.status_code == 409 and deactivate.status_code == 409

    second = await add_user(world, UserRole.OWNER)
    async with world.api() as client:
        assert (await client.patch(f"/api/v1/users/{second.id}", json={"role": "admin"})).json()["role"] == "admin"
        member = await add_user(world, UserRole.MEMBER)
        assert (await client.patch(f"/api/v1/users/{member.id}", json={"is_active": False})).json()["is_active"] is False
    assert len(await world.audit(AuditAction.USER_ROLE_CHANGED)) == 1
    assert len(await world.audit(AuditAction.USER_DEACTIVATED)) == 1


async def test_users_of_another_organization_are_invisible(world, make_tenant):
    _org, other_user, *_ = await make_tenant("Elsewhere")
    async with world.api() as client:
        assert (await client.patch(f"/api/v1/users/{other_user.id}", json={"role": "member"})).status_code == 404
        assert other_user.email not in {u["email"] for u in (await client.get("/api/v1/users")).json()}


# ---- task 033 -----------------------------------------------------------------------

async def oauth_callback(state: str, code: str = "auth-code"):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        return await client.get("/api/v1/google/callback", params={"code": code, "state": state}, follow_redirects=False)


async def test_oauth_state_lives_in_redis_and_is_single_use(world, fake_redis, monkeypatch):
    exchanged = []

    async def fake_exchange(code, code_verifier=None):
        exchanged.append(code_verifier)
        return {"access_token": "a", "refresh_token": "r"}

    async def fake_email(token):
        return "ads@acme-tests.io"

    monkeypatch.setattr(google_api, "exchange_code_for_tokens", fake_exchange)
    monkeypatch.setattr(google_api, "fetch_user_email", fake_email)

    async with world.api() as client:
        started = await client.post("/api/v1/google/connect")
    url = started.json()["authorization_url"]
    query = parse_qs(urlsplit(url).query)
    state = query["state"][0]
    assert "token=" not in url and query["code_challenge_method"] == ["S256"]
    assert f"oauth_state:{state}" in fake_redis.data and fake_redis.ttls[f"oauth_state:{state}"] == 600

    # Survives an API restart: nothing about it is in process memory.
    ok = await oauth_callback(state)
    assert ok.status_code == 302 and "success" in ok.headers["location"]
    assert exchanged and exchanged[0]  # PKCE verifier sent with the code
    replay = await oauth_callback(state)
    assert "error" in replay.headers["location"]

    async with world.sessionmaker() as db:
        connections = (await db.execute(select(GoogleConnection).where(GoogleConnection.google_account_email == "ads@acme-tests.io"))).scalars().all()
    assert [c.organization_id for c in connections] == [world.organization.id]
    assert {AuditAction.GOOGLE_CONNECT_STARTED, AuditAction.GOOGLE_CONNECT} <= {a.action for a in await world.audit()}


async def test_expired_or_unknown_state_is_rejected(world):
    response = await oauth_callback("expired-or-never-issued")
    assert response.status_code == 302 and "error" in response.headers["location"]


async def test_connect_refuses_without_redis(world, fake_redis):
    fake_redis.down = True
    async with world.api() as client:
        response = await client.post("/api/v1/google/connect")
    assert response.status_code == 503


async def test_old_get_connect_with_token_in_url_is_gone(world):
    async with world.api() as client:
        response = await client.get("/api/v1/google/connect", params={"token": "x"})
    assert response.status_code == 405


# ---- task 027 -----------------------------------------------------------------------

async def test_admin_area_requires_platform_admin(world):
    async with world.api() as client:  # an organization OWNER is not platform staff
        codes = {path: (await client.get(path)).status_code for path in (
            "/api/v1/admin/health", "/api/v1/admin/organizations", "/api/v1/admin/connections", "/api/v1/admin/audit-logs")}
    assert set(codes.values()) == {403}


async def test_platform_admin_sees_all_tenants_without_credentials(world, make_tenant):
    await make_tenant("Second")
    staff = await add_user(world, UserRole.MEMBER, platform_admin=True)
    async with world.api(staff) as client:
        orgs = (await client.get("/api/v1/admin/organizations")).json()
        connections = (await client.get("/api/v1/admin/connections"))
        users = (await client.get("/api/v1/admin/users")).json()
    assert len(orgs) == 2 and len(users) >= 3
    assert "refresh_token" not in connections.text and "encrypted" not in connections.text
    assert {c["customer_id"] for c in connections.json()} == {"1234567890"}


async def test_admin_retries_a_failed_action_with_audit(world):
    staff = await add_user(world, UserRole.MEMBER, platform_admin=True)
    session = await world.fraud_session("198.51.100.245")
    async with world.sessionmaker() as db:
        from app.services.protection_service import enqueue_exclusion_for_session

        result = await enqueue_exclusion_for_session(db, await db.get(type(session), session.id))
        [action] = result.actions
        action.status, action.last_error = ActionStatus.FAILED, "boom"
        result.exclusion.status = ExclusionStatus.FAILED
        await db.commit()
    async with world.api(staff) as client:
        failed = (await client.get("/api/v1/admin/actions")).json()
        retried = await client.post(f"/api/v1/admin/actions/{action.id}/retry")
    assert [a["id"] for a in failed] == [str(action.id)] and failed[0]["last_error"] == "boom"
    assert retried.status_code == 200 and retried.json()["status"] == "PENDING"
    [entry] = await world.audit(AuditAction.ADMIN_ACTION_RETRY)
    assert entry.user_id == staff.id and entry.details["previous_error"] == "boom"
    async with world.sessionmaker() as db:
        assert (await db.get(PlatformAction, action.id)).attempts == 0
    assert (await world.exclusions("198.51.100.245"))[0].status == ExclusionStatus.PENDING


async def test_global_rule_edit_is_versioned_and_audited(world):
    staff = await add_user(world, UserRole.MEMBER, platform_admin=True)
    async with world.api(staff) as client:
        response = await client.patch("/api/v1/admin/rules/DATACENTER_DETECTED", json={"weight": 14})
        await client.patch("/api/v1/admin/rules/DATACENTER_DETECTED", json={"weight": 12})  # restore the seed value
    assert response.json()["weight"] == 14 and response.json()["version"] == 2
    assert len(await world.audit(AuditAction.ADMIN_RULE_CHANGED)) == 2
    async with world.sessionmaker() as db:
        from app.models import Rule

        rule = await db.get(Rule, "DATACENTER_DETECTED")
        rule.version = 1  # keep the shared reference data as migrated
        await db.commit()


async def test_health_reports_redis_and_queue_down(world, fake_redis):
    staff = await add_user(world, UserRole.MEMBER, platform_admin=True)
    async with world.api(staff) as client:
        healthy = (await client.get("/api/v1/admin/health")).json()
        fake_redis.down = True
        down = (await client.get("/api/v1/admin/health")).json()
        live = await client.get("/health/live")
        ready = await client.get("/health/ready")
    names = {c["name"] for c in healthy["components"]}
    assert names == {"Database", "Redis", "Queue", "Tracking API", "Fraud Engine", "Google API", "ML Service"}
    by_name = {c["name"]: c["status"] for c in down["components"]}
    assert by_name["Redis"] == "DOWN" and by_name["Queue"] == "DOWN" and down["status"] == "DOWN"
    assert by_name["Database"] == "HEALTHY" and by_name["ML Service"] == "NOT_DEPLOYED"
    assert live.status_code == 200 and ready.status_code == 200  # the API stays up


async def test_health_queue_degraded_for_old_pending_actions(world, fake_redis):
    import time
    from datetime import datetime, timedelta, timezone

    staff = await add_user(world, UserRole.MEMBER, platform_admin=True)
    session = await world.fraud_session("198.51.100.246")
    async with world.sessionmaker() as db:
        from app.services.protection_service import enqueue_exclusion_for_session

        result = await enqueue_exclusion_for_session(db, await db.get(type(session), session.id))
        result.actions[0].scheduled_at = datetime.now(timezone.utc) - timedelta(hours=1)
        await db.commit()
    fake_redis.data["worker:heartbeat"] = str(time.time())
    async with world.api(staff) as client:
        queue = next(c for c in (await client.get("/api/v1/admin/health")).json()["components"] if c["name"] == "Queue")
    assert queue["status"] == "DEGRADED" and queue["metrics"]["oldest_due_action_seconds"] >= 3500


async def test_reauth_connection_shows_in_google_health(world):
    staff = await add_user(world, UserRole.MEMBER, platform_admin=True)
    async with world.sessionmaker() as db:
        connection = await db.get(GoogleConnection, world.connection.id)
        connection.needs_reauth = True
        await db.commit()
    async with world.api(staff) as client:
        google = next(c for c in (await client.get("/api/v1/admin/health")).json()["components"] if c["name"] == "Google API")
    assert google["status"] == "DEGRADED" and "1 connection needs re-auth" in google["detail"]

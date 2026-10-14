"""Tasks 015 (rules in the database), 016 (protection modes), 017 (FLAG), 020 (feedback → reputation)."""
from __future__ import annotations

import uuid

from sqlalchemy import select

from app.models import FraudEvent, IPReputation, ProtectionMode, Rule, Session, User, UserRole, Verdict
from app.services.audit_service import AuditAction
from app.services.protection_service import enqueue_exclusion_for_session
from app.services.rules import CATALOG
from tests.conftest import BOT_UA, World, create_tenant


async def other_world(world: World, name: str) -> World:
    async with world.sessionmaker() as db:
        org, user, website, connection, campaign = await create_tenant(db, name)
    return World(sessionmaker=world.sessionmaker, organization=org, user=user, website=website,
                 connection=connection, campaign=campaign, ip_intel=world.ip_intel)


async def reasons(world: World, ip: str) -> set[str]:
    session = (await world.sessions(ip))[-1]
    async with world.sessionmaker() as db:
        rows = await db.execute(
            select(FraudEvent.reason_code).where(FraudEvent.session_id == session.id, FraudEvent.triggered.is_(True))
        )
        return set(rows.scalars())


async def burst(world: World, ip: str, clicks: int, **kwargs) -> list[dict]:
    return [await world.visit(ip, visitor=f"v_{ip}", events=["page_view"], **kwargs) for _ in range(clicks)]


# ---- task 015 ------------------------------------------------------------------

async def test_migrations_seed_exactly_the_catalog(db):
    rows = {row.code: row for row in (await db.execute(select(Rule))).scalars()}
    assert set(rows) == {rule.code for rule in CATALOG}
    for rule in CATALOG:
        row = rows[rule.code]
        assert (row.name, row.category, row.weight, row.confidence, row.enabled, row.params) == (
            rule.name, rule.category.value, rule.weight, rule.confidence, rule.enabled, rule.params), rule.code


async def test_rule_results_record_category_and_rule_version(world):
    await world.visit("198.51.100.70", events=["page_view"], duration=0.5, user_agent=BOT_UA)
    session = (await world.sessions("198.51.100.70"))[-1]
    async with world.sessionmaker() as db:
        rows = (await db.execute(select(FraudEvent).where(FraudEvent.session_id == session.id))).scalars().all()
    by_code = {row.rule_name: row for row in rows}
    assert by_code["BOT_USER_AGENT_DETECTED"].category == "AUTOMATION"
    assert by_code["BOT_USER_AGENT_DETECTED"].rule_version == 1
    assert by_code["BOT_USER_AGENT_DETECTED"].rule_config["weight"] == 18
    assert session.scoring_version == 2 and session.risk_band in {"LOW", "MODERATE", "HIGH", "VERY_HIGH"}


async def test_org_override_changes_scoring_only_for_that_org(world):
    org_b = await other_world(world, "Beta")
    async with world.api() as client:
        response = await client.patch("/api/v1/rules/ABNORMAL_CLICK_VELOCITY", json={"params": {"clicks_60_seconds_gte": 5}})
    assert response.status_code == 200, response.text
    assert response.json()["params"]["clicks_60_seconds_gte"] == 5 and response.json()["override"]["version"] == 1

    await burst(world, "198.51.100.71", 6, duration=30.0)
    await burst(org_b, "198.51.100.72", 6, duration=30.0)
    assert "ABNORMAL_CLICK_VELOCITY" in await reasons(world, "198.51.100.71")
    assert "ABNORMAL_CLICK_VELOCITY" not in await reasons(org_b, "198.51.100.72")


async def test_disabling_a_rule_stops_it_and_is_audited(world):
    await world.visit("198.51.100.73", user_agent=BOT_UA)
    assert "BOT_USER_AGENT_DETECTED" in await reasons(world, "198.51.100.73")

    async with world.api() as client:
        response = await client.patch("/api/v1/rules/BOT_USER_AGENT_DETECTED", json={"enabled": False})
        assert response.status_code == 200 and response.json()["enabled"] is False
        listed = {rule["code"]: rule for rule in (await client.get("/api/v1/rules")).json()}
    assert listed["BOT_USER_AGENT_DETECTED"]["enabled"] is False
    assert listed["BOT_USER_AGENT_DETECTED"]["defaults"]["enabled"] is True
    assert len(listed) == len(CATALOG)

    await world.visit("198.51.100.74", user_agent=BOT_UA)
    assert "BOT_USER_AGENT_DETECTED" not in await reasons(world, "198.51.100.74")

    async with world.api() as client:
        reset = await client.delete("/api/v1/rules/BOT_USER_AGENT_DETECTED/override")
    assert reset.status_code == 200 and reset.json()["override"] is None and reset.json()["enabled"] is True

    changes = await world.audit(AuditAction.RULE_CHANGED)
    assert len(changes) == 2
    assert changes[0].details["before"]["enabled"] is True and changes[0].details["after"]["enabled"] is False
    assert changes[1].details["reset"] is True and changes[0].user_id == world.user.id


async def test_rule_changes_are_validated_and_admin_only(world):
    async with world.api() as client:
        bad = await client.patch("/api/v1/rules/ABNORMAL_CLICK_VELOCITY", json={"params": {"clicks_60_seconds_gte": 0}})
        unknown_param = await client.patch("/api/v1/rules/ABNORMAL_CLICK_VELOCITY", json={"params": {"nope": 1}})
        weight = await client.patch("/api/v1/rules/ABNORMAL_CLICK_VELOCITY", json={"weight": 101})
        unknown_rule = await client.patch("/api/v1/rules/NOT_A_RULE", json={"enabled": False})
    assert (bad.status_code, unknown_param.status_code, weight.status_code, unknown_rule.status_code) == (422, 422, 422, 404)

    async with world.sessionmaker() as db:
        member = User(organization_id=world.organization.id, email=f"member-{uuid.uuid4().hex[:6]}@acme-tests.io",
                      hashed_password="x", role=UserRole.MEMBER)
        db.add(member)
        await db.commit()
    async with world.api(member) as client:
        assert (await client.get("/api/v1/rules")).status_code == 200
        assert (await client.patch("/api/v1/rules/VPN_DETECTED", json={"weight": 0})).status_code == 403
        assert (await client.patch("/api/v1/organizations/me", json={"protection_mode": "aggressive"})).status_code == 403
    assert await world.audit(AuditAction.RULE_CHANGED) == []


# ---- task 016 ------------------------------------------------------------------

async def test_mode_change_via_api_is_audited_and_not_retroactive(world):
    await burst(world, "198.51.100.80", 1)
    async with world.api() as client:
        before = (await client.get("/api/v1/organizations/me")).json()
        response = await client.patch("/api/v1/organizations/me", json={"protection_mode": "conservative"})
    assert before["policy"]["mode"] == "balanced" and set(before["mode_defaults"]) == {"conservative", "balanced", "aggressive"}
    assert response.status_code == 200
    assert response.json()["policy"] == {"mode": "conservative", "flag_risk": 70, "fraud_risk": 90,
                                         "fraud_confidence": 90, "min_diversity": 3, "auto_exclude": True}
    [entry] = await world.audit(AuditAction.PROTECTION_MODE_CHANGED)
    assert entry.details["before"]["mode"] == "balanced" and entry.details["after"]["mode"] == "conservative"
    [old] = await world.sessions("198.51.100.80")
    assert old.scoring_version == 2  # untouched


async def test_custom_mode_rejects_diversity_below_two(world):
    async with world.api() as client:
        bad = await client.patch("/api/v1/organizations/me",
                                 json={"protection_mode": "custom", "protection_settings": {"min_diversity": 1}})
        ok = await client.patch("/api/v1/organizations/me",
                                json={"protection_mode": "custom", "protection_settings": {"fraud_risk": 75, "min_diversity": 2}})
    assert bad.status_code == 422
    assert ok.status_code == 200
    assert ok.json()["policy"]["fraud_risk"] == 75 and ok.json()["policy"]["min_diversity"] == 2
    assert ok.json()["protection_settings"]["flag_risk"] == 60  # completed from Balanced


async def set_mode(world: World, mode: ProtectionMode, settings: dict | None = None) -> None:
    async with world.sessionmaker() as db:
        org = await db.get(type(world.organization), world.organization.id)
        org.protection_mode = mode
        org.protection_settings = settings
        await db.commit()


async def test_aggressive_blocks_at_least_as_much_as_conservative_on_identical_traffic(world):
    aggressive = await other_world(world, "Aggro")
    await set_mode(world, ProtectionMode.CONSERVATIVE)
    await set_mode(aggressive, ProtectionMode.AGGRESSIVE)

    verdicts = {}
    for name, tenant in (("conservative", world), ("aggressive", aggressive)):
        results = []
        for i, ip in enumerate(["198.51.100.90", "198.51.100.91"]):
            world.ip_intel[ip] = {"is_datacenter": True, "country": "US"}  # world.ip_intel is shared
            results += await burst(tenant, ip, 8 if i == 0 else 5, duration=0.5, user_agent=BOT_UA)
        verdicts[name] = [r["verdict"] for r in results]
    fraud = {name: v.count("FRAUD") for name, v in verdicts.items()}
    assert fraud["aggressive"] > fraud["conservative"]
    for c, a in zip(verdicts["conservative"], verdicts["aggressive"]):
        if c == "FRAUD":
            assert a == "FRAUD"


async def test_exclusion_enqueue_respects_mode(world):
    await set_mode(world, ProtectionMode.CUSTOM, {"flag_risk": 60, "fraud_risk": 80, "fraud_confidence": 80,
                                                  "min_diversity": 3, "auto_exclude": False})
    world.ip_intel["198.51.100.95"] = {"is_datacenter": True, "country": "US"}
    await world.seed_history("198.51.100.95", Verdict.FRAUD, count=5, hours_ago=6)
    results = await burst(world, "198.51.100.95", 10, duration=0.5)
    assert results[-1]["verdict"] == "FRAUD"
    assert await world.exclusions("198.51.100.95") == [] and world.pushed_jobs == []


# ---- task 017 ------------------------------------------------------------------

async def test_flag_sessions_never_create_exclusions_and_form_the_review_queue(world):
    flagged = await world.fraud_session("198.51.100.96", risk=85, confidence=70)
    async with world.sessionmaker() as db:
        session = await db.get(Session, flagged.id)
        session.verdict = session.system_verdict = Verdict.FLAG
        await db.commit()
        result = await enqueue_exclusion_for_session(db, session)
    assert result.outcome == "not_actionable"
    assert await world.exclusions() == []

    await world.human("198.51.100.97")
    async with world.api() as client:
        queue = (await client.get("/api/v1/dashboard/sessions", params={"verdict": "FLAG"})).json()
        overview = (await client.get("/api/v1/dashboard/overview")).json()
    assert [s["id"] for s in queue] == [str(flagged.id)]
    assert queue[0]["verdict"] == "FLAG" and overview["review_sessions"] == 1


# ---- task 020 ------------------------------------------------------------------

async def counters(world: World, ip: str) -> tuple[int, int]:
    async with world.sessionmaker() as db:
        row = await db.get(IPReputation, (world.organization.id, ip))
        return row.fraud_sessions, row.legitimate_sessions


async def test_feedback_moves_session_between_reputation_counters(world):
    ip = "198.51.100.98"
    await world.human(ip)
    assert await counters(world, ip) == (0, 1)
    [session] = await world.sessions(ip)
    async with world.api() as client:
        r1 = await client.patch(f"/api/v1/dashboard/sessions/{session.id}/feedback", json={"client_verdict": "fraud"})
        assert r1.status_code == 200
        assert await counters(world, ip) == (1, 0)
        await client.patch(f"/api/v1/dashboard/sessions/{session.id}/feedback", json={"client_verdict": "fraud"})
        assert await counters(world, ip) == (1, 0)  # same label again: no change
        await client.patch(f"/api/v1/dashboard/sessions/{session.id}/feedback", json={"client_verdict": "legitimate"})
    assert await counters(world, ip) == (0, 1)


async def test_marking_sessions_legitimate_stops_high_fraud_history(world):
    ip = "198.51.100.99"
    await world.seed_history(ip, Verdict.FRAUD, count=6, hours_ago=5)
    await world.seed_history(ip, Verdict.SAFE, count=2, hours_ago=8)
    await world.visit(ip, events=["page_view"], duration=40.0)
    assert "HIGH_FRAUD_HISTORY" in await reasons(world, ip)

    frauds = [s for s in await world.sessions(ip) if s.verdict == Verdict.FRAUD][:5]
    async with world.api() as client:
        for s in frauds:
            assert (await client.patch(f"/api/v1/dashboard/sessions/{s.id}/feedback",
                                       json={"client_verdict": "legitimate"})).status_code == 200
    await world.visit(ip, events=["page_view"], duration=40.0)
    assert "HIGH_FRAUD_HISTORY" not in await reasons(world, ip)

"""Tasks 025 (overview, breakdowns, organization timezone) and 026 (campaigns, session detail)."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from sqlalchemy import select

from app.models import (
    AuditLog,
    AuditResult,
    Exclusion,
    ExclusionStatus,
    GoogleCampaign,
    Organization,
    Session,
    Verdict,
)
from app.services.analytics_service import GROUP_BY_VALUES
from tests.conftest import CAMPAIGN_ID


async def seed(world, rows: list[dict]) -> list[Session]:
    now = datetime.now(timezone.utc)
    out = []
    async with world.sessionmaker() as db:
        for i, row in enumerate(rows):
            verdict = row.pop("verdict", Verdict.SAFE)
            created = row.pop("created_at", now - timedelta(minutes=5 + i))
            session = Session(organization_id=world.organization.id, website_id=world.website.id,
                              session_token=f"s_rep_{uuid.uuid4().hex[:10]}", verdict=verdict, system_verdict=verdict,
                              created_at=created, risk_score=row.pop("risk_score", 90 if verdict == Verdict.FRAUD else 10),
                              **row)
            db.add(session)
            out.append(session)
        await db.commit()
    return out


async def breakdown(world, group_by: str, **params) -> list[dict]:
    async with world.api() as client:
        response = await client.get("/api/v1/analytics/fraud", params={"group_by": group_by, "range": "7d", **params})
    assert response.status_code == 200, response.text
    return response.json()["rows"]


async def test_breakdowns_match_the_seed_for_every_dimension(world, make_tenant):
    async with world.sessionmaker() as db:
        second = GoogleCampaign(connection_id=world.connection.id, campaign_id="777", name="Drain Cleaning")
        db.add(second)
        await db.commit()
    now = datetime.now(timezone.utc)
    await seed(world, [
        {"country": "US", "google_campaign_id": world.campaign.id, "ad_landing_at": now, "gclid": "g1", "device": "mobile"},
        {"country": "US", "google_campaign_id": world.campaign.id, "ad_landing_at": now, "verdict": Verdict.FRAUD, "device": "desktop"},
        {"country": "DE", "google_campaign_id": second.id, "ad_landing_at": now, "verdict": Verdict.FRAUD, "device": "desktop"},
        {"country": "FR", "referrer": "https://news.test/", "verdict": Verdict.MONITOR, "device": "mobile"},
    ])
    _org, other_user, other_site, *_ = await make_tenant("Noise")
    async with world.sessionmaker() as db:  # another tenant's traffic must never show up
        db.add(Session(organization_id=_org.id, website_id=other_site.id, session_token="s_noise_000001",
                       country="US", verdict=Verdict.FRAUD, system_verdict=Verdict.FRAUD))
        await db.commit()

    countries = {r["key"]: r for r in await breakdown(world, "country")}
    assert {k: (r["sessions"], r["fraud"]) for k, r in countries.items()} == {"US": (2, 1), "DE": (1, 1), "FR": (1, 0)}
    assert countries["US"]["fraud_rate"] == 0.5 and countries["FR"]["suspicious"] == 1
    campaigns = {r["label"]: r["sessions"] for r in await breakdown(world, "campaign")}
    assert campaigns == {"Emergency Plumbing": 2, "Drain Cleaning": 1, "Not matched to a campaign": 1}
    assert {r["key"]: r["sessions"] for r in await breakdown(world, "source")} == {"paid": 3, "organic": 1}
    assert {r["key"]: r["sessions"] for r in await breakdown(world, "device")} == {"desktop": 2, "mobile": 2}
    for group_by in GROUP_BY_VALUES:  # every dimension answers, tenant-scoped
        rows = await breakdown(world, group_by)
        assert sum(r["sessions"] for r in rows) == 4, group_by


async def test_day_and_today_use_the_organization_timezone(world):
    async with world.sessionmaker() as db:
        org = await db.get(Organization, world.organization.id)
        org.timezone = "America/Chicago"
        await db.commit()
    chicago = ZoneInfo("America/Chicago")
    yesterday_local = datetime.now(chicago).date() - timedelta(days=1)
    late_evening = datetime.combine(yesterday_local, datetime.min.time(), tzinfo=chicago) + timedelta(hours=23, minutes=30)
    await seed(world, [{"created_at": late_evening.astimezone(timezone.utc)}, {}])
    days = {r["key"]: r["sessions"] for r in await breakdown(world, "day")}
    assert days.get(yesterday_local.isoformat()) == 1  # 05:30 UTC the next day, still "yesterday" in Chicago
    async with world.api() as client:
        today = (await client.get("/api/v1/dashboard/overview", params={"range": "today"})).json()
    assert today["timezone"] == "America/Chicago" and today["total_sessions"] == 1


async def test_feedback_moves_a_session_out_of_the_fraud_count(world):
    [fraud] = await seed(world, [{"verdict": Verdict.FRAUD, "country": "US"}])
    assert (await breakdown(world, "country"))[0]["fraud"] == 1
    async with world.api() as client:
        await client.patch(f"/api/v1/dashboard/sessions/{fraud.id}/feedback", json={"client_verdict": "legitimate"})
    row = (await breakdown(world, "country"))[0]
    assert row["fraud"] == 0 and row["suspicious"] == 0


async def test_overview_has_every_main_dashboard_metric(world):
    now = datetime.now(timezone.utc)
    await seed(world, [{"ad_landing_at": now, "verdict": Verdict.FRAUD}, {"ad_landing_at": now}, {}])
    async with world.api() as client:
        overview = (await client.get("/api/v1/dashboard/overview")).json()
    assert overview["protection_status"] == "ACTIVE" and overview["protection_missing"] == []
    assert overview["clicks"] == 2 and overview["total_sessions"] == 3 and overview["fraud_sessions"] == 1
    assert overview["fraud_rate"] == round(1 / 3, 4)
    assert overview["connected_websites"] == 1 and overview["protected_campaigns"] == 1
    assert overview["connected_google_accounts"] == 1
    for field in ("suspicious_sessions", "protected_ips", "average_risk_score", "high_confidence_traffic"):
        assert field in overview

    async with world.api() as client:
        await client.patch(f"/api/v1/google/campaigns/{world.campaign.id}/protection", json={"protection_enabled": False})
        setup = (await client.get("/api/v1/dashboard/overview")).json()
    assert setup["protection_status"] == "SETUP_REQUIRED" and setup["protection_missing"] == ["protected_campaign"]


# ---- task 026 ---------------------------------------------------------------------

async def test_campaign_stats_with_fraud_rate_and_trend(world):
    now = datetime.now(timezone.utc)
    rows = [{"google_campaign_id": world.campaign.id, "ad_landing_at": now} for _ in range(8)]
    rows += [{"google_campaign_id": world.campaign.id, "ad_landing_at": now, "verdict": Verdict.FRAUD} for _ in range(2)]
    await seed(world, rows)
    async with world.api() as client:
        [campaign] = (await client.get("/api/v1/campaigns")).json()
        detail = (await client.get(f"/api/v1/campaigns/{world.campaign.id}")).json()
    assert campaign["sessions"] == 10 and campaign["fraud"] == 2 and campaign["fraud_rate"] == 0.2
    assert len(campaign["trend"]) == 14 and campaign["trend"][-1]["sessions"] == 10
    assert campaign["exclusion_limit"] > 0
    assert len(detail["recent_fraud_sessions"]) == 2 and detail["exclusions"] == []


async def test_session_detail_explains_the_decision_with_exclusion_history(world):
    ip = "203.0.113.150"
    world.ip_intel[ip] = {"is_datacenter": True, "country": "US", "city": "Dallas", "asn": "AS1", "isp": "Hosting"}
    await world.seed_history(ip, Verdict.FRAUD, count=5, hours_ago=6)
    for _ in range(10):
        last = await world.visit(ip, visitor="v_detail_bot", events=["page_view"], duration=0.5)
    assert last["verdict"] == "FRAUD"
    async with world.sessionmaker() as db:
        exclusion = (await db.execute(select(Exclusion).where(Exclusion.ip_address == ip))).scalar_one()
        exclusion.status, exclusion.api_request_id = ExclusionStatus.ACTIVE, "req-777"
        db.add(AuditLog(organization_id=world.organization.id, action="ADD_IP_EXCLUSION", result=AuditResult.SUCCESS,
                        resource_type="exclusion", resource_id=str(exclusion.id), google_request_id="req-777"))
        await db.commit()

    async with world.api() as client:
        detail = (await client.get(f"/api/v1/dashboard/sessions/{last['session_id']}")).json()
    assert detail["verdict"] == "FRAUD" and detail["source"] == "paid"
    assert detail["campaign_id"] == CAMPAIGN_ID and detail["city"] == "Dallas" and detail["is_datacenter"]
    assert detail["explanation"].startswith(f"Fraud Risk: {detail['risk_score']}/100 · Reasons: ")
    codes = [r["code"] for r in detail["reasons"]]
    assert len(codes) == len(set(codes)) and "DATACENTER_DETECTED" in codes
    assert detail["signal_diversity"] >= 3 and detail["clicks"]["clicks_60_seconds"] >= 8
    assert detail["ad_group_id"] is None and detail["keyword"] is None  # "not available" in the UI
    [excl] = detail["exclusions"]
    assert excl["status"] == "ACTIVE" and excl["api_request_id"] == "req-777"
    assert [t["action"] for t in excl["timeline"]] == ["EXCLUSION_QUEUED", "ADD_IP_EXCLUSION"]
    assert excl["timeline"][-1]["google_request_id"] == "req-777"
    assert detail["events"] and {e["event_type"] for e in detail["events"]} == {"ad_landing", "page_view"}


async def test_detail_and_campaigns_are_tenant_scoped(world, make_tenant):
    [mine] = await seed(world, [{}])
    other_org, other_user, *_rest = await make_tenant("Rival")
    other_campaign = _rest[-1]
    async with world.api(other_user) as client:
        assert (await client.get(f"/api/v1/dashboard/sessions/{mine.id}")).status_code == 404
        assert (await client.get(f"/api/v1/campaigns/{world.campaign.id}")).status_code == 404
        assert [c["id"] for c in (await client.get("/api/v1/campaigns")).json()] == [str(other_campaign.id)]

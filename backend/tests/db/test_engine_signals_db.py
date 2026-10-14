"""Tasks 018 (geo targeting sync + rule), 019 (repeat visitors), 021 (timing), 022 (anomaly job) end to end."""
from __future__ import annotations

import time
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update

from app.api import google as google_api
from app.models import (
    CampaignTrafficStat,
    FraudEvent,
    GoogleCampaignLocation,
    Session,
    TrafficAnomaly,
    Verdict,
)
from app.services.anomaly_service import build_stats_upsert, hour_floor, run_anomaly_detection
from app.services.audit_service import AuditAction
from tests.conftest import CAMPAIGN_ID, World


async def reasons(world: World, ip: str) -> dict[str, FraudEvent]:
    session = (await world.sessions(ip))[-1]
    async with world.sessionmaker() as db:
        rows = await db.execute(
            select(FraudEvent).where(FraudEvent.session_id == session.id, FraudEvent.triggered.is_(True))
        )
        return {row.reason_code: row for row in rows.scalars()}


async def shift_back(world: World, *, minutes: float, ip: str | None = None) -> None:
    """Move existing paid sessions into the past (so new visits don't trip 60-second velocity)."""
    async with world.sessionmaker() as db:
        stmt = update(Session).where(Session.ad_landing_at.is_not(None))
        if ip is not None:
            stmt = stmt.where(Session.ip_address == ip)
        await db.execute(stmt.values(
            ad_landing_at=Session.ad_landing_at - timedelta(minutes=minutes),
            created_at=Session.created_at - timedelta(minutes=minutes),
        ))
        await db.commit()


# ---- task 018 ------------------------------------------------------------------

async def test_campaign_sync_stores_location_targets_and_geo_rule_uses_them(world, monkeypatch):
    async def fake_refresh(token):
        return {"access_token": "access-token"}

    async def fake_campaigns(**kwargs):
        return [{"campaign_id": CAMPAIGN_ID, "name": "Emergency Plumbing", "campaign_type": "SEARCH",
                 "status": "ENABLED", "supports_ip_exclusion": True, "geo_target_type": "PRESENCE"}]

    async def fake_counts(**kwargs):
        return {}

    async def fake_locations(**kwargs):
        return {CAMPAIGN_ID: [
            {"criterion_id": "2840", "criterion_type": "LOCATION", "negative": False,
             "geo_target_constant": "geoTargetConstants/2840", "country_code": "US", "region": None,
             "name": "United States", "target_type": "Country"},
            {"criterion_id": "2643", "criterion_type": "LOCATION", "negative": True,
             "geo_target_constant": "geoTargetConstants/2643", "country_code": "RU", "region": None,
             "name": "Russia", "target_type": "Country"},
        ]}

    monkeypatch.setattr(google_api, "refresh_access_token", fake_refresh)
    monkeypatch.setattr(google_api, "list_google_campaigns", fake_campaigns)
    monkeypatch.setattr(google_api, "count_ip_exclusions_by_campaign", fake_counts)
    monkeypatch.setattr(google_api, "list_campaign_locations", fake_locations)

    async with world.api() as client:
        assert (await client.post("/api/v1/google/campaigns/sync")).status_code == 200
        assert (await client.post("/api/v1/google/campaigns/sync")).status_code == 200  # replaces, never duplicates
        [campaign] = (await client.get("/api/v1/google/campaigns")).json()
    assert campaign["geo_target_type"] == "PRESENCE"
    assert {(loc["country_code"], loc["negative"]) for loc in campaign["locations"]} == {("US", False), ("RU", True)}
    async with world.sessionmaker() as db:
        assert len((await db.execute(select(GoogleCampaignLocation))).scalars().all()) == 2

    world.ip_intel["198.51.100.120"] = {"country": "US", "region": "Texas"}
    world.ip_intel["198.51.100.121"] = {"country": "DE", "region": "Berlin"}
    await world.human("198.51.100.120")
    await world.human("198.51.100.121")
    assert "GEO_ANOMALY" not in await reasons(world, "198.51.100.120")
    geo = (await reasons(world, "198.51.100.121"))["GEO_ANOMALY"]
    assert geo.score_contribution == 15 and geo.category == "GEO"
    [de_session] = await world.sessions("198.51.100.121")
    assert de_session.verdict != Verdict.FRAUD  # geo alone never blocks


async def test_timezone_mismatch_fires_from_tracked_timezone(world):
    world.ip_intel["198.51.100.122"] = {"country": "US"}
    await world.human("198.51.100.122", timezone_name="Asia/Karachi")
    assert "GEO_TIMEZONE_MISMATCH" in await reasons(world, "198.51.100.122")


# ---- task 019 ------------------------------------------------------------------

async def test_same_visitor_four_clicks_in_six_hours_is_a_repeated_visitor(world):
    ip = "198.51.100.130"
    for _ in range(3):
        await world.human(ip, visitor="v_returning")
        await shift_back(world, minutes=120)
    await world.human(ip, visitor="v_returning")
    found = await reasons(world, ip)
    assert "REPEATED_VISITOR" in found and "ABNORMAL_CLICK_VELOCITY" not in found
    session = (await world.sessions(ip))[-1]
    assert session.extra_signals["repeat_visitor"]["visitor_campaign"]["short"] == 4


async def test_many_visitors_behind_one_ip_are_not_repeat_visitors(world):
    ip = "198.51.100.131"
    for i in range(20):
        await world.human(ip, duration=60.0 + 7 * i)
        await shift_back(world, minutes=10, ip=ip)   # spread over a few hours, 1 click each
    hit = (await reasons(world, ip)).get("REPEATED_VISITOR")
    assert hit is None or hit.score_contribution <= 4
    assert (await world.sessions(ip))[-1].extra_signals["repeat_visitor"]["ip_shared"] is True


async def test_same_device_from_five_ips_within_an_hour_is_a_rotating_proxy(world):
    for i in range(5):
        await world.visit(f"198.51.100.{140 + i}", events=["page_view"], duration=20.0,
                          screen=(1366, 768), timezone_name="America/Chicago")
        await shift_back(world, minutes=5)
    found = await reasons(world, "198.51.100.144")
    assert "REPEATED_VISITOR" in found and "device profile across 5 IPs" in found["REPEATED_VISITOR"].reason_text
    keys = {s.device_key for i in range(5) for s in await world.sessions(f"198.51.100.{140 + i}")}
    assert len(keys) == 1 and len(next(iter(keys))) == 64


async def test_organic_returns_are_not_paid_repeats(world):
    ip = "198.51.100.150"
    for _ in range(4):
        await world.human(ip, visitor="v_organic", paid=False)
    await world.human(ip, visitor="v_organic")
    session = (await world.sessions(ip))[-1]
    assert session.extra_signals["repeat_visitor"]["visitor_campaign"]["short"] == 1
    assert "REPEATED_VISITOR" not in await reasons(world, ip)


async def test_scoring_stays_fast(world):
    ip = "198.51.100.151"
    for _ in range(5):
        await world.visit(ip, events=["page_view"], duration=5.0)
    from app.core.metrics import scoring_latency

    scoring_latency.samples.clear()
    started = time.perf_counter()
    await world.visit(ip, events=["page_view", "click", "scroll"], duration=5.0)
    # Spec §61: scoring within 500 ms (engine time, measured by the engine itself, task 027).
    assert scoring_latency.snapshot()["p95_ms"] < 500
    # The whole request in the test setup (a new DB connection per request): a loose bound.
    assert time.perf_counter() - started < 1.5


# ---- task 021 ------------------------------------------------------------------

async def test_interaction_timing_stats_are_stored_and_rule_fires(world):
    ip = "198.51.100.160"
    await world.visit(ip, events=["page_view"] + ["click"] * 20, duration=0.42)  # 20 clicks ~20 ms apart
    [session] = await world.sessions(ip)
    assert session.event_interval_min_ms is not None and session.event_interval_min_ms < 50
    assert session.extra_signals["event_intervals"]["events"] == 20
    assert "IMPOSSIBLE_INTERACTION_TIMING" in await reasons(world, ip)

    await world.human("198.51.100.161")
    assert "IMPOSSIBLE_INTERACTION_TIMING" not in await reasons(world, "198.51.100.161")


async def test_machine_regular_ad_clicks_are_detected_from_landing_history(world):
    ip, visitor = "198.51.100.170", "v_metronome"
    await world.human(ip, visitor=visitor)
    [first] = await world.sessions(ip)
    now = datetime.now(timezone.utc)
    async with world.sessionmaker() as db:
        for k in range(5, 0, -1):  # 5 earlier clicks exactly 10.0 s apart
            db.add(Session(organization_id=world.organization.id, website_id=world.website.id,
                           visitor_id=first.visitor_id, session_token=f"s_metro_{k}_{uuid.uuid4().hex[:6]}",
                           ip_address=ip, gclid=f"g_{k}_{uuid.uuid4().hex[:6]}", google_campaign_id=world.campaign.id,
                           ad_landing_at=now - timedelta(seconds=10 * k), verdict=Verdict.SAFE,
                           system_verdict=Verdict.SAFE, created_at=now - timedelta(seconds=10 * k)))
        await db.execute(update(Session).where(Session.id == first.id)
                         .values(ad_landing_at=now - timedelta(seconds=60), created_at=now - timedelta(seconds=60)))
        await db.commit()
    await world.human(ip, visitor=visitor)
    session = (await world.sessions(ip))[-1]
    assert session.ad_click_interval_cv is not None and session.ad_click_interval_cv < 0.15
    assert 9.5 < session.ad_click_interval_avg_s < 10.5
    assert "ABNORMAL_CLICK_TIMING" in await reasons(world, ip)


# ---- task 022 ------------------------------------------------------------------

async def test_anomaly_job_detects_a_spike_and_flags_sessions_during_it(world):
    now = datetime.now(timezone.utc)
    current = hour_floor(now)
    spike_hour = current - timedelta(hours=1)
    # 14 days at ~4 landings / hour …
    rows = [
        {"google_campaign_id": world.campaign.id, "organization_id": world.organization.id,
         "hour_bucket": spike_hour - timedelta(hours=h), "ad_landings": 3 + (h % 3), "distinct_ips": 3,
         "distinct_visitors": 3, "fraud_sessions": 0, "median_click_interval_s": 900.0}
        for h in range(1, 14 * 24 + 1)
    ]
    async with world.sessionmaker() as db:
        await db.execute(build_stats_upsert(rows))
        # … then 80 paid landings in one hour, from many IPs.
        for i in range(80):
            landed = spike_hour + timedelta(seconds=40 * i)
            db.add(Session(organization_id=world.organization.id, website_id=world.website.id,
                           session_token=f"s_spike_{i}_{uuid.uuid4().hex[:6]}", ip_address=f"10.99.{i // 250}.{i % 250 + 1}",
                           google_campaign_id=world.campaign.id, ad_landing_at=landed, created_at=landed,
                           verdict=Verdict.SAFE, system_verdict=Verdict.SAFE))
        await db.commit()

    async with world.sessionmaker() as db:
        metrics = await run_anomaly_detection(db, now)
    assert metrics["alerts"] >= 1
    async with world.sessionmaker() as db:
        stat = await db.get(CampaignTrafficStat, (world.campaign.id, spike_hour))
        anomalies = (await db.execute(select(TrafficAnomaly))).scalars().all()
    assert stat.ad_landings == 80 and stat.distinct_ips == 80 and abs(stat.median_click_interval_s - 40) < 1
    spike = next(a for a in anomalies if a.metric == "ad_landings")
    assert spike.level == "HIGH" and spike.window_start == spike_hour and spike.observed == 80
    # Volume spike and clicks much closer together than the usual 15 minutes: two HIGH alerts.
    alerts = await world.audit(AuditAction.TRAFFIC_ANOMALY_DETECTED)
    assert {a.details["metric"] for a in alerts} == {"ad_landings", "median_click_interval"}
    assert all(a.details["fraud_signal"] for a in alerts)

    # Running again doesn't duplicate rows or alerts.
    async with world.sessionmaker() as db:
        await run_anomaly_detection(db, now)
    assert len(await world.audit(AuditAction.TRAFFIC_ANOMALY_DETECTED)) == 2

    # A click landing now (within the grace period) gets the context rule — and it alone isn't FRAUD.
    result = await world.human("198.51.100.180")
    assert "TRAFFIC_ANOMALY" in await reasons(world, "198.51.100.180")
    assert result["verdict"] == "SAFE"

    async with world.api() as client:
        listed = (await client.get("/api/v1/dashboard/anomalies")).json()
    assert any(a["metric"] == "ad_landings" and a["level"] == "HIGH" for a in listed)


async def test_anomaly_job_skips_new_campaigns(world):
    await world.human("198.51.100.190")
    now = datetime.now(timezone.utc)
    async with world.sessionmaker() as db:
        metrics = await run_anomaly_detection(db, now)
        anomalies = (await db.execute(select(TrafficAnomaly))).scalars().all()
        stats = (await db.execute(select(CampaignTrafficStat))).scalars().all()
    assert anomalies == [] and metrics["cold_start"] >= 1
    assert sum(s.ad_landings for s in stats) == 1

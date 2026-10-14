"""Tasks 018 (geo), 019 (repeat visitor, device key), 021 (interval statistics), 022 (anomaly statistics)."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.models import Session, Verdict
from app.services.anomaly_service import HourStat, detect_hour, robust_baseline, robust_z
from app.services.features import device_key, interval_stats, repeat_counts_from_row
from app.services.geo import GeoTarget, match_campaign_geo, timezone_countries
from app.services.rules import FeatureContext, evaluate
from app.services.rules.repository import catalog_configs
from app.services.scoring import aggregate
from app.services.protection_policy import decide, get_policy


def session(**overrides) -> Session:
    fields = dict(
        id=uuid.uuid4(), organization_id=uuid.uuid4(), website_id=uuid.uuid4(), session_token="s_test_0001",
        ip_address="203.0.113.9", page_count=3, click_count=2, interaction_count=4, scroll_depth=60.0,
        session_duration_seconds=90.0, clicks_10_seconds=1, clicks_30_seconds=1, clicks_60_seconds=1,
        clicks_5_minutes=1, clicks_1_hour=1, clicks_24_hours=1, is_vpn=False, is_proxy=False, is_tor=False,
        is_datacenter=False, country="US", verdict=Verdict.SAFE, system_verdict=Verdict.SAFE,
    )
    fields.update(overrides)
    return Session(**fields)


def fired(ctx: FeatureContext) -> dict:
    return {result.code: result for result in evaluate(ctx, catalog_configs())}


# ---- task 018: geo ------------------------------------------------------------

US = GeoTarget(country_code="US", region=None, name="United States", target_type="Country")
DALLAS = GeoTarget(country_code="US", region="Texas", name="Dallas", target_type="City")


def test_geo_target_in_country_is_normal():
    assert match_campaign_geo([US], country="US") is None
    assert "GEO_ANOMALY" not in fired(FeatureContext(session=session(country="US"), geo_targets=[US]))


def test_geo_traffic_from_untargeted_country_fires_with_configured_weight():
    hit = fired(FeatureContext(session=session(country="DE"), geo_targets=[US], geo_target_type="PRESENCE"))["GEO_ANOMALY"]
    assert hit.score == 15 and hit.category == "GEO"


def test_geo_presence_or_interest_lowers_the_weight():
    hit = fired(FeatureContext(session=session(country="DE"), geo_targets=[US],
                               geo_target_type="PRESENCE_OR_INTEREST"))["GEO_ANOMALY"]
    assert 0 < hit.score < 15


def test_geo_region_mismatch_inside_the_country_counts_less():
    match = match_campaign_geo([DALLAS], country="US", region="California")
    assert match is not None and match.kind == "outside_regions"
    assert match_campaign_geo([DALLAS], country="US", region="Texas") is None  # §18 Dallas → normal
    assert match_campaign_geo([DALLAS], country="US", region=None) is None     # IP data too coarse
    hit = fired(FeatureContext(session=session(country="US", region="California"), geo_targets=[DALLAS],
                               geo_target_type="PRESENCE"))["GEO_ANOMALY"]
    assert hit.score < 15


def test_geo_excluded_location_fires():
    excluded = GeoTarget(country_code="RU", region=None, name="Russia", target_type="Country", negative=True)
    assert match_campaign_geo([US, excluded], country="RU").kind == "excluded_location"


def test_geo_rule_skipped_without_targets_or_country():
    assert "GEO_ANOMALY" not in fired(FeatureContext(session=session(country="DE"), geo_targets=[]))
    assert "GEO_ANOMALY" not in fired(FeatureContext(session=session(country=None), geo_targets=[US]))


def test_geo_mismatch_alone_is_never_fraud():
    s = session(country="DE", timezone="Asia/Karachi")
    agg = aggregate(evaluate(FeatureContext(session=s, geo_targets=[DALLAS], geo_target_type="PRESENCE"),
                             catalog_configs()), s)
    assert agg.diversity <= 1 and decide(agg.risk, agg.evidence_confidence, agg.diversity, get_policy(None)).value != "FRAUD"


def test_timezone_mismatch():
    assert timezone_countries("Asia/Karachi") == frozenset({"PK"})
    assert timezone_countries("UTC") is None
    assert "GEO_TIMEZONE_MISMATCH" in fired(FeatureContext(session=session(country="US", timezone="Asia/Karachi")))
    assert "GEO_TIMEZONE_MISMATCH" not in fired(FeatureContext(session=session(country="US", timezone="America/Chicago")))
    assert "GEO_TIMEZONE_MISMATCH" not in fired(FeatureContext(session=session(country="US", timezone=None)))


# ---- task 019: repeat visitor / device key --------------------------------------

def repeat(**counts) -> dict:
    base = {
        "visitor_campaign": {"short": 1, "long": 1}, "ip_campaign": {"short": 1, "long": 1},
        "ip_landing": {"short": 1, "long": 1}, "device_campaign": 1, "device_distinct_ips": 1,
        "ip_distinct_visitors": 1, "ip_shared": False, "windows_hours": {"short": 24, "long": 168},
        "device_window_minutes": 60,
    }
    base.update(counts)
    return base


def repeated_visitor(signals: dict):
    return fired(FeatureContext(session=session(extra_signals={"repeat_visitor": signals}))).get("REPEATED_VISITOR")


def test_same_visitor_repeatedly_clicking_a_campaign_fires():
    hit = repeated_visitor(repeat(visitor_campaign={"short": 4, "long": 4}))
    assert hit is not None and hit.category == "VELOCITY"
    assert repeated_visitor(repeat()) is None


def test_contribution_grows_with_the_count_with_diminishing_returns():
    # threshold 3, then each count doubled: every doubling adds less than the one before
    scores = [repeated_visitor(repeat(visitor_campaign={"short": n, "long": n})).score for n in (3, 6, 12, 24)]
    assert scores == sorted(scores) and scores[-1] <= 20
    gains = [b - a for a, b in zip(scores, scores[1:])]
    assert gains == sorted(gains, reverse=True) and gains[0] > gains[-1]


def test_shared_ip_with_many_visitors_gets_minimal_weight():
    shared = repeated_visitor(repeat(ip_campaign={"short": 20, "long": 20}, ip_distinct_visitors=20, ip_shared=True))
    alone = repeated_visitor(repeat(ip_campaign={"short": 20, "long": 20}))
    assert shared is None or shared.score <= 4
    assert alone.score >= 15


def test_rotating_proxy_pattern_fires_on_device_key():
    hit = repeated_visitor(repeat(device_campaign=5, device_distinct_ips=5))
    assert hit is not None and "device profile" in hit.description
    # The same count from one IP is not the rotating-proxy pattern.
    assert repeated_visitor(repeat(device_campaign=5, device_distinct_ips=1)) is None


def test_common_device_profile_at_its_usual_volume_is_not_a_rotating_proxy():
    # A popular phone/timezone/language profile: ~3 landings per hour on the campaign all week.
    assert repeated_visitor(repeat(device_campaign=5, device_distinct_ips=5, device_campaign_usual=3.0)) is None
    burst = repeated_visitor(repeat(device_campaign=15, device_distinct_ips=15, device_campaign_usual=3.0))
    assert burst is not None


def test_device_key_is_a_salted_per_org_hash_without_raw_values():
    org_a, org_b = uuid.uuid4(), uuid.uuid4()
    traits = dict(browser="Chrome", os="Windows", device="desktop", screen_width=1920, screen_height=1080,
                  timezone_name="America/Chicago", language="en-US")
    key = device_key(org_a, **traits)
    assert len(key) == 64 and all(c in "0123456789abcdef" for c in key)
    assert key == device_key(org_a, **traits)
    assert key != device_key(org_b, **traits)          # not joinable across tenants
    assert key != device_key(org_a, **{**traits, "screen_width": 1366})
    for value in ("Chrome", "Windows", "1920", "America/Chicago", "en-us"):
        assert value.casefold() not in key
    assert device_key(org_a, browser=None, os=None, device=None) is None


def test_repeat_counts_mark_shared_ips():
    row = type("Row", (), {"_mapping": {
        "visitor_campaign_short": 1, "visitor_campaign_long": 1, "ip_campaign_short": 20, "ip_campaign_long": 20,
        "ip_landing_short": 20, "ip_landing_long": 20, "device_campaign": 3, "device_distinct_ips": 1,
        "ip_distinct_visitors": 20,
    }})()
    counts = repeat_counts_from_row(row)
    assert counts["ip_shared"] is True and counts["ip_campaign"] == {"short": 20, "long": 20}


# ---- task 021: interval statistics --------------------------------------------

@pytest.mark.parametrize("values", [[], [1.0], [1.0, 2.0], [1.0, 2.0, 3.0]])
def test_interval_stats_need_enough_samples(values):
    assert interval_stats(values) is None  # fewer than 3 intervals


def test_interval_stats_values():
    stats = interval_stats([0, 10, 20, 30, 40, 50])
    assert stats.count == 5 and stats.mean == 10 and stats.minimum == 10 and stats.variance == 0 and stats.cv == 0
    irregular = interval_stats([0, 30, 50, 140, 160, 260])
    assert irregular.minimum == 20 and irregular.cv > 0.5
    assert interval_stats([30, 0, 10, 20]).minimum == 10  # out of order input is sorted


def timing(**columns):
    return fired(FeatureContext(session=session(**columns)))


def test_machine_regular_ad_clicks_fire():
    stats = interval_stats([0, 10, 20, 30, 40, 50])  # 6 landings exactly 10.0 s apart
    hit = timing(ad_click_interval_avg_s=stats.mean, ad_click_interval_min_s=stats.minimum,
                 ad_click_interval_cv=stats.cv, extra_signals={"ad_click_intervals": {"landings": 6}})
    assert "ABNORMAL_CLICK_TIMING" in hit


def test_human_like_ad_click_intervals_do_not_fire():
    stats = interval_stats([0, 45, 160, 190, 420, 600])
    hits = timing(ad_click_interval_avg_s=stats.mean, ad_click_interval_min_s=stats.minimum,
                  ad_click_interval_cv=stats.cv, extra_signals={"ad_click_intervals": {"landings": 6}})
    assert "ABNORMAL_CLICK_TIMING" not in hits


def test_spec_31_sub_second_clicks_fire():
    stats = interval_stats([0, 0.2, 1.0, 1.4, 2.4])
    hits = timing(ad_click_interval_avg_s=stats.mean, ad_click_interval_min_s=stats.minimum,
                  ad_click_interval_cv=stats.cv, extra_signals={"ad_click_intervals": {"landings": 5}})
    # A burst is velocity evidence (same family as BURST_CLICK_PATTERN), not a second category.
    assert hits["SUB_SECOND_CLICK_INTERVAL"].category == "VELOCITY"
    assert "ABNORMAL_CLICK_TIMING" not in hits


def test_regular_sub_second_burst_is_not_counted_as_automation():
    stats = interval_stats([i * 0.08 for i in range(10)])  # scripted burst, perfectly regular
    hits = timing(ad_click_interval_avg_s=stats.mean, ad_click_interval_min_s=stats.minimum,
                  ad_click_interval_cv=stats.cv, extra_signals={"ad_click_intervals": {"landings": 10}})
    assert "SUB_SECOND_CLICK_INTERVAL" in hits and "ABNORMAL_CLICK_TIMING" not in hits


def test_impossible_interaction_timing():
    stats = interval_stats([i * 0.020 for i in range(20)])  # 20 clicks 20 ms apart
    hits = timing(event_interval_min_ms=stats.minimum * 1000, event_interval_cv=stats.cv,
                  extra_signals={"event_intervals": {"events": 20}})
    assert "IMPOSSIBLE_INTERACTION_TIMING" in hits
    human = interval_stats([0, 1.3, 4.0, 4.6, 9.8, 12.0, 15.5, 21.0, 22.2, 30.0, 31.7])
    hits = timing(event_interval_min_ms=human.minimum * 1000, event_interval_cv=human.cv,
                  extra_signals={"event_intervals": {"events": 11}})
    assert "IMPOSSIBLE_INTERACTION_TIMING" not in hits


# ---- task 022: anomaly statistics ---------------------------------------------

def test_robust_baseline_and_z():
    baseline = robust_baseline([4, 5, 3, 4, 6, 4, 100])  # one past spike barely moves it
    assert baseline.median == 4 and baseline.mad == 1
    assert robust_z(80, baseline) > 40
    assert robust_baseline([]) is None


START = datetime(2026, 9, 1, tzinfo=timezone.utc)


def hourly(days: int, value_for) -> dict:
    return {START + timedelta(hours=h): HourStat(value_for(h)) for h in range(days * 24)}


def test_spike_after_steady_traffic_is_high():
    stats = hourly(14, lambda h: 4)
    spike_hour = START + timedelta(days=14)
    stats[spike_hour] = HourStat(80)
    [finding] = [f for f in detect_hour(spike_hour, stats, first_hour=START) if f.metric == "ad_landings"]
    assert finding.level == "HIGH" and finding.expected == 4


def test_normal_daily_variation_is_not_an_anomaly():
    stats = hourly(15, lambda h: [2, 8, 5, 3, 6, 4, 7][h % 7])
    for day_hour in range(24):
        hour = START + timedelta(days=14, hours=day_hour)
        assert not [f for f in detect_hour(hour, stats, first_hour=START) if f.level == "HIGH"]


def test_spec_31_daily_spike_100_to_2000():
    stats = hourly(14, lambda h: 4)               # ~100 / day
    hour = START + timedelta(days=14)
    stats[hour] = HourStat(83)                     # ~2,000 / day pace
    assert any(f.level == "HIGH" for f in detect_hour(hour, stats, first_hour=START))


def test_interval_drop_is_detected():
    stats = {h: HourStat(60, 60.0 + (i % 5)) for i, h in enumerate(hourly(14, lambda h: 60))}
    hour = START + timedelta(days=14)
    stats[hour] = HourStat(60, 1.0)
    findings = {f.metric: f for f in detect_hour(hour, stats, first_hour=START)}
    assert findings["median_click_interval"].level == "HIGH"


def test_cold_start_is_skipped():
    stats = hourly(3, lambda h: 4)
    assert detect_hour(START + timedelta(days=3), stats, first_hour=START) is None


def test_traffic_drop_is_tracking_alert_not_fraud_signal():
    stats = hourly(14, lambda h: 40)
    hour = START + timedelta(days=14)               # no row = no landings at all
    findings = detect_hour(hour, stats, first_hour=START)
    assert [f.metric for f in findings] == ["ad_landings_drop"]


def test_traffic_anomaly_rule_alone_is_context_only():
    s = session()
    results = evaluate(FeatureContext(session=s, traffic_anomaly_level="HIGH"), catalog_configs())
    assert [r.code for r in results] == ["TRAFFIC_ANOMALY"]
    agg = aggregate(results, s)
    assert agg.risk < 30 and decide(agg.risk, agg.evidence_confidence, agg.diversity, get_policy(None)).value == "SAFE"
    assert evaluate(FeatureContext(session=s, traffic_anomaly_level="MEDIUM"), catalog_configs()) == []

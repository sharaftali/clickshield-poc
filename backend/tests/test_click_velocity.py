"""Task 004: velocity counts paid ad landings across sessions, not on-page clicks per batch."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy.dialects import postgresql

from app.models import Session, Verdict
from app.schemas.tracking import TrackingBatchIn
from app.services.rules import FeatureContext, evaluate
from app.services.rules.repository import catalog_configs
from app.services.tracking_service import (
    VELOCITY_WINDOWS,
    TrackingService,
    build_ad_click_velocity_query,
    merge_velocity_counts,
)

NOW = datetime(2026, 10, 6, 12, 0, tzinfo=timezone.utc)


def make_session(**overrides) -> Session:
    fields = dict(
        id=uuid.uuid4(), organization_id=uuid.uuid4(), website_id=uuid.uuid4(), visitor_id=uuid.uuid4(),
        session_token="s_session_test", ip_address="203.0.113.7", page_count=0, click_count=0,
        interaction_count=0, scroll_depth=0.0, session_duration_seconds=0.0,
        verdict=Verdict.SAFE, system_verdict=Verdict.SAFE, is_vpn=False, is_proxy=False,
        is_tor=False, is_datacenter=False,
        **{name: 0 for name, _ in VELOCITY_WINDOWS},
    )
    fields.update(overrides)
    return Session(**fields)


def batch(*event_types: str, **attribution) -> TrackingBatchIn:
    return TrackingBatchIn(
        events=[
            {
                "site_token": "site_token_test", "visitor_token": "v_visitor_test",
                "session_token": "s_session_test", "event_type": event_type,
                "page_url": "https://example.test/", "timestamp": (NOW + timedelta(seconds=i)).isoformat(),
                **attribution,
            }
            for i, event_type in enumerate(event_types)
        ]
    )


def test_on_page_clicks_never_feed_velocity():
    session = make_session()
    TrackingService(db=None)._update_session_counters(session, batch("page_view", *["click"] * 15))
    assert session.click_count == 15
    assert all(getattr(session, name) == 0 for name, _ in VELOCITY_WINDOWS)


def test_interaction_count_excludes_page_views():
    session = make_session()
    TrackingService(db=None)._update_session_counters(
        session, batch("page_view", "page_view", "click", "scroll", "form_start", "phone_click")
    )
    assert session.page_count == 2
    assert session.interaction_count == 4


@pytest.mark.parametrize(
    ("events", "attribution", "paid"),
    [
        (["page_view"], {"gclid": "abc"}, True),
        (["page_view"], {"utm_source": "google"}, True),
        (["page_view"], {"campaign_id": "555"}, True),
        (["ad_landing", "page_view"], {}, True),
        (["page_view"], {"utm_source": "newsletter"}, False),
        (["page_view", "click"], {}, False),
    ],
)
def test_is_paid_landing(events, attribution, paid):
    payload = batch(*events, **attribution)
    assert TrackingService(db=None)._is_paid_landing(payload.events[0], payload) is paid


def test_merge_velocity_counts_takes_highest_key_and_counts_current_landing():
    merged = merge_velocity_counts(
        {
            "ip": {"clicks_60_seconds": 8, "clicks_24_hours": 9},
            "visitor": {"clicks_60_seconds": 2, "clicks_24_hours": 20},
        }
    )
    assert merged["clicks_60_seconds"] == 8
    assert merged["clicks_24_hours"] == 20
    assert merged["clicks_10_seconds"] == 1  # never below the current landing
    assert merge_velocity_counts({}) == {name: 1 for name, _ in VELOCITY_WINDOWS}


def test_velocity_query_is_org_scoped_distinct_gclid_and_windowed():
    org_id = uuid.uuid4()
    query = build_ad_click_velocity_query(
        organization_id=org_id, key_column=Session.ip_address, key_value="203.0.113.7", landed_at=NOW
    )
    compiled = query.compile(dialect=postgresql.dialect())
    sql = str(compiled)
    params = list(compiled.params.values())
    assert "count(DISTINCT coalesce(sessions.gclid, CAST(sessions.id AS VARCHAR))) FILTER (WHERE sessions.ad_landing_at >" in sql
    assert sql.count("FILTER") == len(VELOCITY_WINDOWS)
    assert "sessions.organization_id = %(organization_id_1)s" in sql and org_id in params
    assert "sessions.ip_address = " in sql and "203.0.113.7" in params
    assert "sessions.ad_landing_at <= " in sql and NOW in params
    assert NOW - timedelta(seconds=60) in params and NOW - timedelta(days=1) in params


class FakeDB:
    """Returns one velocity row per execute() call."""

    def __init__(self, *rows: dict[str, int]):
        self.rows = list(rows)
        self.flushed = 0

    async def flush(self):
        self.flushed += 1

    async def execute(self, query):
        row = self.rows.pop(0)
        return SimpleNamespace(one=lambda: SimpleNamespace(_mapping=row))


async def test_apply_velocity_stores_max_of_ip_and_visitor():
    ip_counts = {name: 0 for name, _ in VELOCITY_WINDOWS} | {"clicks_60_seconds": 8, "clicks_24_hours": 8}
    visitor_counts = {name: 0 for name, _ in VELOCITY_WINDOWS} | {"clicks_60_seconds": 1, "clicks_24_hours": 12}
    db = FakeDB(ip_counts, visitor_counts)
    session = make_session(ad_landing_at=NOW, extra_signals={"source_platform": "google_ads"})

    await TrackingService(db=db)._apply_ad_click_velocity(session)

    assert db.flushed == 1
    assert session.clicks_60_seconds == 8 and session.clicks_24_hours == 12
    assert session.extra_signals["ad_click_velocity"]["ip"]["clicks_60_seconds"] == 8
    assert session.extra_signals["source_platform"] == "google_ads"


def reasons(session: Session, rules=None) -> set[str]:
    return {result.code for result in evaluate(FeatureContext(session=session), rules or catalog_configs())}


def test_human_with_many_page_clicks_has_no_velocity_rule():
    # Spec §75 test 1: one ad landing, lots of on-page clicks, real browsing.
    session = make_session(
        click_count=15, page_count=4, scroll_depth=80.0, session_duration_seconds=120.0,
        **{name: 1 for name, _ in VELOCITY_WINDOWS},
    )
    assert "ABNORMAL_CLICK_VELOCITY" not in reasons(session)
    assert "BURST_CLICK_PATTERN" not in reasons(session)


def test_repeated_ad_landings_trigger_velocity_rules():
    # Spec §75 test 2: many ad clicks from one IP in a short time.
    session = make_session(
        clicks_10_seconds=5, clicks_30_seconds=12, clicks_60_seconds=12, clicks_5_minutes=12,
        clicks_1_hour=12, clicks_24_hours=12, session_duration_seconds=1.0, page_count=1,
    )
    assert {"ABNORMAL_CLICK_VELOCITY", "BURST_CLICK_PATTERN"} <= reasons(session)


def test_velocity_threshold_comes_from_rule_configuration():
    from dataclasses import replace

    session = make_session(clicks_60_seconds=5, session_duration_seconds=60.0, page_count=3)
    assert "ABNORMAL_CLICK_VELOCITY" not in reasons(session)
    rules = [
        replace(rule, params={**rule.params, "clicks_60_seconds_gte": 5}) if rule.code == "ABNORMAL_CLICK_VELOCITY" else rule
        for rule in catalog_configs()
    ]
    assert "ABNORMAL_CLICK_VELOCITY" in reasons(session, rules)

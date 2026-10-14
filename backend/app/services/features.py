"""
Feature engine (spec §15–20, §81): signals computed from stored traffic, kept on
the session so rules stay pure and results stay explainable.

- device_key (task 019): coarse, salted, per-organization hash — no raw fingerprint.
- repeat counts (task 019): paid landings by visitor / IP / landing page / device
  key on the same campaign, short and long windows; computed once, at landing.
- ad-click intervals (task 021): avg / min / variance / CV of the gaps between
  this source's paid landings (last 24h); computed at landing.
- on-page action intervals (task 021): the same statistics for this session's
  clicks / form / phone / outbound / conversion events (not scroll: the browser
  fires scroll events every frame, which says nothing about the person).
- identical sessions (task 019, §20) and the campaign's geo targets / active
  traffic anomaly: loaded at scoring time into the FeatureContext.
"""
from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import Float, String, and_, cast, distinct, func, literal, select, true
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models import Event, EventType, GoogleCampaign, GoogleCampaignLocation, Session, TrafficAnomaly
from app.services.geo import GeoTarget
from app.services.ip_reputation import ReputationEvidence
from app.services.rules.evaluators import FeatureContext, RuleConfig

TIMING_EVENT_TYPES = (
    EventType.CLICK,
    EventType.FORM_START,
    EventType.FORM_SUBMIT,
    EventType.PHONE_CLICK,
    EventType.OUTBOUND_CLICK,
    EventType.CONVERSION,
)
MAX_TIMING_EVENTS = 2000


# ---- device key -------------------------------------------------------------

def _salt() -> str:
    return settings.DEVICE_KEY_SALT or hashlib.sha256(f"device-key:{settings.SECRET_KEY}".encode()).hexdigest()


def device_key(
    organization_id,
    *,
    browser: str | None,
    os: str | None,
    device: str | None,
    screen_width: object = None,
    screen_height: object = None,
    timezone_name: str | None = None,
    language: str | None = None,
) -> str | None:
    """sha256 over coarse traits (browser family, OS, device class, screen size, timezone,
    language), salted and scoped per organization so keys can't be joined across tenants."""
    parts = [
        browser or "", os or "", device or "",
        f"{screen_width or ''}x{screen_height or ''}",
        (timezone_name or "").strip(), (language or "").strip().casefold(),
    ]
    if not any(part.strip("x") for part in parts):
        return None
    raw = "|".join([_salt(), str(organization_id), *parts])
    return hashlib.sha256(raw.encode()).hexdigest()


# ---- interval statistics ----------------------------------------------------

@dataclass(frozen=True)
class IntervalStats:
    count: int        # intervals
    mean: float
    minimum: float
    variance: float   # population variance
    cv: float         # std / mean (0 when mean is 0)


def interval_stats(timestamps: list[float]) -> IntervalStats | None:
    """Statistics of the gaps between sorted timestamps (Welford). Out-of-order values
    are sorted; None with fewer than INTERVAL_MIN_SAMPLES gaps (meaningless)."""
    values = sorted(timestamps)
    gaps = [max(0.0, b - a) for a, b in zip(values, values[1:])]
    if len(gaps) < max(1, settings.INTERVAL_MIN_SAMPLES):
        return None
    mean = m2 = 0.0
    for n, gap in enumerate(gaps, start=1):
        delta = gap - mean
        mean += delta / n
        m2 += delta * (gap - mean)
    variance = m2 / len(gaps)
    cv = math.sqrt(variance) / mean if mean > 0 else 0.0
    return IntervalStats(count=len(gaps), mean=mean, minimum=min(gaps), variance=variance, cv=cv)


# ---- queries ----------------------------------------------------------------

def _click_key():
    # Reloads of one ad click share a gclid and count once (as in velocity, task 004).
    return func.coalesce(Session.gclid, cast(Session.id, String))


def landing_path(column=Session.landing_page):
    """URL without query string / fragment (gclid differs on every click)."""
    return func.split_part(func.split_part(column, "?", 1), "#", 1)


def _strip_query(url: str | None) -> str | None:
    if url is None:
        return None
    return url.split("?", 1)[0].split("#", 1)[0]


def build_repeat_counts_query(session: Session, *, landed_at: datetime):
    short = landed_at - timedelta(hours=settings.REPEAT_SHORT_WINDOW_HOURS)
    long = landed_at - timedelta(hours=settings.REPEAT_LONG_WINDOW_HOURS)
    device_since = landed_at - timedelta(minutes=settings.DEVICE_KEY_WINDOW_MINUTES)
    click_key = _click_key()
    same_campaign = (
        Session.google_campaign_id == session.google_campaign_id
        if session.google_campaign_id is not None else true()
    )
    same_visitor = Session.visitor_id == session.visitor_id if session.visitor_id else literal(False)
    same_ip = Session.ip_address == session.ip_address if session.ip_address else literal(False)
    same_device = Session.device_key == session.device_key if session.device_key else literal(False)
    same_landing = landing_path() == _strip_query(session.landing_page) if session.landing_page else literal(False)

    def count(condition, since):
        return func.count(distinct(click_key)).filter(and_(condition, Session.ad_landing_at > since))

    return select(
        count(and_(same_visitor, same_campaign), short).label("visitor_campaign_short"),
        count(and_(same_visitor, same_campaign), long).label("visitor_campaign_long"),
        count(and_(same_ip, same_campaign), short).label("ip_campaign_short"),
        count(and_(same_ip, same_campaign), long).label("ip_campaign_long"),
        count(and_(same_ip, same_landing), short).label("ip_landing_short"),
        count(and_(same_ip, same_landing), long).label("ip_landing_long"),
        count(and_(same_device, same_campaign), device_since).label("device_campaign"),
        # The same device profile's landings on the campaign before the device window: how
        # common the (coarse) profile normally is.
        func.count(distinct(click_key)).filter(
            and_(same_device, same_campaign, Session.ad_landing_at <= device_since)
        ).label("device_campaign_before"),
        func.count(distinct(Session.ip_address)).filter(and_(same_device, Session.ad_landing_at > device_since))
        .label("device_distinct_ips"),
        func.count(distinct(Session.visitor_id)).filter(and_(same_ip, Session.ad_landing_at > short))
        .label("ip_distinct_visitors"),
    ).where(
        Session.organization_id == session.organization_id,
        Session.ad_landing_at.is_not(None),
        Session.ad_landing_at > long,
        Session.ad_landing_at <= landed_at,
        same_visitor | same_ip | same_device,
    )


def repeat_counts_from_row(row) -> dict:
    m = row._mapping
    return {
        "visitor_campaign": {"short": int(m["visitor_campaign_short"] or 0), "long": int(m["visitor_campaign_long"] or 0)},
        "ip_campaign": {"short": int(m["ip_campaign_short"] or 0), "long": int(m["ip_campaign_long"] or 0)},
        "ip_landing": {"short": int(m["ip_landing_short"] or 0), "long": int(m["ip_landing_long"] or 0)},
        "device_campaign": int(m["device_campaign"] or 0),
        # Expected landings of this device profile in one device window, from the long window.
        "device_campaign_usual": round(
            int(m.get("device_campaign_before") or 0) * settings.DEVICE_KEY_WINDOW_MINUTES
            / max(1, settings.REPEAT_LONG_WINDOW_HOURS * 60 - settings.DEVICE_KEY_WINDOW_MINUTES),
            3,
        ),
        "device_distinct_ips": int(m["device_distinct_ips"] or 0),
        "ip_distinct_visitors": int(m["ip_distinct_visitors"] or 0),
        "ip_shared": int(m["ip_distinct_visitors"] or 0) >= settings.SHARED_IP_MIN_DISTINCT_VISITORS,
        "windows_hours": {"short": settings.REPEAT_SHORT_WINDOW_HOURS, "long": settings.REPEAT_LONG_WINDOW_HOURS},
        "device_window_minutes": settings.DEVICE_KEY_WINDOW_MINUTES,
    }


def build_landing_times_query(session: Session, key_column, key_value, *, landed_at: datetime):
    """One landing time per distinct ad click for this source within the lookback."""
    since = landed_at - timedelta(hours=settings.AD_CLICK_INTERVAL_LOOKBACK_HOURS)
    return (
        select(func.min(func.extract("epoch", Session.ad_landing_at)).cast(Float))
        .where(
            Session.organization_id == session.organization_id,
            key_column == key_value,
            Session.ad_landing_at.is_not(None),
            Session.ad_landing_at > since,
            Session.ad_landing_at <= landed_at,
        )
        .group_by(_click_key())
    )


def build_identical_sessions_query(session: Session, params: dict, *, now: datetime):
    window = timedelta(minutes=int(params["window_minutes"]))
    tolerance = float(params["duration_tolerance_seconds"])
    duration = float(session.session_duration_seconds or 0)
    return select(func.count()).select_from(Session).where(
        Session.organization_id == session.organization_id,
        Session.id != session.id,
        Session.device_key == session.device_key,
        Session.ip_address == session.ip_address,
        Session.ad_landing_at.is_not(None),
        Session.ad_landing_at > now - window,
        landing_path() == _strip_query(session.landing_page),
        Session.page_count == int(session.page_count or 0),
        Session.session_duration_seconds.between(duration - tolerance, duration + tolerance),
    )


# ---- apply to a session -----------------------------------------------------

async def apply_landing_features(db: AsyncSession, session: Session) -> None:
    """At a new paid landing: repeat counts and ad-click interval statistics (call after flush)."""
    landed_at = session.ad_landing_at
    if landed_at is None:
        return
    row = (await db.execute(build_repeat_counts_query(session, landed_at=landed_at))).one()
    repeat = repeat_counts_from_row(row)

    # Intervals per source; a shared IP's gaps mix many people, so it is left out.
    keys = []
    if session.visitor_id:
        keys.append(("visitor", Session.visitor_id, session.visitor_id))
    if session.ip_address and not repeat["ip_shared"]:
        keys.append(("ip", Session.ip_address, session.ip_address))
    best: tuple[str, list[float]] | None = None
    for name, column, value in keys:
        times = list(
            (await db.execute(build_landing_times_query(session, column, value, landed_at=landed_at))).scalars()
        )
        if best is None or len(times) > len(best[1]):
            best = (name, times)

    stats = interval_stats(best[1]) if best else None
    session.ad_click_interval_avg_s = stats.mean if stats else None
    session.ad_click_interval_min_s = stats.minimum if stats else None
    session.ad_click_interval_var = stats.variance if stats else None
    session.ad_click_interval_cv = stats.cv if stats else None
    session.extra_signals = {
        **(session.extra_signals or {}),
        "repeat_visitor": repeat,
        "ad_click_intervals": {"key": best[0] if best else None, "landings": len(best[1]) if best else 0},
    }


async def apply_event_interval_features(db: AsyncSession, session: Session) -> None:
    """Every batch: timing of this session's on-page actions (call after flush)."""
    times = list(
        (
            await db.execute(
                select(func.extract("epoch", Event.timestamp).cast(Float))
                .where(Event.session_id == session.id, Event.event_type.in_(TIMING_EVENT_TYPES))
                .order_by(Event.timestamp)
                .limit(MAX_TIMING_EVENTS)
            )
        ).scalars()
    )
    stats = interval_stats(times)
    session.event_interval_avg_ms = stats.mean * 1000 if stats else None
    session.event_interval_min_ms = stats.minimum * 1000 if stats else None
    session.event_interval_var = stats.variance * 1_000_000 if stats else None
    session.event_interval_cv = stats.cv if stats else None
    session.extra_signals = {**(session.extra_signals or {}), "event_intervals": {"events": len(times)}}


async def _identical_sessions(db: AsyncSession, session: Session, rules: dict[str, RuleConfig]) -> int:
    rule = rules.get("REPEATED_IDENTICAL_SESSIONS")
    if rule is None or not rule.enabled or not session.device_key or not session.ip_address or session.ad_landing_at is None:
        return 0
    # Bounces all look alike; they are UNUSUAL_SESSION's evidence, not cloned behaviour.
    if float(session.session_duration_seconds or 0) < float(rule.params["min_duration_seconds"]):
        return 0
    query = build_identical_sessions_query(session, rule.params, now=datetime.now(timezone.utc))
    return int(await db.scalar(query) or 0)


async def _geo_targets(db: AsyncSession, session: Session) -> tuple[list[GeoTarget], str | None]:
    if session.google_campaign_id is None:
        return [], None
    geo_type = await db.scalar(
        select(GoogleCampaign.geo_target_type).where(GoogleCampaign.id == session.google_campaign_id)
    )
    rows = (
        await db.execute(
            select(GoogleCampaignLocation).where(GoogleCampaignLocation.campaign_id == session.google_campaign_id)
        )
    ).scalars()
    targets = [
        GeoTarget(country_code=row.country_code, region=row.region, name=row.name,
                  target_type=row.target_type, negative=row.negative)
        for row in rows
    ]
    return targets, geo_type


async def _active_anomaly_level(db: AsyncSession, session: Session) -> str | None:
    if session.google_campaign_id is None or session.ad_landing_at is None:
        return None
    grace = timedelta(hours=settings.ANOMALY_SESSION_RULE_HOURS)
    levels = (
        await db.execute(
            select(TrafficAnomaly.level).where(
                TrafficAnomaly.google_campaign_id == session.google_campaign_id,
                TrafficAnomaly.metric.in_(("ad_landings", "median_click_interval")),
                TrafficAnomaly.window_start <= session.ad_landing_at,
                TrafficAnomaly.window_end + grace > session.ad_landing_at,
            )
        )
    ).scalars().all()
    if "HIGH" in levels:
        return "HIGH"
    return "MEDIUM" if levels else None


async def build_context(
    db: AsyncSession,
    session: Session,
    rules: list[RuleConfig],
    reputation: ReputationEvidence | None,
) -> FeatureContext:
    by_code = {rule.code: rule for rule in rules}
    targets, geo_type = await _geo_targets(db, session)
    return FeatureContext(
        session=session,
        reputation=reputation,
        identical_sessions=await _identical_sessions(db, session, by_code),
        geo_targets=targets,
        geo_target_type=geo_type,
        traffic_anomaly_level=await _active_anomaly_level(db, session),
    )

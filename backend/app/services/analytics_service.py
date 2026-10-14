"""
Reporting definitions (spec §46–48, task 025), shared by the dashboard, analytics
and campaign endpoints so their numbers always agree.

- label      = final_label (client feedback) when present, else the system verdict
- suspicious = label in (MONITOR, FLAG, FRAUD)
- fraud      = label == FRAUD
- clicks     = sessions that landed from a paid ad (ad_landing_at set)
- fraud rate = fraud / sessions for the same filter

Days and hours are in the organization's timezone (organizations.timezone).
Plain PostgreSQL GROUP BY over `sessions` (ix_sessions_org_created). A daily
rollup or ClickHouse only when this gets slow (spec §59).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
from typing import Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import String, and_, case, cast, func, literal, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import GoogleCampaign, Session, Verdict

GroupBy = Literal["day", "hour", "campaign", "country", "city", "asn", "isp", "device", "source"]
GROUP_BY_VALUES: tuple[str, ...] = GroupBy.__args__
HIGH_CARDINALITY = {"city", "asn", "isp", "country"}
RANGE_DAYS = {"today": 0, "7d": 6, "30d": 29}

LABEL = func.coalesce(Session.final_label, Session.verdict)
IS_FRAUD = LABEL == Verdict.FRAUD
IS_SUSPICIOUS = LABEL.in_((Verdict.MONITOR, Verdict.FLAG, Verdict.FRAUD))
IS_PAID = Session.ad_landing_at.is_not(None)


def zone(name: str | None) -> ZoneInfo:
    try:
        return ZoneInfo(name or "UTC")
    except (ZoneInfoNotFoundError, ValueError):
        return ZoneInfo("UTC")


@dataclass(frozen=True)
class Period:
    start: datetime   # UTC, inclusive
    end: datetime     # UTC, exclusive
    timezone: str


def period_for_range(range_name: str, tz_name: str, *, now: datetime | None = None) -> Period:
    """'today' / '7d' / '30d' as whole local days ending today."""
    tz = zone(tz_name)
    local_now = (now or datetime.now(timezone.utc)).astimezone(tz)
    first_day = local_now.date() - timedelta(days=RANGE_DAYS[range_name])
    return period_for_dates(first_day, local_now.date(), tz_name)


def period_for_dates(first: date, last: date, tz_name: str) -> Period:
    tz = zone(tz_name)
    start = datetime.combine(first, time.min, tzinfo=tz)
    end = datetime.combine(last + timedelta(days=1), time.min, tzinfo=tz)
    return Period(start.astimezone(timezone.utc), end.astimezone(timezone.utc), str(tz.key))


def metric_columns():
    return (
        func.count().label("sessions"),
        func.count().filter(IS_PAID).label("clicks"),
        func.count().filter(IS_SUSPICIOUS).label("suspicious"),
        func.count().filter(IS_FRAUD).label("fraud"),
        func.coalesce(func.avg(Session.risk_score), 0).label("avg_risk"),
    )


def rate(part: int, whole: int) -> float:
    return round(part / whole, 4) if whole else 0.0


def _source_expr():
    return case(
        (IS_PAID | Session.gclid.is_not(None) | Session.gbraid.is_not(None) | Session.wbraid.is_not(None), literal("paid")),
        (Session.referrer.is_not(None) & (Session.referrer != ""), literal("organic")),
        else_=literal("direct"),
    )


def _group_expr(group_by: str, tz_name: str):
    local = func.timezone(tz_name, Session.created_at)
    return {
        "day": cast(func.date(local), String),
        "hour": cast(func.extract("hour", local), String),
        "campaign": cast(Session.google_campaign_id, String),
        "country": Session.country,
        "city": Session.city,
        "asn": Session.asn,
        "isp": Session.isp,
        "device": Session.device,
        "source": _source_expr(),
    }[group_by]


async def breakdown(
    db: AsyncSession,
    organization_id,
    *,
    group_by: str,
    period: Period,
    website_id=None,
    campaign_id=None,
    limit: int = 20,
) -> list[dict]:
    key = _group_expr(group_by, period.timezone).label("key")
    query = (
        select(key, *metric_columns())
        .where(
            Session.organization_id == organization_id,
            Session.created_at >= period.start,
            Session.created_at < period.end,
        )
        .group_by(key)
    )
    if website_id is not None:
        query = query.where(Session.website_id == website_id)
    if campaign_id is not None:
        query = query.where(Session.google_campaign_id == campaign_id)
    rows = [dict(row._mapping) for row in (await db.execute(query)).all()]

    labels: dict[str, str] = {}
    if group_by == "campaign":
        ids = [row["key"] for row in rows if row["key"]]
        if ids:
            labels = {
                str(cid): name for cid, name in (
                    await db.execute(select(GoogleCampaign.id, GoogleCampaign.name).where(cast(GoogleCampaign.id, String).in_(ids)))
                ).all()
            }

    items = []
    for row in rows:
        raw = row["key"]
        if group_by == "hour" and raw is not None:
            raw = str(int(float(raw)))
        label = labels.get(raw) if group_by == "campaign" else None
        items.append({
            "key": raw if raw is not None else "unknown",
            "label": label or (raw if raw not in (None, "") else ("Not matched to a campaign" if group_by == "campaign" else "Unknown")),
            "sessions": int(row["sessions"]), "clicks": int(row["clicks"]),
            "suspicious": int(row["suspicious"]), "fraud": int(row["fraud"]),
            "fraud_rate": rate(int(row["fraud"]), int(row["sessions"])),
            "avg_risk": round(float(row["avg_risk"] or 0), 1),
        })

    if group_by in ("day", "hour"):
        items.sort(key=lambda item: int(item["key"]) if group_by == "hour" and item["key"].isdigit() else item["key"])
        return items
    items.sort(key=lambda item: (-item["sessions"], item["key"]))
    if group_by in HIGH_CARDINALITY and len(items) > limit:
        rest = items[limit:]
        sessions = sum(i["sessions"] for i in rest)
        fraud = sum(i["fraud"] for i in rest)
        items = items[:limit] + [{
            "key": "other", "label": f"Other ({len(rest)})", "sessions": sessions,
            "clicks": sum(i["clicks"] for i in rest), "suspicious": sum(i["suspicious"] for i in rest),
            "fraud": fraud, "fraud_rate": rate(fraud, sessions),
            "avg_risk": round(sum(i["avg_risk"] * i["sessions"] for i in rest) / sessions, 1) if sessions else 0.0,
        }]
    return items[: limit + 1] if group_by in HIGH_CARDINALITY else items


async def totals(db: AsyncSession, organization_id, period: Period, *, extra_where=None) -> dict:
    query = select(*metric_columns()).where(
        Session.organization_id == organization_id,
        Session.created_at >= period.start,
        Session.created_at < period.end,
    )
    if extra_where is not None:
        query = query.where(and_(extra_where))
    row = (await db.execute(query)).one()._mapping
    return {
        "sessions": int(row["sessions"]), "clicks": int(row["clicks"]), "suspicious": int(row["suspicious"]),
        "fraud": int(row["fraud"]), "fraud_rate": rate(int(row["fraud"]), int(row["sessions"])),
        "avg_risk": round(float(row["avg_risk"] or 0), 1),
    }

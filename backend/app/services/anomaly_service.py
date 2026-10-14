"""
Statistical anomaly detection per campaign (spec §31, §66, §76; task 022). No ML.

Every few minutes the worker:
1. aggregates paid landings into hourly `campaign_traffic_stats` rows
   (landings, distinct IPs / visitors, FRAUD sessions, median click interval);
2. compares the last complete hour — and the current hour so far, scaled — with the
   campaign's robust baseline: median and MAD of the previous ANOMALY_BASELINE_DAYS
   of hourly values (same hour of day when there is enough data, else all hours;
   hours without traffic count as 0). robust z = (x − median) / (1.4826 × MAD).
3. stores `traffic_anomalies`:
   - `ad_landings`            spike (more paid clicks than normal) — fraud signal
   - `median_click_interval`  clicks suddenly much closer together — fraud signal
   - `ad_landings_drop`       traffic stopped (tracking removed?) — §66 "tracking
                              failure", never a fraud signal
   A new HIGH anomaly writes an audit row (TRAFFIC_ANOMALY_DETECTED); alert delivery is task 028.

Sessions landing during, or up to ANOMALY_SESSION_RULE_HOURS after, a fraud-signal
anomaly get the TRAFFIC_ANOMALY rule (category ANOMALY: context only, never decides alone).
Campaigns with less than ANOMALY_MIN_HISTORY_DAYS of traffic are skipped (cold start).
"""
from __future__ import annotations

import logging
import math
import uuid
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from statistics import median

from sqlalchemy import func, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models import AuditResult, CampaignTrafficStat, TrafficAnomaly
from app.services import alert_service, audit_service
from app.services.audit_service import AuditAction

logger = logging.getLogger(__name__)

MAD_TO_SIGMA = 1.4826
HOUR = timedelta(hours=1)
MIN_INTERVAL_LANDINGS = 5        # an hour needs this many landings for its median interval to mean anything
MIN_INTERVAL_SCALE = 0.1         # log-seconds: floor for a perfectly regular baseline
MIN_PARTIAL_HOUR_FRACTION = 0.25  # don't judge the current hour on its first minutes
FRAUD_METRICS = ("ad_landings", "median_click_interval")


# ---- pure statistics ----------------------------------------------------------

@dataclass(frozen=True)
class Baseline:
    median: float
    mad: float
    samples: int


def robust_baseline(values: list[float]) -> Baseline | None:
    if not values:
        return None
    center = median(values)
    return Baseline(median=center, mad=median(abs(v - center) for v in values), samples=len(values))


def robust_z(observed: float, baseline: Baseline, *, min_scale: float = 1.0) -> float:
    """(x − median) / (1.4826 × MAD), with a floor on the scale so a flat baseline
    (MAD 0) doesn't turn a tiny change into an infinite score."""
    scale = max(MAD_TO_SIGMA * baseline.mad, min_scale)
    return (observed - baseline.median) / scale


def count_scale_floor(baseline: Baseline) -> float:
    # Counts are noisy like a Poisson process: allow ~√median of normal variation.
    return max(1.0, math.sqrt(max(baseline.median, 0.0)))


def level_for(z: float) -> str | None:
    if z >= settings.ANOMALY_Z_HIGH:
        return "HIGH"
    if z >= settings.ANOMALY_Z_MEDIUM:
        return "MEDIUM"
    return None


@dataclass(frozen=True)
class HourStat:
    ad_landings: int
    median_click_interval_s: float | None = None


@dataclass(frozen=True)
class Finding:
    metric: str
    observed: float
    expected: float
    score: float
    level: str


def detect_hour(
    hour: datetime,
    stats: dict[datetime, HourStat],
    *,
    first_hour: datetime,
    fraction: float = 1.0,
) -> list[Finding] | None:
    """Findings for one hour of one campaign; None = not enough history (cold start).

    `stats` maps hour buckets to the campaign's statistics (missing hour = no traffic).
    `fraction` < 1 judges the current, incomplete hour against a scaled baseline.
    """
    if hour - first_hour < timedelta(days=settings.ANOMALY_MIN_HISTORY_DAYS):
        return None
    start = max(first_hour, hour - timedelta(days=settings.ANOMALY_BASELINE_DAYS))
    history_hours = []
    h = start
    while h < hour:
        history_hours.append(h)
        h += HOUR

    same_hour = [h for h in history_hours if h.hour == hour.hour]
    chosen = same_hour if len(same_hour) >= settings.ANOMALY_MIN_SAME_HOUR_SAMPLES else history_hours
    counts = [float(stats[h].ad_landings) if h in stats else 0.0 for h in chosen]
    baseline = robust_baseline(counts)
    if baseline is None:
        return None

    findings: list[Finding] = []
    current = stats.get(hour)
    observed = float(current.ad_landings) if current else 0.0
    scaled = Baseline(baseline.median * fraction, baseline.mad * fraction, baseline.samples)
    z = robust_z(observed, scaled, min_scale=count_scale_floor(scaled))
    level = level_for(z)
    if level and observed >= settings.ANOMALY_MIN_LANDINGS * fraction:
        findings.append(Finding("ad_landings", observed, round(scaled.median, 2), round(z, 2), level))

    # Traffic stopped where it is normally busy: "tracking failure?" (complete hours only).
    if fraction >= 1.0 and baseline.median >= settings.ANOMALY_MIN_LANDINGS:
        drop_level = level_for(-z)
        if drop_level:
            findings.append(Finding("ad_landings_drop", observed, round(baseline.median, 2), round(-z, 2), drop_level))

    # Clicks suddenly much closer together. Compared on a log scale: 60 s → 1 s is
    # as unusual as 600 s → 10 s.
    if current and current.median_click_interval_s is not None and current.ad_landings >= MIN_INTERVAL_LANDINGS:
        logs = [
            math.log(max(stats[h].median_click_interval_s, 0.01))
            for h in history_hours
            if h in stats and stats[h].median_click_interval_s is not None and stats[h].ad_landings >= MIN_INTERVAL_LANDINGS
        ]
        interval_baseline = robust_baseline(logs)
        if interval_baseline and interval_baseline.samples >= settings.ANOMALY_MIN_SAME_HOUR_SAMPLES:
            observed_log = math.log(max(current.median_click_interval_s, 0.01))
            z_interval = (interval_baseline.median - observed_log) / max(MAD_TO_SIGMA * interval_baseline.mad, MIN_INTERVAL_SCALE)
            interval_level = level_for(z_interval)
            if interval_level:
                findings.append(Finding(
                    "median_click_interval", round(current.median_click_interval_s, 3),
                    round(math.exp(interval_baseline.median), 3), round(z_interval, 2), interval_level,
                ))
    return findings


# ---- jobs -------------------------------------------------------------------------

AGGREGATE_SQL = text(
    """
    INSERT INTO campaign_traffic_stats (
        google_campaign_id, hour_bucket, organization_id, ad_landings, distinct_ips,
        distinct_visitors, fraud_sessions, median_click_interval_s, created_at, updated_at
    )
    SELECT google_campaign_id, hour_bucket, (array_agg(organization_id))[1], count(*),
           count(DISTINCT ip_address), count(DISTINCT visitor_id),
           count(*) FILTER (WHERE verdict = 'FRAUD'),
           percentile_cont(0.5) WITHIN GROUP (ORDER BY gap), now(), now()
    FROM (
        SELECT google_campaign_id, organization_id, ip_address, visitor_id, verdict, ad_landing_at,
               date_trunc('hour', ad_landing_at AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' AS hour_bucket,
               EXTRACT(EPOCH FROM ad_landing_at - lag(ad_landing_at)
                   OVER (PARTITION BY google_campaign_id ORDER BY ad_landing_at)) AS gap
        FROM sessions
        WHERE google_campaign_id IS NOT NULL
          AND ad_landing_at >= CAST(:since AS timestamptz) - interval '1 hour'
          AND ad_landing_at < CAST(:until AS timestamptz)
    ) AS landings
    WHERE ad_landing_at >= CAST(:since AS timestamptz)
    GROUP BY google_campaign_id, hour_bucket
    ON CONFLICT (google_campaign_id, hour_bucket) DO UPDATE SET
        ad_landings = EXCLUDED.ad_landings,
        distinct_ips = EXCLUDED.distinct_ips,
        distinct_visitors = EXCLUDED.distinct_visitors,
        fraud_sessions = EXCLUDED.fraud_sessions,
        median_click_interval_s = EXCLUDED.median_click_interval_s,
        updated_at = now()
    """
)


def hour_floor(moment: datetime) -> datetime:
    return moment.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)


async def aggregate_hourly_stats(db: AsyncSession, now: datetime) -> datetime:
    """Refresh hourly stats from the last aggregated hour (re-doing it and the one before,
    which may have been partial) — or the whole baseline period on first run."""
    latest = await db.scalar(select(func.max(CampaignTrafficStat.hour_bucket)))
    if latest is None:
        since = hour_floor(now) - timedelta(days=settings.ANOMALY_BASELINE_DAYS + 1)
    else:
        since = min(latest, hour_floor(now)) - HOUR
    await db.execute(AGGREGATE_SQL, {"since": since, "until": now})
    return since


async def _store(db: AsyncSession, organization_id, campaign_id, hour: datetime, finding: Finding) -> TrafficAnomaly | None:
    """Upsert one anomaly; returns the row when it is newly HIGH (alert-worthy)."""
    existing = (
        await db.execute(
            select(TrafficAnomaly).where(
                TrafficAnomaly.google_campaign_id == campaign_id,
                TrafficAnomaly.metric == finding.metric,
                TrafficAnomaly.window_start == hour,
            )
        )
    ).scalar_one_or_none()
    was_high = existing is not None and existing.level == "HIGH"
    if existing is None:
        existing = TrafficAnomaly(
            id=uuid.uuid4(), organization_id=organization_id, google_campaign_id=campaign_id,
            window_start=hour, window_end=hour + HOUR, metric=finding.metric,
            observed=finding.observed, expected=finding.expected, score=finding.score, level=finding.level,
        )
        db.add(existing)
    elif finding.score >= existing.score:
        existing.observed, existing.expected = finding.observed, finding.expected
        existing.score, existing.level = finding.score, finding.level
    return existing if existing.level == "HIGH" and not was_high else None


async def detect_anomalies(db: AsyncSession, now: datetime) -> dict[str, int]:
    current_hour = hour_floor(now)
    previous_hour = current_hour - HOUR
    fraction = (now - current_hour) / HOUR
    since = current_hour - timedelta(days=settings.ANOMALY_BASELINE_DAYS + 1)

    rows = (
        await db.execute(select(CampaignTrafficStat).where(CampaignTrafficStat.hour_bucket >= since))
    ).scalars().all()
    by_campaign: dict[uuid.UUID, dict[datetime, HourStat]] = defaultdict(dict)
    orgs: dict[uuid.UUID, uuid.UUID] = {}
    for row in rows:
        by_campaign[row.google_campaign_id][hour_floor(row.hour_bucket)] = HourStat(row.ad_landings, row.median_click_interval_s)
        orgs[row.google_campaign_id] = row.organization_id
    first_hours = dict(
        (
            await db.execute(
                select(CampaignTrafficStat.google_campaign_id, func.min(CampaignTrafficStat.hour_bucket))
                .group_by(CampaignTrafficStat.google_campaign_id)
            )
        ).all()
    )

    metrics = {"campaigns": 0, "cold_start": 0, "anomalies": 0, "alerts": 0}
    for campaign_id, stats in by_campaign.items():
        first_hour = hour_floor(first_hours.get(campaign_id, since))
        hours = [(previous_hour, 1.0)]
        if fraction >= MIN_PARTIAL_HOUR_FRACTION:
            hours.append((current_hour, fraction))
        for hour, hour_fraction in hours:
            findings = detect_hour(hour, stats, first_hour=first_hour, fraction=hour_fraction)
            if findings is None:
                metrics["cold_start"] += 1
                logger.debug("Campaign %s: less than %s days of traffic history, anomaly scoring skipped",
                             campaign_id, settings.ANOMALY_MIN_HISTORY_DAYS)
                break
            metrics["campaigns"] += hour_fraction == 1.0
            for finding in findings:
                metrics["anomalies"] += 1
                alert = await _store(db, orgs[campaign_id], campaign_id, hour, finding)
                if alert is not None:
                    metrics["alerts"] += 1
                    logger.warning("HIGH traffic anomaly on campaign %s: %s %s (expected %s, z=%s)",
                                   campaign_id, finding.metric, finding.observed, finding.expected, finding.score)
                    audit_service.record(
                        db, action=AuditAction.TRAFFIC_ANOMALY_DETECTED, result=AuditResult.SUCCESS,
                        organization_id=orgs[campaign_id], resource_type="campaign", resource_id=campaign_id,
                        details={"metric": finding.metric, "observed": finding.observed, "expected": finding.expected,
                                 "robust_z": finding.score, "level": finding.level,
                                 "window_start": hour, "fraud_signal": finding.metric in FRAUD_METRICS},
                    )
                    # Task 028: spikes → UNUSUAL_TRAFFIC; traffic stopping → TRACKING_FAILURE (tracking removed?).
                    drop = finding.metric == "ad_landings_drop"
                    await alert_service.raise_alert(
                        db, organization_id=orgs[campaign_id],
                        type=alert_service.AlertType.TRACKING_FAILURE if drop else alert_service.AlertType.UNUSUAL_TRAFFIC,
                        severity="warning",
                        dedupe_key=f"{'traffic_drop' if drop else 'unusual_traffic'}:{campaign_id}:{finding.metric}",
                        title="Paid traffic stopped on a campaign" if drop else "Unusual traffic on a campaign",
                        message=(f"{finding.metric}: observed {finding.observed}, usually {finding.expected} "
                                 f"(robust z {finding.score}) in the hour from {hour:%Y-%m-%d %H:%M} UTC."),
                        resource_type="campaign", resource_id=str(campaign_id),
                        details={"metric": finding.metric, "observed": finding.observed, "expected": finding.expected},
                    )
    return metrics


async def run_anomaly_detection(db: AsyncSession, now: datetime | None = None) -> dict[str, int]:
    """The scheduled job: aggregate, then detect. Commits."""
    if not settings.ANOMALY_DETECTION_ENABLED:
        return {}
    now = now or datetime.now(timezone.utc)
    await aggregate_hourly_stats(db, now)
    await db.flush()
    metrics = await detect_anomalies(db, now)
    await db.commit()
    return metrics


def build_stats_upsert(rows: list[dict]):
    """Insert hourly stats directly (backfills, tests)."""
    stmt = pg_insert(CampaignTrafficStat).values(rows)
    return stmt.on_conflict_do_update(
        index_elements=[CampaignTrafficStat.google_campaign_id, CampaignTrafficStat.hour_bucket],
        set_={"ad_landings": stmt.excluded.ad_landings,
              "median_click_interval_s": stmt.excluded.median_click_interval_s},
    )

"""
Alerts (spec §66, §43; task 028).

`raise_alert` opens an alert, or — while one with the same dedupe_key is open or
acknowledged — counts another occurrence. Emails go to the organization's active
owners and admins who keep alert emails on (platform-level alerts: platform
admins), at most once per dedupe key every ALERT_EMAIL_THROTTLE_HOURS. Delivery is
queued as `notifications` rows and sent by the worker (`deliver_pending`), so an
SMTP outage never blocks the caller; failures stay visible on the row.

`resolve` closes alerts whose condition cleared (auto-resolve). `run_checks` is the
scheduled part: tracking failures, fraud spikes, system errors.

Channels: email now; Slack / SMS plug in as more `channel` values in deliver_pending.
"""
from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from typing import Any

from sqlalchemy import and_, func, or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.middleware import SYSTEM_ERROR_KEY
from app.core.redis import get_redis
from app.models import Alert, Notification, Session, User, UserRole, Verdict, Website
from app.services.audit_service import scrub
from app.services.email_service import EmailError, send_email

logger = logging.getLogger(__name__)


class AlertType(StrEnum):
    GOOGLE_API_FAILURE = "GOOGLE_API_FAILURE"
    AUTH_EXPIRED = "AUTH_EXPIRED"
    EXCLUSION_LIMIT_REACHED = "EXCLUSION_LIMIT_REACHED"
    HIGH_FRAUD_SPIKE = "HIGH_FRAUD_SPIKE"
    UNUSUAL_TRAFFIC = "UNUSUAL_TRAFFIC"
    TRACKING_FAILURE = "TRACKING_FAILURE"
    WEBSITE_DISCONNECTED = "WEBSITE_DISCONNECTED"
    SYSTEM_ERROR = "SYSTEM_ERROR"


SEVERITY_RANK = {"info": 0, "warning": 1, "critical": 2}
OPEN_STATUSES = ("open", "acknowledged")


# ---- dedupe keys (one place, so raisers and resolvers agree) ------------------------

def google_failure_key(campaign_id) -> str:
    return f"google_api_failure:{campaign_id}"


def auth_expired_key(connection_id) -> str:
    return f"auth_expired:{connection_id}"


def capacity_key(campaign_id) -> str:
    return f"exclusion_limit:{campaign_id}"


def website_disconnected_key(website_id) -> str:
    return f"website_disconnected:{website_id}"


def tracking_failure_key(website_id) -> str:
    return f"tracking_failure:{website_id}"


def fraud_spike_key(organization_id) -> str:
    return f"fraud_spike:{organization_id}"


SYSTEM_ERROR_DEDUPE = "system_error"


# ---- raise / resolve -----------------------------------------------------------

async def _recipients(db: AsyncSession, organization_id: uuid.UUID | None) -> list[str]:
    query = select(User.email).where(User.is_active.is_(True), User.alert_emails.is_(True))
    if organization_id is None:
        query = query.where(User.is_platform_admin.is_(True))
    else:
        query = query.where(User.organization_id == organization_id, User.role.in_((UserRole.OWNER, UserRole.ADMIN)))
    return list((await db.execute(query)).scalars())


async def raise_alert(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID | None,
    type: AlertType | str,
    severity: str,
    dedupe_key: str,
    title: str,
    message: str,
    resource_type: str | None = None,
    resource_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> Alert | None:
    """Open or bump an alert in the caller's transaction (the caller commits)."""
    if not settings.ALERTS_ENABLED:
        return None
    now = datetime.now(timezone.utc)
    # Serialize concurrent raisers of the same key (two workers failing together).
    await db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:key))"), {"key": dedupe_key})
    alert = (
        await db.execute(
            select(Alert).where(Alert.dedupe_key == dedupe_key, Alert.status.in_(OPEN_STATUSES))
            .order_by(Alert.first_seen_at.desc()).limit(1)
        )
    ).scalar_one_or_none()
    if alert is None:
        alert = Alert(
            id=uuid.uuid4(), organization_id=organization_id, type=str(type), severity=severity, title=title,
            message=message, resource_type=resource_type, resource_id=resource_id,
            details=scrub(details) if details else None, status="open", dedupe_key=dedupe_key,
            occurrences=1, first_seen_at=now, last_seen_at=now,
        )
        db.add(alert)
        logger.warning("ALERT %s [%s] %s", type, severity, title)
    else:
        alert.occurrences += 1
        alert.last_seen_at = now
        alert.message = message
        if details:
            alert.details = scrub(details)
        if SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(alert.severity, 0):
            alert.severity, alert.title = severity, title
    await db.flush()
    await _queue_emails(db, alert, now)
    return alert


async def _queue_emails(db: AsyncSession, alert: Alert, now: datetime) -> None:
    if not settings.ALERT_EMAILS_ENABLED:
        return
    if SEVERITY_RANK.get(alert.severity, 0) < SEVERITY_RANK[settings.ALERT_EMAIL_MIN_SEVERITY]:
        return
    throttle = timedelta(hours=settings.ALERT_EMAIL_THROTTLE_HOURS)
    if alert.last_notified_at is not None and alert.last_notified_at > now - throttle:
        return
    recipients = await _recipients(db, alert.organization_id)
    for recipient in recipients:
        db.add(Notification(alert_id=alert.id, channel="email", recipient=recipient, status="pending"))
    if recipients:
        alert.last_notified_at = now


async def resolve(db: AsyncSession, *, dedupe_key: str) -> int:
    """Auto-resolve: the condition behind `dedupe_key` cleared. Returns alerts resolved."""
    alerts = (
        await db.execute(select(Alert).where(Alert.dedupe_key == dedupe_key, Alert.status.in_(OPEN_STATUSES)))
    ).scalars().all()
    now = datetime.now(timezone.utc)
    for alert in alerts:
        alert.status = "resolved"
        alert.resolved_at = now
        logger.info("Alert resolved: %s (%s)", alert.title, dedupe_key)
    return len(alerts)


# ---- delivery -------------------------------------------------------------------

def _email_body(alert: Alert) -> str:
    link = f"{settings.FRONTEND_APP_URL.rstrip('/')}/alerts"
    return (
        f"{alert.title}\n\n{alert.message}\n\nSeverity: {alert.severity}\n"
        f"First seen: {alert.first_seen_at:%Y-%m-%d %H:%M} UTC, occurrences: {alert.occurrences}\n\n"
        f"Open the dashboard: {link}\n"
    )


async def deliver_pending(db: AsyncSession, *, limit: int = 50) -> dict[str, int]:
    """Send queued notifications (worker). A failure is recorded, never raised."""
    rows = (
        await db.execute(
            select(Notification, Alert).join(Alert, Alert.id == Notification.alert_id)
            .where(Notification.status == "pending").order_by(Notification.created_at).limit(limit)
            .with_for_update(of=Notification, skip_locked=True)
        )
    ).all()
    sent = failed = 0
    for notification, alert in rows:
        try:
            await send_email(notification.recipient, f"[Click Shield] {alert.title}", _email_body(alert))
        except EmailError as exc:
            notification.status, notification.error = "failed", str(exc)[:2000]
            failed += 1
            logger.error("Alert email to %s failed: %s", notification.recipient, exc)
        else:
            notification.status, notification.sent_at = "sent", datetime.now(timezone.utc)
            sent += 1
    await db.commit()
    return {"sent": sent, "failed": failed}


# ---- scheduled checks -------------------------------------------------------------

async def check_tracking_failures(db: AsyncSession, now: datetime) -> int:
    """Verified, active websites that went silent after recent traffic (spec §66 "Tracking failure")."""
    silent_since = now - timedelta(hours=settings.TRACKING_FAILURE_HOURS)
    raised = 0
    websites = (
        await db.execute(select(Website).where(Website.is_active.is_(True), Website.is_verified.is_(True),
                                               Website.last_event_at.is_not(None)))
    ).scalars().all()
    for website in websites:
        key = tracking_failure_key(website.id)
        if website.last_event_at >= silent_since:
            await resolve(db, dedupe_key=key)
        elif website.last_event_at >= now - timedelta(days=7):
            raised += 1
            await raise_alert(
                db, organization_id=website.organization_id, type=AlertType.TRACKING_FAILURE, severity="critical",
                dedupe_key=key, title=f"No tracking data from {website.domain}",
                message=(f"No events from {website.domain} since {website.last_event_at:%Y-%m-%d %H:%M} UTC. "
                         "Was the tracking snippet removed?"),
                resource_type="website", resource_id=str(website.id),
                details={"last_event_at": website.last_event_at},
            )
    return raised


async def check_fraud_spikes(db: AsyncSession, now: datetime) -> int:
    """Per organization: last hour's fraud rate far above its 7-day rate."""
    hour_ago, week_ago = now - timedelta(hours=1), now - timedelta(days=7)
    label = func.coalesce(Session.final_label, Session.verdict)
    rows = (
        await db.execute(
            select(
                Session.organization_id,
                func.count().filter(Session.created_at >= hour_ago).label("recent"),
                func.count().filter(and_(Session.created_at >= hour_ago, label == Verdict.FRAUD)).label("recent_fraud"),
                func.count().filter(Session.created_at < hour_ago).label("baseline"),
                func.count().filter(and_(Session.created_at < hour_ago, label == Verdict.FRAUD)).label("baseline_fraud"),
            )
            .where(Session.created_at >= week_ago)
            .group_by(Session.organization_id)
        )
    ).all()
    raised = 0
    for row in rows:
        key = fraud_spike_key(row.organization_id)
        recent_rate = row.recent_fraud / row.recent if row.recent else 0.0
        baseline_rate = row.baseline_fraud / row.baseline if row.baseline else 0.0
        spiking = (
            row.recent_fraud >= settings.FRAUD_SPIKE_MIN_FRAUD_SESSIONS
            and recent_rate > settings.FRAUD_SPIKE_FACTOR * max(baseline_rate, 0.01)
        )
        if not spiking:
            await resolve(db, dedupe_key=key)
            continue
        raised += 1
        await raise_alert(
            db, organization_id=row.organization_id, type=AlertType.HIGH_FRAUD_SPIKE, severity="warning",
            dedupe_key=key, title="Fraud spike in the last hour",
            message=(f"{row.recent_fraud} of {row.recent} sessions in the last hour were fraud "
                     f"({recent_rate:.0%}, usually {baseline_rate:.0%})."),
            details={"recent": row.recent, "recent_fraud": row.recent_fraud, "baseline_rate": round(baseline_rate, 4)},
        )
    return raised


async def check_system_errors(db: AsyncSession) -> bool:
    minute = int(time.time()) // 60
    buckets = [f"{SYSTEM_ERROR_KEY}{minute - i}" for i in range(max(1, settings.SYSTEM_ERROR_WINDOW_SECONDS // 60))]
    try:
        values = await get_redis().mget(buckets)
    except Exception as exc:
        logger.warning("System error counters unavailable: %s", exc)
        return False
    errors = sum(int(v or 0) for v in values)
    if errors < settings.SYSTEM_ERROR_ALERT_COUNT:
        await resolve(db, dedupe_key=SYSTEM_ERROR_DEDUPE)
        return False
    await raise_alert(
        db, organization_id=None, type=AlertType.SYSTEM_ERROR, severity="critical", dedupe_key=SYSTEM_ERROR_DEDUPE,
        title="API errors above threshold",
        message=f"{errors} server errors in the last {settings.SYSTEM_ERROR_WINDOW_SECONDS // 60} minutes.",
        details={"errors": errors},
    )
    return True


async def run_checks(db: AsyncSession, now: datetime | None = None) -> dict[str, int]:
    """Worker cron (every 15 minutes)."""
    if not settings.ALERTS_ENABLED:
        return {}
    now = now or datetime.now(timezone.utc)
    metrics = {
        "tracking_failures": await check_tracking_failures(db, now),
        "fraud_spikes": await check_fraud_spikes(db, now),
        "system_errors": int(await check_system_errors(db)),
    }
    await db.commit()
    return metrics


async def open_counts(db: AsyncSession, organization_id: uuid.UUID, *, include_platform: bool = False) -> dict[str, int]:
    scope = Alert.organization_id == organization_id
    if include_platform:
        scope = or_(scope, Alert.organization_id.is_(None))
    rows = (
        await db.execute(
            select(Alert.severity, func.count()).where(scope, Alert.status == "open").group_by(Alert.severity)
        )
    ).all()
    counts = {severity: int(count) for severity, count in rows}
    return {"open": sum(counts.values()), "critical": counts.get("critical", 0), "warning": counts.get("warning", 0)}


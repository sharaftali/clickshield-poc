"""
Data retention and anonymization (spec §79, §9; task 029). Runs daily in the worker.

Per organization (overrides on `organizations`, else the settings):
- events older than RAW_EVENTS_RETENTION_DAYS are deleted;
- non-fraud sessions older than SESSIONS_RETENTION_DAYS are anonymized (IPv4 → /24,
  IPv6 → /48; user agent, gclid / gbraid / wbraid, visitor link, device key, raw
  signals and URL query strings removed) — or deleted with SESSIONS_RETENTION_MODE=delete;
- FRAUD sessions (system verdict or client label) get the same treatment after
  FRAUD_SESSION_RETENTION_DAYS — they are fraud intelligence until then;
- visitors left without sessions are deleted.
Platform-wide: audit logs (AUDIT_LOG_RETENTION_DAYS), resolved alerts
(ALERT_RETENTION_DAYS) and IP reputation rows not seen for IP_REPUTATION_RETENTION_DAYS.

Anonymizing keeps country, device, verdict, risk and campaign, so the dashboard
aggregates for past periods don't change. Every statement works in batches of
RETENTION_BATCH_SIZE rows (short transactions, no long locks on /track).
RETENTION_DRY_RUN=true (the default) only counts; each run writes one audit row.
"""
from __future__ import annotations

import logging
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import settings
from app.models import AuditResult, Organization
from app.services import audit_service
from app.services.audit_service import AuditAction

logger = logging.getLogger(__name__)

# NULL-safe: a session without client feedback (final_label NULL) must still count as "not fraud".
IS_FRAUD_SQL = "(s.verdict = 'FRAUD' OR COALESCE(s.final_label = 'FRAUD', false))"
NOT_ANONYMIZED_SQL = "(s.extra_signals IS NULL OR s.extra_signals->>'anonymized' IS NULL)"

ANONYMIZE_SQL = """
UPDATE sessions SET
    ip_address = CASE
        WHEN ip_address IS NULL THEN NULL
        WHEN family(ip_address) = 4 THEN set_masklen(network(set_masklen(ip_address, 24))::inet, 32)
        ELSE set_masklen(network(set_masklen(ip_address, 48))::inet, 128) END,
    user_agent = NULL, gclid = NULL, gbraid = NULL, wbraid = NULL, visitor_id = NULL, device_key = NULL,
    referrer = NULLIF(split_part(referrer, '?', 1), ''),
    landing_page = NULLIF(split_part(landing_page, '?', 1), ''),
    extra_signals = '{"anonymized": true}'::jsonb,
    updated_at = now()
WHERE id = ANY(:ids)
"""


def _cutoffs(org: Organization, now: datetime) -> dict[str, datetime]:
    return {
        "events": now - timedelta(days=org.raw_events_retention_days or settings.RAW_EVENTS_RETENTION_DAYS),
        "sessions": now - timedelta(days=org.sessions_retention_days or settings.SESSIONS_RETENTION_DAYS),
        "fraud_sessions": now - timedelta(days=org.fraud_session_retention_days or settings.FRAUD_SESSION_RETENTION_DAYS),
    }


async def _batched(db: AsyncSession, select_ids_sql: str, apply_sql: str | None, params: dict, *, dry_run: bool) -> int:
    """Run `apply_sql` on batches of ids from `select_ids_sql` (which must take :batch). Dry run: count."""
    if dry_run:
        count_sql = f"SELECT count(*) FROM ({select_ids_sql.replace('LIMIT :batch', '')}) AS candidates"
        return int((await db.execute(text(count_sql), params)).scalar() or 0)
    total = 0
    while True:
        ids = [row[0] for row in (await db.execute(text(select_ids_sql), {**params, "batch": settings.RETENTION_BATCH_SIZE})).all()]
        if not ids:
            break
        await db.execute(text(apply_sql), {"ids": ids})
        await db.commit()  # one short transaction per batch
        total += len(ids)
        if len(ids) < settings.RETENTION_BATCH_SIZE:
            break
    return total


async def anonymize_sessions(db: AsyncSession, session_ids: list[uuid.UUID]) -> int:
    if not session_ids:
        return 0
    await db.execute(text(ANONYMIZE_SQL), {"ids": session_ids})
    return len(session_ids)


async def _organization_pass(db: AsyncSession, org: Organization, now: datetime, dry_run: bool) -> Counter:
    counts: Counter = Counter()
    cut = _cutoffs(org, now)
    org_id = {"org": org.id}

    counts["events_deleted"] += await _batched(
        db, "SELECT id FROM events WHERE organization_id = :org AND created_at < :cutoff LIMIT :batch",
        "DELETE FROM events WHERE id = ANY(:ids)", {**org_id, "cutoff": cut["events"]}, dry_run=dry_run,
    )

    delete_mode = settings.SESSIONS_RETENTION_MODE == "delete"
    apply_sql = "DELETE FROM sessions WHERE id = ANY(:ids)" if delete_mode else ANONYMIZE_SQL
    pending = "" if delete_mode else f" AND {NOT_ANONYMIZED_SQL}"
    verb = "deleted" if delete_mode else "anonymized"
    counts[f"sessions_{verb}"] += await _batched(
        db, f"SELECT s.id FROM sessions s WHERE s.organization_id = :org AND s.created_at < :cutoff "
            f"AND NOT {IS_FRAUD_SQL}{pending} LIMIT :batch",
        apply_sql, {**org_id, "cutoff": cut["sessions"]}, dry_run=dry_run,
    )
    counts[f"fraud_sessions_{verb}"] += await _batched(
        db, f"SELECT s.id FROM sessions s WHERE s.organization_id = :org AND s.created_at < :cutoff "
            f"AND {IS_FRAUD_SQL}{pending} LIMIT :batch",
        apply_sql, {**org_id, "cutoff": cut["fraud_sessions"]}, dry_run=dry_run,
    )
    counts["visitors_deleted"] += await _batched(
        db, "SELECT v.id FROM visitors v WHERE v.organization_id = :org AND v.last_seen_at < :cutoff "
            "AND NOT EXISTS (SELECT 1 FROM sessions s WHERE s.visitor_id = v.id) LIMIT :batch",
        "DELETE FROM visitors WHERE id = ANY(:ids)", {**org_id, "cutoff": cut["sessions"]}, dry_run=dry_run,
    )
    return counts


async def _platform_pass(db: AsyncSession, now: datetime, dry_run: bool) -> Counter:
    counts: Counter = Counter()
    counts["audit_logs_deleted"] += await _batched(
        db, "SELECT id FROM audit_logs WHERE created_at < :cutoff LIMIT :batch",
        "DELETE FROM audit_logs WHERE id = ANY(:ids)",
        {"cutoff": now - timedelta(days=settings.AUDIT_LOG_RETENTION_DAYS)}, dry_run=dry_run,
    )
    counts["alerts_deleted"] += await _batched(
        db, "SELECT id FROM alerts WHERE status = 'resolved' AND resolved_at < :cutoff LIMIT :batch",
        "DELETE FROM alerts WHERE id = ANY(:ids)",
        {"cutoff": now - timedelta(days=settings.ALERT_RETENTION_DAYS)}, dry_run=dry_run,
    )
    # ip_reputation has a composite key: batch on ctid.
    counts["ip_reputation_deleted"] += await _batched(
        db, "SELECT ctid FROM ip_reputation WHERE last_seen < :cutoff LIMIT :batch",
        "DELETE FROM ip_reputation WHERE ctid = ANY(CAST(:ids AS tid[]))",
        {"cutoff": now - timedelta(days=settings.IP_REPUTATION_RETENTION_DAYS)}, dry_run=dry_run,
    )
    return counts


async def run_retention(sessionmaker: async_sessionmaker, now: datetime | None = None, *, dry_run: bool | None = None) -> dict:
    if not settings.RETENTION_ENABLED:
        return {}
    now = now or datetime.now(timezone.utc)
    dry_run = settings.RETENTION_DRY_RUN if dry_run is None else dry_run
    totals: Counter = Counter()
    async with sessionmaker() as db:
        orgs = list((await db.execute(text("SELECT id FROM organizations"))).scalars())
    for org_id in orgs:
        async with sessionmaker() as db:
            org = await db.get(Organization, org_id)
            totals.update(await _organization_pass(db, org, now, dry_run))
    async with sessionmaker() as db:
        totals.update(await _platform_pass(db, now, dry_run))
        audit_service.record(
            db, action=AuditAction.RETENTION_RUN, result=AuditResult.SUCCESS,
            details={"dry_run": dry_run, "mode": settings.SESSIONS_RETENTION_MODE, **dict(totals)},
        )
        await db.commit()
    logger.info("Retention %s: %s", "dry run (nothing changed)" if dry_run else "run", dict(totals))
    return {"dry_run": dry_run, **dict(totals)}

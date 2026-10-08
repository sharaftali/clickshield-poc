"""Spec §75 Test 7 — Google API failure → retry (exponential backoff) + log + alert.

Alerts (task 028) don't exist yet: the final failure is asserted as an ERROR log
line plus a FAILED audit row, and the dashboard-visible exclusion error.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import update

from app.adapters.google_ads_adapter import ErrorCategory, GoogleAdsApiResult
from app.core.config import settings
from app.models import ActionStatus, ExclusionStatus, PlatformAction
from app.services.audit_service import AuditAction


async def test_google_failure_is_retried_with_backoff_then_failed_and_logged(world, caplog, monkeypatch):
    monkeypatch.setattr(settings, "ACTION_QUEUE_MAX_ATTEMPTS", 5)
    monkeypatch.setattr(settings, "ACTION_QUEUE_RETRY_BACKOFF_SECONDS", 30)
    world.google_results = [
        GoogleAdsApiResult(ok=False, retryable=True, error_category=ErrorCategory.TRANSIENT,
                           error_code="internalError.TRANSIENT_ERROR", message="503 Service Unavailable",
                           api_request_id="req-503")
    ]

    session = await world.fraud_session("203.0.113.70")
    from app.services.protection_service import enqueue_exclusion_for_session

    async with world.sessionmaker() as db:
        result = await enqueue_exclusion_for_session(db, session)
        await db.commit()
    assert result.outcome == "queued"

    delays = []
    for attempt in range(1, 6):
        with caplog.at_level(logging.WARNING):
            await world.run_worker()
        [action] = await world.actions()
        assert action.attempts == attempt
        if attempt < 5:
            assert action.status == ActionStatus.RETRYING
            [exclusion] = await world.exclusions()
            assert exclusion.status == ExclusionStatus.PENDING  # not FAILED while retrying
            delays.append((action.scheduled_at - datetime.now(timezone.utc)).total_seconds())
            # Let the backoff elapse.
            async with world.sessionmaker() as db:
                await db.execute(update(PlatformAction).values(scheduled_at=datetime.now(timezone.utc)))
                await db.commit()

    # 30s, 60s, 120s, 240s with ±20% jitter (task 008)
    for delay, base in zip(delays, (30, 60, 120, 240), strict=True):
        assert base * 0.8 - 2 <= delay <= base * 1.2 + 1, delays

    [action] = await world.actions()
    [exclusion] = await world.exclusions()
    assert action.status == ActionStatus.FAILED
    assert exclusion.status == ExclusionStatus.FAILED
    assert "gave up after 5 attempts" in exclusion.last_error
    assert exclusion.api_request_id == "req-503"

    assert len(await world.audit(AuditAction.EXCLUSION_RETRY_SCHEDULED)) == 4
    [failed] = await world.audit(AuditAction.EXCLUSION_FAILED)
    assert failed.result.value == "FAILED" and failed.google_request_id == "req-503"
    assert any(r.levelno == logging.ERROR and "failed permanently" in r.getMessage() for r in caplog.records)
    assert len(world.google_calls) == 5

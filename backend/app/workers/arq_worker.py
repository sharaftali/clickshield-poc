"""
Protection worker (spec §42–43), run with:

    arq app.workers.arq_worker.WorkerSettings

- `process_action(action_id)` — pushed by the API right after a FRAUD verdict
  queues an exclusion (app/core/queue.py).
- `sweep` (cron, every WORKER_SWEEP_SECONDS) — the safety net and scheduler:
  re-queues actions left PROCESSING by a crashed worker, runs due actions and
  scheduled retries (including any whose job push failed), promotes campaign
  overflow queues and expires stale exclusions (task 012).
- `anomaly_detection` (cron, every 5 minutes) — hourly campaign traffic stats and
  statistical anomaly detection (task 022).
- `alert_checks` (cron, every 15 minutes) — tracking failures, fraud spikes, system
  errors (task 028). Alert emails are delivered by the sweep (`deliver_pending`).
- `send_email(to, subject, body)` — one email (invitations, task 030).
- `retention` (cron, daily 03:15 UTC) — data retention / anonymization (task 029).
- The sweep also writes the worker heartbeat read by the health page (task 027).

Health: `arq --check app.workers.arq_worker.WorkerSettings` (docker / ECS).
"""
from __future__ import annotations

import logging
import time
import uuid

from arq import cron

from app.core.config import settings
from app.core.database import AsyncSessionLocal, engine
from app.core.logging_config import setup_logging
from app.core.queue import PROCESS_ACTION_JOB, SEND_EMAIL_JOB, redis_settings
from app.core.redis import get_redis
from app.services import alert_service
from app.services.anomaly_service import run_anomaly_detection
from app.services.email_service import EmailError, send_email as deliver_email
from app.services.health_service import WORKER_HEARTBEAT_KEY
from app.workers.retention import run_retention
from app.services.exclusion_capacity import expire_stale_exclusions, rebalance_all
from app.workers.action_worker import ActionWorker

logger = logging.getLogger(__name__)


async def startup(ctx: dict) -> None:
    setup_logging()
    # The arq CLI installs its own handler on the "arq" logger; without this every
    # arq line would also reach our root handler and be printed twice.
    logging.getLogger("arq").propagate = False
    ctx["action_worker"] = ActionWorker()
    logger.info(
        "Protection worker started (max_jobs=%s, sweep every %ss)",
        settings.ACTION_QUEUE_WORKER_CONCURRENCY,
        settings.WORKER_SWEEP_SECONDS,
    )


async def shutdown(ctx: dict) -> None:
    await engine.dispose()
    logger.info("Protection worker stopped")


async def process_action(ctx: dict, action_id: str) -> str | None:
    async with AsyncSessionLocal() as db:
        outcome = await ctx["action_worker"].process_action_id(db, uuid.UUID(action_id))
    if outcome is None:
        logger.debug("Action %s not due or already handled", action_id)
    return outcome


async def _heartbeat() -> None:
    try:
        await get_redis().set(WORKER_HEARTBEAT_KEY, str(time.time()), ex=settings.HEALTH_WORKER_HEARTBEAT_SECONDS * 2)
    except Exception as exc:
        logger.warning("Could not write the worker heartbeat: %s", exc)


async def sweep(ctx: dict) -> dict:
    await _heartbeat()
    async with AsyncSessionLocal() as db:
        metrics = await ctx["action_worker"].process_pending(db, limit=settings.WORKER_BATCH_SIZE)
    async with AsyncSessionLocal() as db:
        metrics["promoted_or_evicting"] = len(await rebalance_all(db))
    async with AsyncSessionLocal() as db:
        metrics["expiring"] = len(await expire_stale_exclusions(db))
    async with AsyncSessionLocal() as db:
        delivered = await alert_service.deliver_pending(db)
        metrics["emails_sent"], metrics["emails_failed"] = delivered["sent"], delivered["failed"]
    if any(metrics.values()):
        logger.info("Sweep: %s", metrics)
    return metrics


async def anomaly_detection(ctx: dict) -> dict:
    async with AsyncSessionLocal() as db:
        metrics = await run_anomaly_detection(db)
    if metrics.get("anomalies"):
        logger.info("Anomaly detection: %s", metrics)
    return metrics


async def alert_checks(ctx: dict) -> dict:
    async with AsyncSessionLocal() as db:
        return await alert_service.run_checks(db)


async def send_email(ctx: dict, to: str, subject: str, body: str) -> bool:
    try:
        await deliver_email(to, subject, body)
    except EmailError as exc:
        logger.error("Email to %s failed: %s", to, exc)
        return False
    return True


async def retention(ctx: dict) -> dict:
    return await run_retention(AsyncSessionLocal)


def _sweep_seconds() -> set[int]:
    step = max(1, min(60, settings.WORKER_SWEEP_SECONDS))
    return set(range(0, 60, step))


class WorkerSettings:
    functions = [process_action, send_email]
    cron_jobs = [
        cron(sweep, second=_sweep_seconds(), run_at_startup=True, unique=True, timeout=300),
        cron(anomaly_detection, minute=set(range(0, 60, 5)), second=30, unique=True, timeout=600),
        cron(alert_checks, minute={2, 17, 32, 47}, second=0, unique=True, timeout=300),
        cron(retention, hour={3}, minute={15}, second=0, unique=True, timeout=3600),
    ]
    redis_settings = redis_settings()
    on_startup = startup
    on_shutdown = shutdown
    max_jobs = settings.ACTION_QUEUE_WORKER_CONCURRENCY
    job_timeout = 120
    keep_result = 60
    # Google failures are retried by ActionWorker with backoff, not by arq.
    max_tries = 1
    # `arq --check` reads this key; refresh it often enough for container health checks.
    health_check_interval = 30


assert PROCESS_ACTION_JOB == process_action.__name__
assert SEND_EMAIL_JOB == send_email.__name__

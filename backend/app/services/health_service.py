"""
System health (spec §65, task 027). Every component reports HEALTHY / DEGRADED / DOWN.

| Component    | Check                                                                 |
|--------------|-----------------------------------------------------------------------|
| Database     | SELECT 1 and latency                                                  |
| Redis        | PING and latency                                                      |
| Queue        | worker heartbeat, arq queue depth, age of the oldest due action       |
| Tracking API | events in the last 5 minutes vs. the 24-hour average, API error rate  |
| Fraud Engine | p95 scoring latency (this API process)                                |
| Google API   | last successful call, failure rate last hour, connections to re-auth  |
| ML Service   | not deployed in Phase 1                                               |

`/health/live` and `/health/ready` are the unauthenticated load balancer probes.
"""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from fastapi import status
from fastapi.responses import JSONResponse
from sqlalchemy import func, select, text

from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.core.metrics import scoring_latency
from app.core.middleware import request_metrics
from app.core.redis import get_redis
from app.models import ActionStatus, Event, GoogleConnection, PlatformAction

HEALTHY, DEGRADED, DOWN, NOT_DEPLOYED = "HEALTHY", "DEGRADED", "DOWN", "NOT_DEPLOYED"
WORKER_HEARTBEAT_KEY = "worker:heartbeat"
ARQ_QUEUE_KEY = "arq:queue"
SLOW_DB_MS = 500
SLOW_SCORING_MS = 500     # spec §61: score within 500 ms
MAX_ERROR_RATE = 0.05
MAX_GOOGLE_FAILURE_RATE = 0.2


def component(name: str, state: str, detail: str, **metrics) -> dict:
    return {"name": name, "status": state, "detail": detail, "metrics": metrics}


async def liveness() -> dict:
    return {"status": "ok", "version": settings.APP_VERSION}


async def readiness():
    try:
        async with AsyncSessionLocal() as db:
            await db.execute(text("SELECT 1"))
    except Exception as exc:
        return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            content={"status": "not_ready", "database": DOWN, "detail": type(exc).__name__})
    return {"status": "ready", "database": HEALTHY}


async def _database(db) -> dict:
    started = time.perf_counter()
    try:
        await db.execute(text("SELECT 1"))
    except Exception as exc:
        return component("Database", DOWN, f"Database unreachable ({type(exc).__name__})")
    ms = round((time.perf_counter() - started) * 1000, 1)
    return component("Database", DEGRADED if ms > SLOW_DB_MS else HEALTHY, f"SELECT 1 in {ms} ms", latency_ms=ms)


async def _redis() -> dict:
    started = time.perf_counter()
    try:
        await get_redis().ping()
    except Exception as exc:
        return component("Redis", DOWN, f"Redis unreachable ({type(exc).__name__})")
    ms = round((time.perf_counter() - started) * 1000, 1)
    return component("Redis", HEALTHY, f"PING in {ms} ms", latency_ms=ms)


async def _queue(db, redis_ok: bool, now: datetime) -> dict:
    oldest = await db.scalar(
        select(func.min(func.coalesce(PlatformAction.scheduled_at, PlatformAction.created_at))).where(
            PlatformAction.status.in_((ActionStatus.PENDING, ActionStatus.RETRYING)),
            func.coalesce(PlatformAction.scheduled_at, PlatformAction.created_at) <= now,
        )
    )
    oldest_age = int((now - oldest).total_seconds()) if oldest else 0
    if not redis_ok:
        return component("Queue", DOWN, "Redis is down: jobs can't be pushed; the worker can't run.",
                         oldest_due_action_seconds=oldest_age)
    try:
        redis = get_redis()
        heartbeat = await redis.get(WORKER_HEARTBEAT_KEY)
        depth = int(await redis.zcard(ARQ_QUEUE_KEY))
    except Exception as exc:
        return component("Queue", DOWN, f"Queue unreadable ({type(exc).__name__})")
    beat_age = int(now.timestamp() - float(heartbeat)) if heartbeat else None
    metrics = {"queued_jobs": depth, "oldest_due_action_seconds": oldest_age, "worker_heartbeat_seconds": beat_age}
    if beat_age is None or beat_age > settings.HEALTH_WORKER_HEARTBEAT_SECONDS:
        return component("Queue", DOWN, "No worker heartbeat: the protection worker isn't running.", **metrics)
    if oldest_age > settings.HEALTH_QUEUE_OLDEST_PENDING_SECONDS:
        return component("Queue", DEGRADED, f"The oldest due protection action has waited {oldest_age}s.", **metrics)
    return component("Queue", HEALTHY, f"Worker alive, {depth} queued job(s).", **metrics)


async def _tracking(db, now: datetime) -> dict:
    recent = int(await db.scalar(select(func.count()).select_from(Event).where(Event.created_at >= now - timedelta(minutes=5))) or 0)
    day = int(await db.scalar(select(func.count()).select_from(Event).where(Event.created_at >= now - timedelta(hours=24))) or 0)
    expected = day / 288  # 5-minute slots in a day
    errors = request_metrics.snapshot()
    metrics = {"events_5m": recent, "expected_5m": round(expected, 1), **{f"api_{k}": v for k, v in errors.items()}}
    if errors["error_rate"] > MAX_ERROR_RATE and errors["requests"] >= 20:
        return component("Tracking API", DEGRADED, f"{errors['error_rate']:.0%} of API requests failed recently.", **metrics)
    if expected >= 10 and recent < 0.1 * expected:
        return component("Tracking API", DEGRADED, "Far fewer events than usual in the last 5 minutes.", **metrics)
    return component("Tracking API", HEALTHY, f"{recent} events in the last 5 minutes.", **metrics)


def _engine() -> dict:
    stats = scoring_latency.snapshot()
    if not stats["count"]:
        return component("Fraud Engine", HEALTHY, "No scoring in this API process recently.", **stats)
    state = DEGRADED if stats["p95_ms"] > SLOW_SCORING_MS else HEALTHY
    return component("Fraud Engine", state, f"p95 scoring {stats['p95_ms']} ms over {stats['count']} sessions.", **stats)


async def _google(db, now: datetime) -> dict:
    last_ok = await db.scalar(select(func.max(PlatformAction.completed_at)).where(PlatformAction.status == ActionStatus.SUCCESS))
    hour = now - timedelta(hours=1)
    done = (await db.execute(
        select(PlatformAction.status, func.count()).where(
            PlatformAction.completed_at >= hour, PlatformAction.status.in_((ActionStatus.SUCCESS, ActionStatus.FAILED))
        ).group_by(PlatformAction.status)
    )).all()
    counts = {s: int(c) for s, c in done}
    finished = counts.get(ActionStatus.SUCCESS, 0) + counts.get(ActionStatus.FAILED, 0)
    failure_rate = round(counts.get(ActionStatus.FAILED, 0) / finished, 3) if finished else 0.0
    reauth = int(await db.scalar(select(func.count()).select_from(GoogleConnection).where(
        GoogleConnection.is_active.is_(True), GoogleConnection.needs_reauth.is_(True))) or 0)
    metrics = {"last_success_at": last_ok.isoformat() if last_ok else None, "failure_rate_1h": failure_rate,
               "actions_1h": finished, "connections_needing_reauth": reauth}
    problems = []
    if reauth:
        problems.append(f"{reauth} connection{'s' if reauth > 1 else ''} need{'' if reauth > 1 else 's'} re-auth")
    if finished >= 5 and failure_rate > MAX_GOOGLE_FAILURE_RATE:
        problems.append(f"{failure_rate:.0%} of Google calls failed in the last hour")
    if problems:
        return component("Google API", DEGRADED, "; ".join(problems) + ".", **metrics)
    return component("Google API", HEALTHY, "No failures in the last hour." if finished else "No Google calls in the last hour.", **metrics)


async def system_health(db) -> dict:
    """All components, using the caller's database session."""
    now = datetime.now(timezone.utc)
    redis = await _redis()
    database = await _database(db)
    if database["status"] == DOWN:
        components = [database, component("Tracking API", DOWN, "Needs the database."), _engine(), redis,
                      component("Queue", DOWN, "Needs the database."), component("Google API", DOWN, "Needs the database.")]
    else:
        components = [database, await _tracking(db, now), _engine(), redis,
                      await _queue(db, redis["status"] != DOWN, now), await _google(db, now)]
    components.append(component("ML Service", NOT_DEPLOYED, "Not part of Phase 1 (spec §29)."))
    states = {c["status"] for c in components}
    overall = DOWN if DOWN in states else DEGRADED if DEGRADED in states else HEALTHY
    return {"status": overall, "checked_at": now.isoformat(), "components": components}

"""
arq job queue client used by the API (spec §42: detection is real-time, the
Google action is asynchronous).

Pushing a job is an optimisation: the worker also sweeps the platform_actions
table every WORKER_SWEEP_SECONDS, so an action whose push failed (Redis down)
is still processed. Pushes must therefore never fail the caller.
"""
from __future__ import annotations

import dataclasses
import logging
import uuid
from collections.abc import Iterable

from arq.connections import ArqRedis, RedisSettings, create_pool

from app.core.config import settings

logger = logging.getLogger(__name__)

PROCESS_ACTION_JOB = "process_action"

_pool: ArqRedis | None = None


def redis_settings() -> RedisSettings:
    # Fail fast: a tracking request must never wait seconds for an unreachable Redis.
    return dataclasses.replace(
        RedisSettings.from_dsn(settings.REDIS_URL), conn_timeout=1, conn_retries=0
    )


async def _get_pool() -> ArqRedis:
    global _pool
    if _pool is None:
        _pool = await create_pool(redis_settings())
    return _pool


async def enqueue_actions(action_ids: Iterable[uuid.UUID]) -> int:
    """Push process_action jobs after the actions are committed. Returns jobs pushed."""
    ids = [str(action_id) for action_id in action_ids]
    if not ids:
        return 0
    pushed = 0
    try:
        pool = await _get_pool()
        for action_id in ids:
            # Job id = action id: a second push for the same action is a no-op.
            await pool.enqueue_job(PROCESS_ACTION_JOB, action_id, _job_id=f"action:{action_id}")
            pushed += 1
    except Exception as exc:
        logger.warning(
            "Could not push %d protection job(s) to Redis (%s); the worker sweep will pick them up.",
            len(ids) - pushed, exc,
        )
        await close_pool()
    return pushed


async def close_pool() -> None:
    global _pool
    if _pool is not None:
        pool, _pool = _pool, None
        try:
            await pool.aclose()
        except Exception:  # already broken
            pass

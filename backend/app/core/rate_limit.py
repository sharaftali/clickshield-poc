"""
Redis fixed-window rate limits (spec §62, task 031).

`hit(key, limit, window)` counts one request; when the count passes `limit` the
caller answers 429 with Retry-After. Every limiter fails open: when Redis is
unreachable the request is allowed and a warning logged (at most once a minute),
so tracking never breaks because the limiter is down.

Requests refused on /track are fraud data (spec §20 "excessive request rates"):
`note_rate_limited(ip)` keeps an hourly counter that scoring reads.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass

from fastapi import HTTPException, status

from app.core.config import settings
from app.core.redis import get_redis

logger = logging.getLogger(__name__)

RATE_LIMITED_KEY = "ratelimited:track:"
RATE_LIMITED_WINDOW_SECONDS = 3600
_last_warning = 0.0


@dataclass(frozen=True)
class RateResult:
    allowed: bool
    count: int
    retry_after: int


def _warn(exc: Exception) -> None:
    global _last_warning
    if time.monotonic() - _last_warning > 60:
        _last_warning = time.monotonic()
        logger.warning("Rate limiter unavailable, allowing requests (fail open): %s", exc)


async def hit(key: str, limit: int, window_seconds: int, *, cost: int = 1) -> RateResult:
    if not settings.RATE_LIMIT_ENABLED or limit <= 0:
        return RateResult(True, 0, 0)
    now = int(time.time())
    window = now // window_seconds
    redis_key = f"rl:{key}:{window}"
    try:
        redis = get_redis()
        count = int(await redis.incrby(redis_key, cost))
        if count == cost:
            await redis.expire(redis_key, window_seconds + 1)
    except Exception as exc:
        _warn(exc)
        return RateResult(True, 0, 0)
    retry_after = max(1, (window + 1) * window_seconds - now)
    return RateResult(count <= limit, count, retry_after)


async def peek(key: str, window_seconds: int) -> int:
    """Current count of a window without counting (0 when Redis is down)."""
    if not settings.RATE_LIMIT_ENABLED:
        return 0
    window = int(time.time()) // window_seconds
    try:
        return int(await get_redis().get(f"rl:{key}:{window}") or 0)
    except Exception as exc:
        _warn(exc)
        return 0


def too_many(result: RateResult, detail: str = "Too many requests. Please slow down.") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail=detail,
        headers={"Retry-After": str(result.retry_after)},
    )


async def enforce(key: str, limit: int, window_seconds: int, detail: str | None = None) -> None:
    result = await hit(key, limit, window_seconds)
    if not result.allowed:
        raise too_many(result, detail or "Too many requests. Please slow down.")


async def note_rate_limited(ip: str) -> None:
    try:
        redis = get_redis()
        key = RATE_LIMITED_KEY + ip
        await redis.incr(key)
        await redis.expire(key, RATE_LIMITED_WINDOW_SECONDS)
    except Exception as exc:
        _warn(exc)


async def recent_rate_limited(ip: str | None) -> int:
    if not ip:
        return 0
    try:
        return int(await get_redis().get(RATE_LIMITED_KEY + ip) or 0)
    except Exception as exc:
        _warn(exc)
        return 0

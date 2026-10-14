"""
Shared async Redis client (OAuth state, rate limits, heartbeats, alert throttling).

`get_redis()` returns one lazily created client per process. Callers decide what a
Redis failure means: OAuth refuses (task 033), rate limits fail open (task 031).
"""
from __future__ import annotations

import redis.asyncio as aioredis

from app.core.config import settings

_client: aioredis.Redis | None = None


def get_redis() -> aioredis.Redis:
    global _client
    if _client is None:
        _client = aioredis.from_url(
            settings.REDIS_URL,
            decode_responses=True,
            socket_connect_timeout=1,
            socket_timeout=1,
        )
    return _client


async def close_redis() -> None:
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None

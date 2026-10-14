"""
HTTP middleware (task 031: CORS split, security headers; task 027/028: error metrics).

- `PathCORSMiddleware`: the public tracking endpoints accept any origin without
  credentials (the handler checks the Origin against the website, task 023); the
  dashboard API only accepts API_CORS_ORIGINS. A wildcard can never leak from the
  tracking policy to the authenticated API.
- `SecurityHeadersMiddleware`: nosniff, referrer policy, frame denial, HSTS on HTTPS.
- `ErrorMetricsMiddleware`: counts requests and 5xx / unhandled errors for the health
  page (in process) and SYSTEM_ERROR alerts (Redis, shared by all processes).
"""
from __future__ import annotations

import logging
import time
from collections import deque

from starlette.middleware.cors import CORSMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.client_ip import ClientIPError, parse_ip, parse_trusted_networks
from app.core.config import settings
from app.core.redis import get_redis

logger = logging.getLogger(__name__)

TRACKING_PATHS = ("/api/v1/track", "/api/v1/tracking.js", "/track.js")
SYSTEM_ERROR_KEY = "system_errors:"


def is_tracking_path(path: str) -> bool:
    return any(path == prefix or path.startswith(prefix + "/") for prefix in TRACKING_PATHS)


def _split(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


class PathCORSMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app
        self.tracking = CORSMiddleware(
            app,
            allow_origins=_split(settings.TRACKING_CORS_ORIGINS) or ["*"],
            allow_credentials=False,
            allow_methods=["GET", "POST", "OPTIONS"],
            allow_headers=["Content-Type"],
            max_age=86400,
        )
        api_origins = [origin for origin in _split(settings.API_CORS_ORIGINS) if origin != "*"]
        self.api = CORSMiddleware(
            app,
            allow_origins=api_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type"],
            max_age=600,
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        handler = self.tracking if is_tracking_path(scope.get("path", "")) else self.api
        await handler(scope, receive, send)


def _is_https(scope: Scope) -> bool:
    if scope.get("scheme") == "https":
        return True
    headers = dict(scope.get("headers") or [])
    if headers.get(b"x-forwarded-proto", b"").decode("latin-1").split(",")[0].strip().lower() != "https":
        return False
    # Only a trusted proxy may tell us the original scheme (same rule as X-Forwarded-For, task 001).
    client = scope.get("client")
    if not client:
        return False
    try:
        peer = parse_ip(client[0])
    except ClientIPError:
        return False
    return any(peer.version == net.version and peer in net for net in parse_trusted_networks(settings.TRUSTED_PROXY_CIDRS))


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        https = _is_https(scope)

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers") or [])
                present = {name.lower() for name, _ in headers}
                extra = [
                    (b"x-content-type-options", b"nosniff"),
                    (b"referrer-policy", b"strict-origin-when-cross-origin"),
                    (b"x-frame-options", b"DENY"),
                ]
                if https:
                    extra.append((b"strict-transport-security", f"max-age={settings.HSTS_MAX_AGE_SECONDS}; includeSubDomains".encode()))
                headers += [(name, value) for name, value in extra if name not in present]
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_headers)


class RequestMetrics:
    """In-process request / error counts over the last few minutes (health page, task 027)."""

    def __init__(self, window_seconds: int = 300) -> None:
        self.window = window_seconds
        self.requests: deque[float] = deque()
        self.errors: deque[float] = deque()

    def _trim(self, now: float) -> None:
        for queue in (self.requests, self.errors):
            while queue and queue[0] < now - self.window:
                queue.popleft()

    def record(self, *, error: bool) -> None:
        now = time.monotonic()
        self.requests.append(now)
        if error:
            self.errors.append(now)
        self._trim(now)

    def snapshot(self) -> dict:
        self._trim(time.monotonic())
        total = len(self.requests)
        return {"requests": total, "errors": len(self.errors),
                "error_rate": round(len(self.errors) / total, 4) if total else 0.0,
                "window_seconds": self.window}


request_metrics = RequestMetrics()


async def count_system_error() -> None:
    """Shared counter for SYSTEM_ERROR alerts (read by the alert checks, task 028)."""
    try:
        redis = get_redis()
        key = f"{SYSTEM_ERROR_KEY}{int(time.time()) // 60}"
        await redis.incr(key)
        await redis.expire(key, settings.SYSTEM_ERROR_WINDOW_SECONDS + 120)
    except Exception:  # metrics must never break a request
        pass


class ErrorMetricsMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        status_code = 500

        async def capture(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, capture)
        except Exception:
            request_metrics.record(error=True)
            await count_system_error()
            raise
        request_metrics.record(error=status_code >= 500)
        if status_code >= 500:
            await count_system_error()

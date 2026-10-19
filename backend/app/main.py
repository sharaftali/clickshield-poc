from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api import (
    admin,
    alerts,
    analytics,
    audit,
    auth,
    campaigns,
    dashboard,
    google,
    organization,
    privacy,
    protection,
    rules,
    tracking,
    users,
    websites,
)
from app.core.config import STARTUP_WARNINGS, settings
from app.core.database import AsyncSessionLocal
from app.core.logging_config import setup_logging
from app.core.middleware import ErrorMetricsMiddleware, PathCORSMiddleware, SecurityHeadersMiddleware
from app.core.queue import close_pool
from app.core.redis import close_redis
from app.core.seed import seed_defaults
from app.services.health_service import liveness, readiness

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ---- Startup ----
    setup_logging()
    logger.info("%s v%s starting up (ENVIRONMENT=%s)", settings.APP_NAME, settings.APP_VERSION, settings.ENVIRONMENT)
    for warning in STARTUP_WARNINGS:
        logger.warning("SECURITY: %s", warning)

    if settings.is_development:  # task 032: never seed outside development
        async with AsyncSessionLocal() as db:
            try:
                await seed_defaults(db)
            except Exception:
                logger.exception("Seeding failed — continuing without seed")

    yield

    # ---- Shutdown ----
    await close_pool()
    await close_redis()
    logger.info("%s shutting down", settings.APP_NAME)


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    debug=settings.DEBUG,
    lifespan=lifespan,
    # The interactive API map is a development aid; staging / production don't publish it (spec §62).
    docs_url="/docs" if settings.is_development else None,
    redoc_url="/redoc" if settings.is_development else None,
    openapi_url="/openapi.json" if settings.is_development else None,
)

# The last middleware added is the outermost: error metrics wrap CORS and headers.
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(PathCORSMiddleware)
app.add_middleware(ErrorMetricsMiddleware)

for module in (auth, organization, tracking, google, protection, dashboard, audit, rules, users,
               websites, analytics, campaigns, alerts, privacy, admin):
    app.include_router(module.router)
app.include_router(tracking.public_router)


@app.get("/health")
async def health():
    return {"status": "ok", "version": settings.APP_VERSION}


@app.get("/health/live")
async def health_live():
    """The process is up (load balancer / ECS liveness)."""
    return await liveness()


@app.get("/health/ready")
async def health_ready():
    """Ready for traffic: the database answers (readiness; Redis is optional, it fails open)."""
    return await readiness()

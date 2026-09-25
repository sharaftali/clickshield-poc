from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import auth, dashboard, google, organization, protection, tracking
from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.core.logging_config import setup_logging
from app.core.seed import seed_defaults

logger = logging.getLogger(__name__)


def _build_cors_origins() -> list[str]:
    raw_values = [
        *settings.TRACKING_CORS_ORIGINS.split(","),
        *settings.API_CORS_ORIGINS.split(","),
    ]
    cleaned = [origin.strip() for origin in raw_values if origin.strip()]
    if "*" in cleaned:
        return ["*"]
    return list(dict.fromkeys(cleaned))


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ---- Startup ----
    setup_logging()
    logger.info("%s v%s starting up", settings.APP_NAME, settings.APP_VERSION)

    async with AsyncSessionLocal() as db:
        try:
            await seed_defaults(db)
        except Exception:
            logger.exception("Seeding failed — continuing without seed")

    yield

    # ---- Shutdown ----
    logger.info("%s shutting down", settings.APP_NAME)


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    debug=settings.DEBUG,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_build_cors_origins(),
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(organization.router)
app.include_router(tracking.router)
app.include_router(google.router)
app.include_router(protection.router)
app.include_router(dashboard.router)


@app.get("/health")
async def health():
    return {"status": "ok", "version": settings.APP_VERSION}

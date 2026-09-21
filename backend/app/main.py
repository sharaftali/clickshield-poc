from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import tracking, google
from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.core.logging_config import setup_logging
from app.core.seed import seed_defaults

logger = logging.getLogger(__name__)


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
    allow_origins=settings.TRACKING_CORS_ORIGINS.split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(tracking.router)
app.include_router(google.router)


@app.get("/health")
async def health():
    return {"status": "ok", "version": settings.APP_VERSION}

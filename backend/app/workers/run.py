"""
Standalone protection worker:  python -m app.workers.run

Polls platform_actions and processes due ones (new actions and scheduled
retries, spec §42–43) outside the API process. Runs as its own container
(docker compose `worker` service / ECS service).

Stops cleanly on SIGTERM/SIGINT after the current pass. Touches a heartbeat
file every loop so the container health check can detect a hung worker.

Task 010 will replace polling with arq jobs; this loop stays as the fallback sweep.
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
from pathlib import Path

from app.core.config import settings
from app.core.database import AsyncSessionLocal, engine
from app.core.logging_config import setup_logging
from app.workers.action_worker import ActionWorker

logger = logging.getLogger(__name__)

HEARTBEAT_FILE = Path("/tmp/clickshield-worker-heartbeat")


def _install_signal_handlers(stop: asyncio.Event) -> None:
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        with contextlib.suppress(NotImplementedError):  # not available on Windows
            loop.add_signal_handler(sig, stop.set)


async def run_forever(stop: asyncio.Event) -> None:
    worker = ActionWorker()
    logger.info(
        "Protection worker started (poll=%ss, batch=%s)",
        settings.WORKER_POLL_SECONDS,
        settings.WORKER_BATCH_SIZE,
    )
    while not stop.is_set():
        try:
            async with AsyncSessionLocal() as db:
                metrics = await worker.process_pending(db, limit=settings.WORKER_BATCH_SIZE)
            if metrics["processed"]:
                logger.info("Worker pass: %s", metrics)
        except Exception:
            # Database down, migrations not applied yet, ... — log and try again next pass.
            logger.exception("Worker pass failed")

        with contextlib.suppress(OSError):
            HEARTBEAT_FILE.touch()

        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(stop.wait(), timeout=settings.WORKER_POLL_SECONDS)

    logger.info("Protection worker stopped")


async def main() -> None:
    setup_logging()
    stop = asyncio.Event()
    _install_signal_handlers(stop)
    try:
        await run_forever(stop)
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())

"""The standalone worker loop: processes passes, survives errors, writes a heartbeat, stops on signal."""
from __future__ import annotations

import asyncio
import contextlib

from app.core.config import settings
from app.workers import run as runner


class FakeSession:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


async def test_worker_loop_survives_failures_and_stops(monkeypatch, tmp_path):
    heartbeat = tmp_path / "heartbeat"
    passes = []
    stop = asyncio.Event()

    class FakeWorker:
        async def process_pending(self, db, *, limit):
            passes.append(limit)
            if len(passes) == 1:
                raise RuntimeError("database not ready")  # must not kill the loop
            if len(passes) == 3:
                stop.set()
            return {"processed": 1, "successful": 1, "failed": 0, "skipped": 0, "retrying": 0}

    monkeypatch.setattr(runner, "ActionWorker", FakeWorker)
    monkeypatch.setattr(runner, "AsyncSessionLocal", FakeSession)
    monkeypatch.setattr(runner, "HEARTBEAT_FILE", heartbeat)
    monkeypatch.setattr(settings, "WORKER_POLL_SECONDS", 0.01)
    monkeypatch.setattr(settings, "WORKER_BATCH_SIZE", 7)

    await asyncio.wait_for(runner.run_forever(stop), timeout=5)

    assert passes == [7, 7, 7]
    assert heartbeat.exists()


async def test_worker_loop_wakes_immediately_on_stop(monkeypatch, tmp_path):
    stop = asyncio.Event()

    class IdleWorker:
        async def process_pending(self, db, *, limit):
            return {"processed": 0, "successful": 0, "failed": 0, "skipped": 0, "retrying": 0}

    monkeypatch.setattr(runner, "ActionWorker", IdleWorker)
    monkeypatch.setattr(runner, "AsyncSessionLocal", FakeSession)
    monkeypatch.setattr(runner, "HEARTBEAT_FILE", tmp_path / "hb")
    monkeypatch.setattr(settings, "WORKER_POLL_SECONDS", 3600)  # would sleep an hour

    task = asyncio.create_task(runner.run_forever(stop))
    await asyncio.sleep(0.05)
    stop.set()  # what SIGTERM does
    await asyncio.wait_for(task, timeout=2)
    with contextlib.suppress(Exception):
        task.result()

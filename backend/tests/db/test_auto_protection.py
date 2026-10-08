"""Task 010: FRAUD verdicts are protected automatically by the worker — no UI involved."""
from __future__ import annotations

from app.core import queue as queue_module
from app.core.config import settings
from app.models import ActionStatus, ExclusionStatus, Verdict
from app.workers import arq_worker


async def make_fraud(world, ip: str) -> dict:
    world.ip_intel[ip] = {"is_vpn": True}
    await world.seed_history(ip, Verdict.FRAUD, count=5, hours_ago=6)
    responses = [await world.visit(ip, visitor=f"v_{ip}", events=["page_view"], duration=0.5) for _ in range(10)]
    assert responses[-1]["verdict"] == Verdict.FRAUD.value
    return responses[-1]


async def test_fraud_visit_queues_exactly_one_exclusion_and_pushes_a_job(world):
    await make_fraud(world, "198.51.100.10")
    # More fraud from the same IP after it's queued: evidence refresh only (spec §41).
    for _ in range(3):
        await world.visit("198.51.100.10", visitor="v_198.51.100.10", events=["page_view"], duration=0.5)

    exclusions = await world.exclusions("198.51.100.10")
    actions = await world.actions()
    assert len(exclusions) == 1 and len(actions) == 1
    assert world.pushed_jobs == [actions[0].id]
    assert exclusions[0].last_fraud_at is not None


async def test_auto_protection_switch_off_means_detect_only(world, monkeypatch):
    monkeypatch.setattr(settings, "AUTO_PROTECTION_ENABLED", False)
    await make_fraud(world, "198.51.100.11")
    assert await world.exclusions() == [] and await world.actions() == []


async def test_redis_down_push_does_not_fail_and_sweep_processes_the_action(world, monkeypatch):
    # Real enqueue_actions against a Redis port nobody listens on.
    monkeypatch.setattr(settings, "REDIS_URL", "redis://127.0.0.1:6390/0")
    await queue_module.close_pool()
    pushed = await queue_module.enqueue_actions([__import__("uuid").uuid4()])
    assert pushed == 0  # logged, swallowed, never raised

    await make_fraud(world, "198.51.100.12")
    [action] = await world.actions()
    assert action.status == ActionStatus.PENDING

    # The arq sweep (cron) picks it up from the table.
    monkeypatch.setattr(arq_worker, "AsyncSessionLocal", world.sessionmaker)
    ctx = {"action_worker": arq_worker.ActionWorker()}
    metrics = await arq_worker.sweep(ctx)
    assert metrics["successful"] == 1
    [exclusion] = await world.exclusions("198.51.100.12")
    assert exclusion.status == ExclusionStatus.ACTIVE


async def test_process_action_job_handles_its_action_once(world, monkeypatch):
    await make_fraud(world, "198.51.100.13")
    [action] = await world.actions()

    monkeypatch.setattr(arq_worker, "AsyncSessionLocal", world.sessionmaker)
    ctx = {"action_worker": arq_worker.ActionWorker()}
    assert await arq_worker.process_action(ctx, str(action.id)) == "successful"
    # A duplicate job (or the sweep racing it) finds nothing to do.
    assert await arq_worker.process_action(ctx, str(action.id)) is None
    assert len(world.google_calls) == 1


async def test_worker_down_then_up_processes_backlog(world, monkeypatch):
    for ip in ("198.51.100.14", "198.51.100.15"):
        await make_fraud(world, ip)  # worker "down": nothing processes these
    assert {a.status for a in await world.actions()} == {ActionStatus.PENDING}

    monkeypatch.setattr(arq_worker, "AsyncSessionLocal", world.sessionmaker)
    metrics = await arq_worker.sweep({"action_worker": arq_worker.ActionWorker()})
    assert metrics["successful"] == 2
    assert {e.status for e in await world.exclusions()} == {ExclusionStatus.ACTIVE}


async def test_no_google_call_happens_inside_the_tracking_request(world):
    await make_fraud(world, "198.51.100.16")
    assert world.google_calls == []  # only the worker talks to Google


async def test_queue_status_endpoint_reports_the_pipeline(world):
    await make_fraud(world, "198.51.100.17")
    async with world.api() as client:
        before = (await client.get("/api/v1/protection/queue")).json()
        await world.run_worker()
        after = (await client.get("/api/v1/protection/queue")).json()
        actions = (await client.get("/api/v1/protection/actions")).json()
    assert before["pending"] == 1 and before["active_exclusions"] == 0
    assert after["succeeded"] == 1 and after["active_exclusions"] == 1
    assert before["auto_protection_enabled"] is True
    assert actions[0]["ip_address"] == "198.51.100.17" and actions[0]["status"] == "SUCCESS"


async def test_manual_reconcile_and_dry_run_endpoints_are_gone(world):
    async with world.api() as client:
        assert (await client.post("/api/v1/protection/reconcile")).status_code in (404, 405)
        assert (await client.post("/api/v1/protection/dry-run")).status_code in (404, 405)

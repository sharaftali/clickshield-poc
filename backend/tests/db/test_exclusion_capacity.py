"""Task 012: per-campaign IP exclusion limit — capacity, overflow, eviction, re-exclusion."""
from __future__ import annotations

import asyncio

from sqlalchemy import select, update

from app.models import ActionType, ExclusionStatus, GoogleCampaign
from app.services.audit_service import AuditAction
from app.services.protection_service import enqueue_exclusion_for_session


async def enqueue(world, ip: str, *, confidence: int = 95, risk: int = 92):
    session = await world.fraud_session(ip, risk=risk, confidence=confidence)
    async with world.sessionmaker() as db:
        result = await enqueue_exclusion_for_session(db, session)
        await db.commit()
    return result


async def holding_slots(world) -> list:
    return [e for e in await world.exclusions()
            if e.status in (ExclusionStatus.PENDING, ExclusionStatus.SUBMITTED, ExclusionStatus.ACTIVE)]


async def test_full_campaign_puts_weaker_candidate_in_overflow_without_google_call(world, exclusion_limit, active_exclusions):
    exclusion_limit(5)
    await active_exclusions(90, 91, 92, 93, 94)

    result = await enqueue(world, "203.0.113.80", confidence=85, risk=85)

    assert result.outcome == "overflow" and result.actions == []
    assert result.exclusion.status == ExclusionStatus.SKIPPED and result.exclusion.overflow is True
    assert "limit reached (5/5)" in result.exclusion.last_error
    assert await world.actions() == []
    assert len(await world.audit(AuditAction.EXCLUSION_LIMIT_REACHED)) == 1


async def test_stronger_candidate_evicts_weakest_then_takes_the_slot(world, exclusion_limit, active_exclusions):
    exclusion_limit(5)
    seeded = await active_exclusions(80, 91, 92, 93, 94)
    weakest = seeded[0]

    result = await enqueue(world, "203.0.113.81", confidence=99, risk=99)

    # 1) Only the REMOVE is queued; the candidate waits, so Google never holds 6.
    assert result.outcome == "overflow"
    [remove] = await world.actions()
    assert remove.action_type == ActionType.REMOVE_IP_EXCLUSION and remove.reference_id == weakest.id
    assert len(await holding_slots(world)) == 5

    # 2) One worker pass: REMOVE the weakest, promote the freed slot, ADD the candidate
    #    (the promoted action is due immediately, so the same pass picks it up).
    await world.run_worker()
    by_ip = {str(e.ip_address): e for e in await world.exclusions()}
    assert by_ip[str(weakest.ip_address)].status == ExclusionStatus.REMOVED
    assert by_ip["203.0.113.81"].status == ExclusionStatus.ACTIVE
    assert [op for op, *_ in world.google_calls] == ["remove", "create"]  # removal strictly first
    assert len(await holding_slots(world)) == 5
    assert len(await world.audit(AuditAction.EXCLUSION_EVICTED)) == 1
    assert len(await world.audit(AuditAction.EXCLUSION_PROMOTED)) == 1


async def test_equal_priority_candidate_does_not_churn(world, exclusion_limit, active_exclusions):
    exclusion_limit(3)
    await active_exclusions(90, 90, 90)
    result = await enqueue(world, "203.0.113.82", confidence=90, risk=90)
    assert result.outcome == "overflow" and result.actions == []


async def test_removing_an_exclusion_promotes_best_overflow_entry(world, exclusion_limit, active_exclusions):
    exclusion_limit(2)
    seeded = await active_exclusions(95, 96)
    await enqueue(world, "203.0.113.83", confidence=82, risk=82)
    await enqueue(world, "203.0.113.84", confidence=88, risk=88)  # best in the queue

    async with world.sessionmaker() as db:  # the advertiser's IP is removed by any means
        from app.models import Exclusion

        await db.execute(update(Exclusion).where(Exclusion.id == seeded[0].id).values(status=ExclusionStatus.REMOVED))
        await db.commit()
    await world.run_worker()  # nothing queued yet; the sweep's rebalance does the promotion

    from app.services.exclusion_capacity import rebalance_all

    async with world.sessionmaker() as db:
        promoted = await rebalance_all(db)
    assert len(promoted) == 1
    statuses = {str(e.ip_address): e.status for e in await world.exclusions()}
    assert statuses["203.0.113.84"] == ExclusionStatus.PENDING
    assert statuses["203.0.113.83"] == ExclusionStatus.SKIPPED


async def test_manual_advertiser_exclusions_count_toward_the_limit(world, exclusion_limit):
    exclusion_limit(3)
    async with world.sessionmaker() as db:
        await db.execute(update(GoogleCampaign).values(external_exclusion_count=2))
        await db.commit()

    first = await enqueue(world, "203.0.113.85")
    second = await enqueue(world, "203.0.113.86")
    assert first.outcome == "queued"
    assert second.outcome == "overflow"


async def test_removed_ip_can_be_excluded_again_on_the_same_row(world, exclusion_limit):
    exclusion_limit(5)
    first = await enqueue(world, "203.0.113.87")
    await world.run_worker()

    from app.models import Exclusion

    async with world.sessionmaker() as db:
        await db.execute(update(Exclusion).values(status=ExclusionStatus.REMOVED))
        await db.commit()

    again = await enqueue(world, "203.0.113.87")
    assert again.outcome == "queued"
    assert again.exclusion.id == first.exclusion.id
    assert len(await world.exclusions("203.0.113.87")) == 1
    assert len(await world.actions()) == 2


async def test_failed_ip_is_not_retried_inside_the_cooldown(world, exclusion_limit):
    exclusion_limit(5)
    first = await enqueue(world, "203.0.113.88")
    from app.models import Exclusion

    async with world.sessionmaker() as db:
        await db.execute(update(Exclusion).values(status=ExclusionStatus.FAILED))
        await db.commit()
    again = await enqueue(world, "203.0.113.88")
    assert again.outcome == "cooldown"
    assert len(await world.actions()) == 1
    assert again.exclusion.id == first.exclusion.id


async def test_concurrent_enqueues_never_exceed_capacity(world, exclusion_limit):
    exclusion_limit(3)
    sessions = [await world.fraud_session(f"203.0.114.{i}") for i in range(1, 9)]

    async def one(session):
        async with world.sessionmaker() as db:
            result = await enqueue_exclusion_for_session(db, session)
            await db.commit()
            return result.outcome

    outcomes = await asyncio.gather(*(one(s) for s in sessions))
    assert outcomes.count("queued") == 3
    assert outcomes.count("overflow") == 5
    assert len(await holding_slots(world)) == 3


async def test_crossing_90_percent_is_logged_and_audited(world, exclusion_limit, active_exclusions, caplog):
    exclusion_limit(10)
    await active_exclusions(*([95] * 8))
    with caplog.at_level("WARNING"):
        await enqueue(world, "203.0.113.89")
    [warning] = await world.audit(AuditAction.EXCLUSION_CAPACITY_WARNING)
    assert warning.details["used"] == 9 and warning.details["limit"] == 10
    assert any("9/10" in r.getMessage() for r in caplog.records)


async def test_exclusion_count_column_tracks_slots(world, exclusion_limit):
    exclusion_limit(5)
    await enqueue(world, "203.0.113.90")
    await enqueue(world, "203.0.113.91")
    async with world.sessionmaker() as db:
        campaign = (await db.execute(select(GoogleCampaign))).scalar_one()
    assert campaign.exclusion_count == 2


async def test_limit_is_configurable_with_reserved_slots(monkeypatch):
    from app.core.config import settings
    from app.services.exclusion_capacity import campaign_limit

    monkeypatch.setattr(settings, "GOOGLE_MAX_IP_EXCLUSIONS_PER_CAMPAIGN", 500)
    monkeypatch.setattr(settings, "GOOGLE_EXCLUSION_RESERVED_SLOTS", 25)
    assert campaign_limit() == 475
    monkeypatch.setattr(settings, "GOOGLE_MAX_IP_EXCLUSIONS_PER_CAMPAIGN", 1000)
    assert campaign_limit() == 975

"""Spec §75 Test 2 — repeated clicks: many clicks, short intervals → higher risk."""
from __future__ import annotations

from app.models import Verdict


async def test_repeated_ad_clicks_raise_risk(world):
    baseline = await world.human("203.0.113.20")

    ip = "203.0.113.21"
    visitor = "v_repeat_clicker"
    for _ in range(12):  # 12 ad clicks from one IP within seconds, each bounce < 1 s
        last = await world.visit(ip, visitor=visitor, events=["page_view"], duration=0.5)

    assert last["risk_score"] > baseline["risk_score"]
    assert last["risk_score"] >= 50  # MONITOR or higher
    assert last["verdict"] in (Verdict.MONITOR.value, Verdict.FLAG.value, Verdict.FRAUD.value)

    final = (await world.sessions(ip))[-1]
    assert final.clicks_30_seconds >= 12
    reasons = {event.reason_code for event in await _reasons(world, final.id)}
    assert {"ABNORMAL_CLICK_VELOCITY", "BURST_CLICK_PATTERN"} <= reasons


async def _reasons(world, session_id):
    from sqlalchemy import select

    from app.models import FraudEvent

    async with world.sessionmaker() as db:
        return list((await db.execute(
            select(FraudEvent).where(FraudEvent.session_id == session_id, FraudEvent.triggered.is_(True))
        )).scalars())

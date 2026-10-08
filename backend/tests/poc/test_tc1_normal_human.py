"""Spec §75 Test 1 — normal human: 1 click, normal session, normal interaction → LOW RISK."""
from __future__ import annotations

from app.models import Verdict


async def test_normal_human_is_low_risk(world):
    result = await world.human("203.0.113.10")

    assert result["verdict"] == Verdict.SAFE.value
    assert result["risk_score"] < 30  # LOW band (spec §24)
    [session] = await world.sessions("203.0.113.10")
    assert session.clicks_60_seconds == 1  # its one ad click — on-page clicks don't count (task 004)
    assert session.click_count == 6
    assert session.session_duration_seconds >= 119
    assert await world.exclusions() == []

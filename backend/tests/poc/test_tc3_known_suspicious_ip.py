"""Spec §75 Test 3 — known suspicious IP: high reputation risk → high risk."""
from __future__ import annotations

import pytest
from sqlalchemy import select

from app.models import FraudEvent, Verdict


async def _mildly_short_visit(world, ip):
    return await world.visit(ip, events=["page_view"], duration=1.5)


async def _reason_codes(world, ip):
    session = (await world.sessions(ip))[-1]
    async with world.sessionmaker() as db:
        rows = await db.execute(
            select(FraudEvent.reason_code).where(FraudEvent.session_id == session.id, FraudEvent.triggered.is_(True))
        )
        return set(rows.scalars())


async def test_known_suspicious_ip_adds_reputation_risk(world):
    clean = await _mildly_short_visit(world, "203.0.113.31")

    suspicious_ip = "203.0.113.30"
    await world.seed_history(suspicious_ip, Verdict.FRAUD, count=10, hours_ago=3)
    suspicious = await _mildly_short_visit(world, suspicious_ip)

    assert "HIGH_RISK_IP_REPUTATION" in await _reason_codes(world, suspicious_ip)
    assert "HIGH_RISK_IP_REPUTATION" not in await _reason_codes(world, "203.0.113.31")
    assert suspicious["risk_score"] >= clean["risk_score"] + 20
    assert suspicious["risk_score"] >= 30  # at least MODERATE (spec §24)


@pytest.mark.xfail(
    strict=True,
    reason="Spec §75 expects 'high risk' (>= 60). With today's weights reputation adds at most 30 "
    "(it must never be the sole reason, §14); reaching HIGH needs rule tuning (tasks 015/017).",
)
async def test_known_suspicious_ip_reaches_high_band(world):
    suspicious_ip = "203.0.113.32"
    await world.seed_history(suspicious_ip, Verdict.FRAUD, count=10, hours_ago=3)
    suspicious = await _mildly_short_visit(world, suspicious_ip)
    assert suspicious["risk_score"] >= 60

"""Spec §75 Test 3 — known suspicious IP: high reputation risk → high risk."""
from __future__ import annotations

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


async def test_known_suspicious_ip_reaches_high_risk(world):
    clean = await _mildly_short_visit(world, "203.0.113.31")

    suspicious_ip = "203.0.113.30"
    await world.seed_history(suspicious_ip, Verdict.FRAUD, count=10, hours_ago=3)
    suspicious = await _mildly_short_visit(world, suspicious_ip)

    # Both reputation rules (task 020) fire for the known IP, neither for a fresh one.
    assert {"KNOWN_HIGH_RISK_IP", "HIGH_FRAUD_HISTORY"} <= await _reason_codes(world, suspicious_ip)
    assert not {"KNOWN_HIGH_RISK_IP", "HIGH_FRAUD_HISTORY"} & await _reason_codes(world, "203.0.113.31")
    assert suspicious["risk_score"] >= clean["risk_score"] + 20
    assert suspicious["risk_score"] >= 60  # HIGH band (spec §24)

    [session] = [s for s in await world.sessions(suspicious_ip) if s.ad_landing_at is not None]
    assert session.risk_band == "HIGH"
    # Reputation is one category (capped, §14 "never the sole reason"): not FRAUD on its own.
    assert session.risk_categories["REPUTATION"] <= 45
    assert suspicious["verdict"] != Verdict.FRAUD.value
    assert await world.exclusions(suspicious_ip) == []

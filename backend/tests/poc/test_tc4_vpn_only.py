"""Spec §75 Test 4 — VPN only, otherwise normal behaviour → NOT automatically fraud."""
from __future__ import annotations

from app.models import Verdict


async def test_vpn_alone_is_not_fraud(world):
    ip = "203.0.113.40"
    world.ip_intel[ip] = {"is_vpn": True, "country": "US"}

    result = await world.human(ip)

    assert result["verdict"] != Verdict.FRAUD.value
    assert result["risk_score"] < 30
    [session] = await world.sessions(ip)
    assert session.is_vpn is True
    assert await world.exclusions(ip) == []  # spec §73: VPN ≠ automatic block

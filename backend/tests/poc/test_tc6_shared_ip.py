"""Spec §75 Test 6 — same IP, different legitimate users → not blocked solely because the IP is shared."""
from __future__ import annotations

from app.models import Verdict

BOT_UA = "Mozilla/5.0 (compatible; ClickBot/2.1; +http://example.test/bot)"


async def test_shared_ip_is_not_blocked(world):
    office_ip = "203.0.113.60"
    for i in range(20):  # 20 different people behind one office / carrier IP, each browsing their own way
        result = await world.human(office_ip, duration=60.0 + 9 * i)
        assert result["verdict"] != Verdict.FRAUD.value

    # One bot session from the same IP must not get everybody behind it excluded.
    await world.visit(office_ip, events=["page_view"], duration=0.5, user_agent=BOT_UA)

    sessions = await world.sessions(office_ip)
    assert len(sessions) == 21
    assert all(s.verdict != Verdict.FRAUD for s in sessions[:20])
    assert sessions[-1].verdict != Verdict.FRAUD
    assert await world.exclusions(office_ip) == []
    # Many different visitors → the IP is treated as shared: repeat clicks barely count (task 019).
    assert sessions[-1].extra_signals["repeat_visitor"]["ip_shared"] is True

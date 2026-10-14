"""Tasks 028 (alerts, email) and 029 (retention, erase)."""
from __future__ import annotations

import time
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select

from app.core.config import settings
from app.models import (
    Alert,
    Event,
    EventType,
    GoogleCampaign,
    IPReputation,
    Notification,
    Session,
    Verdict,
    Visitor,
    Website,
)
from app.services import alert_service, email_service
from app.services.alert_service import AlertType
from app.services.exclusion_capacity import sync_exclusion_count
from app.services.audit_service import AuditAction
from app.workers.retention import run_retention


async def alerts(world) -> list[Alert]:
    async with world.sessionmaker() as db:
        return list((await db.execute(select(Alert).order_by(Alert.first_seen_at))).scalars())


async def notifications(world) -> list[Notification]:
    async with world.sessionmaker() as db:
        return list((await db.execute(select(Notification))).scalars())


async def raise_google_failure(world) -> None:
    async with world.sessionmaker() as db:
        await alert_service.raise_alert(
            db, organization_id=world.organization.id, type=AlertType.GOOGLE_API_FAILURE, severity="critical",
            dedupe_key=alert_service.google_failure_key(world.campaign.id), title="Protection action failed",
            message="Google 503", resource_type="campaign", resource_id=str(world.campaign.id),
        )
        await db.commit()


# ---- task 028 -----------------------------------------------------------------------

async def test_repeated_failures_are_one_alert_and_at_most_one_email(world):
    for _ in range(10):
        await raise_google_failure(world)
    [alert] = await alerts(world)
    assert alert.occurrences == 10 and alert.status == "open" and alert.severity == "critical"
    [note] = await notifications(world)
    assert note.recipient == world.user.email and note.status == "pending"


async def test_email_delivery_and_smtp_outage_is_recorded_not_raised(world, monkeypatch, caplog):
    import logging

    caplog.set_level(logging.INFO, logger="app.services.email_service")
    await raise_google_failure(world)
    async with world.sessionmaker() as db:
        assert await alert_service.deliver_pending(db) == {"sent": 1, "failed": 0}  # console backend in dev
    assert "EMAIL (console backend)" in caplog.text
    [note] = await notifications(world)
    assert note.status == "sent" and note.sent_at is not None

    async def broken(*_):
        raise email_service.EmailError("SMTP delivery failed: connection refused")

    monkeypatch.setattr(alert_service, "send_email", broken)
    async with world.sessionmaker() as db:
        await alert_service.raise_alert(
            db, organization_id=world.organization.id, type=AlertType.AUTH_EXPIRED, severity="critical",
            dedupe_key="auth_expired:test", title="Auth expired", message="Reconnect")
        await db.commit()
        assert await alert_service.deliver_pending(db) == {"sent": 0, "failed": 1}
    failed = [n for n in await notifications(world) if n.status == "failed"]
    assert failed and "connection refused" in failed[0].error


async def test_alert_emails_respect_user_preference_and_roles(world):
    async with world.api() as client:
        await client.patch("/api/v1/users/me", json={"alert_emails": False})
    await raise_google_failure(world)
    assert await notifications(world) == []


async def test_capacity_warning_then_critical_then_resolved(world, exclusion_limit, active_exclusions):
    exclusion_limit(10)
    await active_exclusions(*[90] * 9)
    async with world.sessionmaker() as db:
        await sync_exclusion_count(db, await db.get(GoogleCampaign, world.campaign.id))
        await db.commit()
    [alert] = await alerts(world)
    assert alert.type == "EXCLUSION_LIMIT_REACHED" and alert.severity == "warning"
    await active_exclusions(90, ip_prefix="10.21.0.")
    async with world.sessionmaker() as db:
        await sync_exclusion_count(db, await db.get(GoogleCampaign, world.campaign.id))
        await db.commit()
    [alert] = await alerts(world)
    assert alert.severity == "critical" and alert.occurrences == 2
    exclusion_limit(100)
    async with world.sessionmaker() as db:
        await sync_exclusion_count(db, await db.get(GoogleCampaign, world.campaign.id))
        await db.commit()
    assert (await alerts(world))[0].status == "resolved"


async def test_tracking_failure_raises_and_auto_resolves(world):
    now = datetime.now(timezone.utc)
    async with world.sessionmaker() as db:
        site = await db.get(Website, world.website.id)
        site.last_event_at = now - timedelta(hours=settings.TRACKING_FAILURE_HOURS + 1)
        await db.commit()
        await alert_service.run_checks(db, now)
    [alert] = await alerts(world)
    assert alert.type == "TRACKING_FAILURE" and alert.status == "open"
    await world.human("198.51.100.250")  # tracking resumes
    async with world.sessionmaker() as db:
        await alert_service.run_checks(db, datetime.now(timezone.utc))
    assert (await alerts(world))[0].status == "resolved"


async def test_fraud_spike(world):
    now = datetime.now(timezone.utc)
    async with world.sessionmaker() as db:
        for i in range(12):
            db.add(Session(organization_id=world.organization.id, website_id=world.website.id,
                           session_token=f"s_spike_{uuid.uuid4().hex[:8]}", verdict=Verdict.FRAUD,
                           system_verdict=Verdict.FRAUD, created_at=now - timedelta(minutes=i)))
        for i in range(100):
            db.add(Session(organization_id=world.organization.id, website_id=world.website.id,
                           session_token=f"s_base_{uuid.uuid4().hex[:8]}", verdict=Verdict.SAFE,
                           system_verdict=Verdict.SAFE, created_at=now - timedelta(days=2, minutes=i)))
        await db.commit()
        assert (await alert_service.run_checks(db, now))["fraud_spikes"] == 1
    assert (await alerts(world))[0].type == "HIGH_FRAUD_SPIKE"


async def test_system_errors_raise_a_platform_alert(world, fake_redis):
    minute = int(time.time()) // 60
    fake_redis.data[f"system_errors:{minute}"] = str(settings.SYSTEM_ERROR_ALERT_COUNT)
    async with world.sessionmaker() as db:
        await alert_service.run_checks(db)
    [alert] = await alerts(world)
    assert alert.type == "SYSTEM_ERROR" and alert.organization_id is None


async def test_website_disconnected_after_repeated_foreign_origin_use(world, monkeypatch):
    import httpx

    from app.main import app

    monkeypatch.setattr(settings, "WEBSITE_ORIGIN_MISMATCH_ALERT_COUNT", 3)
    body = {"events": [{"site_token": world.website.tracking_token, "visitor_token": "v_foreign_01",
                        "session_token": "s_foreign_01", "event_type": "page_view",
                        "timestamp": datetime.now(timezone.utc).isoformat()}]}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        for _ in range(3):
            await client.post("/api/v1/track", json=body, headers={"origin": "https://copycat.test"})
    [alert] = await alerts(world)
    assert alert.type == "WEBSITE_DISCONNECTED" and "copycat.test" in alert.message


async def test_alerts_api_lists_acknowledges_and_resolves(world):
    await raise_google_failure(world)
    async with world.api() as client:
        summary = (await client.get("/api/v1/alerts/summary")).json()
        [item] = (await client.get("/api/v1/alerts")).json()["items"]
        ack = (await client.post(f"/api/v1/alerts/{item['id']}/acknowledge")).json()
        done = (await client.post(f"/api/v1/alerts/{item['id']}/resolve")).json()
        after = (await client.get("/api/v1/alerts/summary")).json()
    assert summary == {"open": 1, "critical": 1, "warning": 0}
    assert item["notifications"][0]["recipient"] == world.user.email
    assert ack["status"] == "acknowledged" and done["status"] == "resolved" and after["open"] == 0
    assert {AuditAction.ALERT_ACKNOWLEDGED, AuditAction.ALERT_RESOLVED} <= {a.action for a in await world.audit()}


async def test_alerts_are_tenant_scoped(world, make_tenant):
    await raise_google_failure(world)
    _org, other_user, *_ = await make_tenant("Calm")
    async with world.api(other_user) as client:
        assert (await client.get("/api/v1/alerts")).json()["total"] == 0


# ---- task 029 -----------------------------------------------------------------------

async def seed_aged(world, *, ip: str, days_old: float, verdict=Verdict.SAFE, event_ages: tuple = ()) -> Session:
    now = datetime.now(timezone.utc)
    async with world.sessionmaker() as db:
        visitor = Visitor(organization_id=world.organization.id, website_id=world.website.id,
                          visitor_token=f"v_aged_{uuid.uuid4().hex[:8]}", first_seen_at=now - timedelta(days=days_old),
                          last_seen_at=now - timedelta(days=days_old))
        db.add(visitor)
        await db.flush()
        session = Session(organization_id=world.organization.id, website_id=world.website.id, visitor_id=visitor.id,
                          session_token=f"s_aged_{uuid.uuid4().hex[:8]}", ip_address=ip, user_agent="UA", gclid="g",
                          referrer="https://ref.test/?q=secret", country="US", device="mobile", verdict=verdict,
                          system_verdict=verdict, created_at=now - timedelta(days=days_old))
        db.add(session)
        await db.flush()
        for age in event_ages:
            db.add(Event(session_id=session.id, organization_id=world.organization.id, event_type=EventType.PAGE_VIEW,
                         timestamp=now - timedelta(days=age), created_at=now - timedelta(days=age)))
        await db.commit()
        return session


async def test_retention_dry_run_then_apply(world):
    await seed_aged(world, ip="203.0.113.77", days_old=100, event_ages=(10, 29, 31, 60))
    fraud = await seed_aged(world, ip="203.0.113.78", days_old=100, verdict=Verdict.FRAUD)

    dry = await run_retention(world.sessionmaker, dry_run=True)
    assert dry["dry_run"] and dry["events_deleted"] == 2 and dry["sessions_anonymized"] == 1
    async with world.sessionmaker() as db:
        assert await db.scalar(select(func.count()).select_from(Event)) == 4  # nothing changed

    applied = await run_retention(world.sessionmaker, dry_run=False)
    assert applied["events_deleted"] == 2 and applied["sessions_anonymized"] == 1 and applied["visitors_deleted"] == 1
    async with world.sessionmaker() as db:
        ages = sorted(round((datetime.now(timezone.utc) - e.created_at).days) for e in (await db.execute(select(Event))).scalars())
        safe = (await db.execute(select(Session).where(Session.verdict == Verdict.SAFE))).scalar_one()
        kept = await db.get(Session, fraud.id)
    assert ages == [10, 29]
    assert str(safe.ip_address) == "203.0.113.0" and safe.user_agent is None and safe.gclid is None
    assert safe.referrer == "https://ref.test/" and safe.visitor_id is None
    assert safe.country == "US" and safe.device == "mobile"   # aggregates unchanged
    assert str(kept.ip_address) == "203.0.113.78" and kept.user_agent == "UA"  # fraud intelligence kept

    again = await run_retention(world.sessionmaker, dry_run=False)
    # Idempotent; the anonymized session's visitor went in the first run, the fraud visitor stays linked.
    assert again["sessions_anonymized"] == 0 and again["visitors_deleted"] == 0
    runs = await world.audit(AuditAction.RETENTION_RUN)
    assert [r.details["dry_run"] for r in runs] == [True, False, False]


async def test_retention_organization_override(world):
    await seed_aged(world, ip="203.0.113.80", days_old=20)
    async with world.api() as client:
        assert (await client.patch("/api/v1/organizations/me", json={"sessions_retention_days": 10})).status_code == 200
    result = await run_retention(world.sessionmaker, dry_run=False)
    assert result["sessions_anonymized"] == 1


async def test_erase_visitor_only_in_this_organization(world, make_tenant):
    ip = "203.0.113.90"
    await world.human(ip, visitor="v_erase_me_01")
    other_org, other_user, other_site, *_ = await make_tenant("Keep")
    async with world.sessionmaker() as db:
        db.add(Session(organization_id=other_org.id, website_id=other_site.id, session_token="s_other_erase",
                       ip_address=ip, verdict=Verdict.SAFE, system_verdict=Verdict.SAFE))
        await db.commit()
    async with world.api() as client:
        result = await client.post("/api/v1/privacy/erase", json={"visitor_token": "v_erase_me_01"})
    assert result.status_code == 200
    assert result.json()["sessions_anonymized"] == 1 and result.json()["visitors_deleted"] == 1
    assert result.json()["events_deleted"] > 0
    async with world.sessionmaker() as db:
        mine = (await db.execute(select(Session).where(Session.organization_id == world.organization.id))).scalar_one()
        theirs = (await db.execute(select(Session).where(Session.organization_id == other_org.id))).scalar_one()
        reputation = await db.get(IPReputation, (world.organization.id, ip))
    assert str(mine.ip_address) == "203.0.113.0" and str(theirs.ip_address) == ip
    assert reputation is not None  # erase by visitor keeps the IP's counters; erase by IP removes them
    [entry] = await world.audit(AuditAction.PRIVACY_ERASE)
    assert "v_erase_me_01" not in str(entry.details) and entry.details["identifier_sha256"]

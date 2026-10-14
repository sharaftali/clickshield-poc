"""Task 007: browser-supplied tokens and internal references are always tenant-scoped."""
from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from types import SimpleNamespace

from sqlalchemy.dialects import postgresql
from sqlalchemy.exc import IntegrityError

from app.models import Session, Website
from app.models import Verdict
from app.services.protection_service import enqueue_exclusion_for_session
from app.services.tracking_service import TrackingService
from app.workers.action_worker import ActionWorker


def pg(stmt):
    compiled = stmt.compile(dialect=postgresql.dialect())
    return str(compiled), list(compiled.params.values())


class ScriptedDB:
    """execute() returns scripted results in order and records every statement."""

    def __init__(self, *results, fail_flush: bool = False):
        self.results = list(results)
        self.statements = []
        self.fail_flush = fail_flush
        self.rolled_back = False
        self.added = []

    async def execute(self, stmt):
        self.statements.append(stmt)
        return self.results.pop(0) if self.results else SimpleNamespace(scalar_one_or_none=lambda: None)

    def add(self, obj):
        self.added.append(obj)

    async def flush(self):
        if self.fail_flush:
            raise IntegrityError("INSERT", {}, Exception("uq_sessions_website_token"))

    @asynccontextmanager
    async def begin_nested(self):
        yield

    async def rollback(self):
        self.rolled_back = True

    async def commit(self):
        pass


def website() -> Website:
    return Website(id=uuid.uuid4(), organization_id=uuid.uuid4(), domain="a.test", display_name="A", tracking_token="t" * 24)


async def test_session_lookup_is_scoped_to_website():
    db = ScriptedDB()
    site = website()
    assert await TrackingService(db)._find_session(site, "s_shared_token") is None
    sql, params = pg(db.statements[0])
    assert "sessions.website_id = " in sql and site.id in params
    assert "sessions.session_token = " in sql and "s_shared_token" in params


async def test_lost_insert_race_recovers_without_rolling_back_the_transaction(monkeypatch):
    site = website()
    existing = Session(id=uuid.uuid4(), website_id=site.id, organization_id=site.organization_id, session_token="s_race_token")
    db = ScriptedDB(
        SimpleNamespace(scalar_one_or_none=lambda: None),      # first lookup: not there yet
        SimpleNamespace(scalar_one_or_none=lambda: existing),  # after losing the race
        fail_flush=True,
    )
    service = TrackingService(db)

    async def no_campaign(**kwargs):
        return None

    async def no_intel(ip):
        return {}

    monkeypatch.setattr(service, "_resolve_google_campaign", no_campaign)
    monkeypatch.setattr(service.ip_intel, "lookup", no_intel)
    first_event = SimpleNamespace(
        session_token="s_race_token", gclid=None, gbraid=None, wbraid=None, adgroup_id=None, keyword=None,
        matchtype=None, campaign_id=None, utm_source=None, utm_medium=None,
        utm_campaign=None, utm_term=None, utm_content=None, referrer=None, page_url="https://a.test/",
        language=None, timezone=None, payload={},
    )
    request = SimpleNamespace(headers={})
    visitor = SimpleNamespace(id=uuid.uuid4())

    session, is_new = await service._get_or_create_session(site, visitor, first_event, "203.0.113.7", request)

    assert session is existing and is_new is False
    assert db.rolled_back is False  # the visitor created earlier in the transaction survives
    sql, params = pg(db.statements[-1])
    assert "sessions.website_id = " in sql and site.id in params


async def test_worker_loads_exclusion_only_within_action_org():
    db = ScriptedDB()
    exclusion_id, org_id = uuid.uuid4(), uuid.uuid4()
    assert await ActionWorker()._get_exclusion(db, exclusion_id, org_id) is None
    sql, params = pg(db.statements[0])
    assert "exclusions.organization_id = " in sql and org_id in params
    assert exclusion_id in params


async def test_enqueue_only_uses_campaigns_of_the_sessions_own_org():
    org_id = uuid.uuid4()
    fraud_session = SimpleNamespace(
        id=uuid.uuid4(), organization_id=org_id, google_campaign_id=uuid.uuid4(),
        ip_address="203.0.113.7", risk_score=95, confidence_score=95, verdict=Verdict.FRAUD,
    )
    db = ScriptedDB(SimpleNamespace(first=lambda: None))  # campaign belongs to another tenant -> no row
    result = await enqueue_exclusion_for_session(db, fraud_session)
    assert result.outcome == "campaign_unavailable" and db.added == []
    sql, params = pg(db.statements[0])
    assert "google_connections.organization_id = " in sql and org_id in params
    assert "FOR UPDATE OF google_campaigns" in sql  # capacity decisions are serialized per campaign

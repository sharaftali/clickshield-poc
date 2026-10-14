"""
Shared fixtures. Unit tests need none of this; database tests (tests/db, tests/poc)
use a real PostgreSQL, migrated with Alembic exactly like production.

    TEST_DATABASE_URL  default postgresql+asyncpg://postgres:postgres@localhost:5432/clickshield_test
                       (the database name must end in "_test" — it is truncated before every test)

Start one with `docker compose up -d db` from the repository root. When no PostgreSQL
is reachable, database tests are skipped, not failed.
"""
from __future__ import annotations

import os
import subprocess
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.adapters.google_ads_adapter import GoogleAdsApiResult
from app.core.config import settings
from app.core.crypto import encrypt
from app.core.database import get_db
from app.core.security import create_token, hash_password
from app.main import app
from app.models import (
    AuditLog,
    Base,
    CampaignStatus,
    CampaignType,
    Exclusion,
    ExclusionStatus,
    GoogleCampaign,
    GoogleConnection,
    Organization,
    PlatformAction,
    Session,
    User,
    UserRole,
    Verdict,
    Website,
)
from app.services import tracking_service as tracking_module
from app.services.ip_intel import IPIntelService
from app.services.rules import repository as rule_repository
from app.workers import action_worker as worker_module
from app.workers.action_worker import ActionWorker

BACKEND_DIR = Path(__file__).resolve().parents[1]
TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL", "postgresql+asyncpg://postgres:postgres@localhost:5432/clickshield_test"
)
CUSTOMER_ID = "1234567890"
CAMPAIGN_ID = "555"
HUMAN_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/129.0 Safari/537.36"
)
BOT_UA = "Mozilla/5.0 (compatible; ClickBot/2.1; +http://example.test/bot)"


def _sync_url(async_url: str) -> str:
    return async_url.replace("+asyncpg", "+psycopg")


@pytest.fixture(scope="session")
def migrated_database() -> str:
    """Create (if needed) and migrate the test database once per test run."""
    import psycopg
    from sqlalchemy.engine import make_url

    url = make_url(TEST_DATABASE_URL)
    if not (url.database or "").endswith("_test"):
        pytest.exit(f"Refusing to use {url.database!r}: test database names must end in '_test'.")

    admin_dsn = f"host={url.host} port={url.port or 5432} user={url.username} password={url.password} dbname=postgres"
    try:
        with psycopg.connect(admin_dsn, connect_timeout=3, autocommit=True) as conn:
            exists = conn.execute("SELECT 1 FROM pg_database WHERE datname = %s", (url.database,)).fetchone()
            if not exists:
                conn.execute(f'CREATE DATABASE "{url.database}"')
    except psycopg.OperationalError as exc:
        pytest.skip(f"PostgreSQL not available for database tests ({exc.__class__.__name__}); "
                    "run `docker compose up -d db`.")

    env = {**os.environ, "DATABASE_URL_SYNC": _sync_url(TEST_DATABASE_URL), "DATABASE_URL": TEST_DATABASE_URL}
    completed = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=BACKEND_DIR, env=env, capture_output=True, text=True,
    )
    if completed.returncode != 0:
        pytest.fail(f"alembic upgrade head failed:\n{completed.stdout}\n{completed.stderr}")
    return TEST_DATABASE_URL


# Reference data seeded by migrations: kept between tests (tests that change it restore it).
KEEP_TABLES = {"rules"}


@pytest.fixture(autouse=True)
def fresh_rule_cache():
    """Rules are cached per process (task 015); every test starts from the database."""
    rule_repository.invalidate()
    yield
    rule_repository.invalidate()


@pytest.fixture
async def sessionmaker(migrated_database):
    engine = create_async_engine(migrated_database, poolclass=NullPool)
    tables = ", ".join(f'"{table.name}"' for table in Base.metadata.sorted_tables if table.name not in KEEP_TABLES)
    async with engine.begin() as conn:
        await conn.execute(text(f"TRUNCATE {tables} RESTART IDENTITY CASCADE"))
    yield async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False, autoflush=False)
    await engine.dispose()


@pytest.fixture
async def db(sessionmaker):
    async with sessionmaker() as session:
        yield session


# ---- world: one tenant with a verified site, a Google connection and a SEARCH campaign ----

@dataclass
class World:
    sessionmaker: async_sessionmaker
    organization: Organization
    user: User
    website: Website
    connection: GoogleConnection
    campaign: GoogleCampaign
    ip_intel: dict[str, dict] = field(default_factory=dict)
    pushed_jobs: list = field(default_factory=list)
    google_results: list[GoogleAdsApiResult] = field(default_factory=list)
    google_calls: list = field(default_factory=list)
    _counter: int = 0

    # -- tracking ---------------------------------------------------------
    def _token(self, prefix: str) -> str:
        self._counter += 1
        return f"{prefix}_{self._counter:06d}_{uuid.uuid4().hex[:8]}"

    async def visit(
        self,
        ip: str,
        *,
        events: list[str] | None = None,
        duration: float = 120.0,
        scroll_depth: float | None = None,
        visitor: str | None = None,
        paid: bool = True,
        gclid: str | None = None,
        user_agent: str = HUMAN_UA,
        timezone_name: str | None = None,
        screen: tuple[int, int] | None = None,
        landing_path: str = "page",
    ) -> dict:
        """One browser session, posted to /api/v1/track as one batch. Returns the API response."""
        events = events or ["page_view"]
        if paid:
            events = ["ad_landing", *events]
        now = datetime.now(timezone.utc)
        step = duration / max(1, len(events) - 1)
        visitor = visitor or self._token("v")
        session_token = self._token("s")
        attribution = {"gclid": gclid or self._token("gclid"), "campaign_id": CAMPAIGN_ID,
                       "utm_source": "google", "utm_medium": "cpc"} if paid else {}
        batch = []
        for i, event_type in enumerate(events):
            payload = {"depth": scroll_depth} if event_type == "scroll" and scroll_depth is not None else {}
            if screen is not None:
                payload |= {"screen_width": screen[0], "screen_height": screen[1]}
            batch.append({
                "site_token": self.website.tracking_token,
                "visitor_token": visitor,
                "session_token": session_token,
                "event_type": event_type,
                "page_url": f"https://{self.website.domain}/{landing_path}-{i}",
                "timezone": timezone_name,
                "timestamp": (now - timedelta(seconds=duration) + timedelta(seconds=step * i)).isoformat(),
                "payload": payload,
                **attribution,
            })
        transport = httpx.ASGITransport(app=app, client=(ip, 51000))
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post("/api/v1/track", json={"events": batch}, headers={"user-agent": user_agent})
        assert response.status_code == 200, response.text
        return response.json()

    def human(self, ip: str, duration: float = 120.0, **kwargs) -> dict:
        """Spec §75 test 1 behaviour: 2 minutes, 3 pages, scrolls, a few clicks."""
        events = ["page_view", "click", "scroll", "page_view", "click", "click",
                  "page_view", "click", "click", "click", "scroll"]
        return self.visit(ip, events=events, duration=duration, scroll_depth=80.0, **kwargs)

    # -- direct data ------------------------------------------------------
    async def seed_history(self, ip: str, verdict: Verdict, count: int, *, hours_ago: float = 2.0) -> None:
        async with self.sessionmaker() as db:
            for i in range(count):
                db.add(Session(
                    organization_id=self.organization.id, website_id=self.website.id,
                    session_token=self._token("hist"), ip_address=ip,
                    verdict=verdict, system_verdict=verdict, risk_score=90 if verdict == Verdict.FRAUD else 5,
                    created_at=datetime.now(timezone.utc) - timedelta(hours=hours_ago, minutes=i),
                ))
            await db.commit()

    async def fraud_session(self, ip: str, *, risk: int = 92, confidence: int = 95) -> Session:
        """A scored FRAUD session on the campaign, created directly (for enqueue tests)."""
        async with self.sessionmaker() as db:
            session = Session(
                organization_id=self.organization.id, website_id=self.website.id,
                session_token=self._token("fraud"), ip_address=ip, google_campaign_id=self.campaign.id,
                verdict=Verdict.FRAUD, system_verdict=Verdict.FRAUD, risk_score=risk, confidence_score=confidence,
            )
            db.add(session)
            await db.commit()
            return session

    async def sessions(self, ip: str) -> list[Session]:
        async with self.sessionmaker() as db:
            return list((await db.execute(
                select(Session).where(Session.ip_address == ip).order_by(Session.created_at)
            )).scalars())

    async def exclusions(self, ip: str | None = None) -> list[Exclusion]:
        async with self.sessionmaker() as db:
            query = select(Exclusion).order_by(Exclusion.created_at)
            if ip is not None:
                query = query.where(Exclusion.ip_address == ip)
            return list((await db.execute(query)).scalars())

    async def actions(self) -> list[PlatformAction]:
        async with self.sessionmaker() as db:
            return list((await db.execute(select(PlatformAction).order_by(PlatformAction.created_at))).scalars())

    async def audit(self, action: str | None = None) -> list[AuditLog]:
        async with self.sessionmaker() as db:
            query = select(AuditLog).order_by(AuditLog.created_at, AuditLog.id)
            if action is not None:
                query = query.where(AuditLog.action == action)
            return list((await db.execute(query)).scalars())

    # -- worker -------------------------------------------------------------
    async def run_worker(self) -> dict:
        async with self.sessionmaker() as db:
            return await ActionWorker().process_pending(db)

    def api(self, user: User | None = None) -> httpx.AsyncClient:
        token = create_token(str((user or self.user).id), "access")
        return httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, client=("198.51.100.20", 52000)),
            base_url="http://test",
            headers={"Authorization": f"Bearer {token}"},
        )


async def create_tenant(db: AsyncSession, name: str) -> tuple[Organization, User, Website, GoogleConnection, GoogleCampaign]:
    org = Organization(name=name, slug=f"{name.lower()}-{uuid.uuid4().hex[:6]}")
    db.add(org)
    await db.flush()
    user = User(organization_id=org.id, email=f"owner-{uuid.uuid4().hex[:8]}@{name.lower()}-tests.io",
                hashed_password=hash_password("Correct-Horse-1"), full_name="Owner", role=UserRole.OWNER)
    website = Website(organization_id=org.id, domain=f"{name.lower()}.test", display_name=name,
                      tracking_token=f"site_{uuid.uuid4().hex}", is_verified=True)
    connection = GoogleConnection(organization_id=org.id, refresh_token_encrypted=encrypt("refresh-token"),
                                  customer_id=CUSTOMER_ID, is_active=True)
    db.add_all([user, website, connection])
    await db.flush()
    campaign = GoogleCampaign(connection_id=connection.id, campaign_id=CAMPAIGN_ID, name="Emergency Plumbing",
                              campaign_type=CampaignType.SEARCH, status=CampaignStatus.ENABLED,
                              protection_enabled=True)
    db.add(campaign)
    await db.commit()
    return org, user, website, connection, campaign


@pytest.fixture
async def world(sessionmaker, monkeypatch) -> World:
    async with sessionmaker() as db:
        org, user, website, connection, campaign = await create_tenant(db, "Acme")
    w = World(sessionmaker=sessionmaker, organization=org, user=user, website=website,
              connection=connection, campaign=campaign)

    async def override_get_db():
        async with sessionmaker() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db

    # IP intelligence: per-IP flags set by the test, nothing by default.
    async def fake_lookup(self, ip: str) -> dict:
        return dict(w.ip_intel.get(ip, {}))

    monkeypatch.setattr(IPIntelService, "lookup", fake_lookup)

    # Job pushes: record instead of talking to Redis (the sweep path is tested separately).
    async def record_push(action_ids):
        ids = list(action_ids)
        w.pushed_jobs.extend(ids)
        return len(ids)

    monkeypatch.setattr(tracking_module, "enqueue_actions", record_push)

    # Google: configured, not dry-run, adapter answers from w.google_results (default: success).
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_ID", "test-client")
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_SECRET", "test-secret")
    monkeypatch.setattr(settings, "GOOGLE_ADS_DRY_RUN", False)
    monkeypatch.setattr(settings, "AUTO_PROTECTION_ENABLED", True)
    monkeypatch.setattr(settings, "TRUSTED_PROXY_CIDRS", "")

    async def fake_refresh(refresh_token):
        return {"access_token": "access-token"}

    class FakeAdapter:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        async def _answer(self, op, kwargs):
            w.google_calls.append((op, self.kwargs, kwargs))
            if w.google_results:
                return w.google_results.pop(0) if len(w.google_results) > 1 else w.google_results[0]
            return GoogleAdsApiResult(
                ok=True,
                resource_name=f"customers/{CUSTOMER_ID}/campaignCriteria/{CAMPAIGN_ID}~{len(w.google_calls)}",
                api_request_id=f"req-{len(w.google_calls)}",
            )

        async def create_ip_exclusion(self, **kwargs):
            return await self._answer("create", kwargs)

        async def remove_ip_exclusion(self, **kwargs):
            return await self._answer("remove", kwargs)

    monkeypatch.setattr(worker_module, "refresh_access_token", fake_refresh)
    monkeypatch.setattr(worker_module, "GoogleAdsAdapter", FakeAdapter)

    yield w
    app.dependency_overrides.pop(get_db, None)


@pytest.fixture
def make_tenant(sessionmaker):
    """Create another organization (with site, connection, campaign) for isolation tests."""
    async def make(name: str):
        async with sessionmaker() as db:
            return await create_tenant(db, name)
    return make


@pytest.fixture
def exclusion_limit(monkeypatch):
    """Set the usable per-campaign limit (Google limit, no reserved slots)."""
    def set_limit(limit: int) -> None:
        monkeypatch.setattr(settings, "GOOGLE_MAX_IP_EXCLUSIONS_PER_CAMPAIGN", limit)
        monkeypatch.setattr(settings, "GOOGLE_EXCLUSION_RESERVED_SLOTS", 0)
    return set_limit


@pytest.fixture
def active_exclusions(world):
    """Insert ACTIVE exclusions with given confidences directly (fill a campaign)."""
    async def insert(*confidences: int, ip_prefix: str = "10.20.0.") -> list[Exclusion]:
        rows = []
        async with world.sessionmaker() as db:
            for i, confidence in enumerate(confidences, start=1):
                row = Exclusion(
                    organization_id=world.organization.id, google_customer_id=CUSTOMER_ID,
                    campaign_id=CAMPAIGN_ID, google_campaign_id=world.campaign.id,
                    ip_address=f"{ip_prefix}{i}", reason="seed", risk_score=confidence,
                    confidence=confidence, status=ExclusionStatus.ACTIVE,
                    google_resource_name=f"customers/{CUSTOMER_ID}/campaignCriteria/{CAMPAIGN_ID}~9{i:03d}",
                    last_fraud_at=datetime.now(timezone.utc) - timedelta(hours=i),
                )
                db.add(row)
                rows.append(row)
            await db.commit()
        return rows
    return insert

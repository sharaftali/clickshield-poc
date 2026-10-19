"""Regression tests for defects found in the end-to-end QA / security pass (2026-10-14).

Each test reproduces a request that used to answer 500 (or mis-score) and pins the fix.
"""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import uuid
from datetime import datetime, timedelta, timezone

import httpx
import jwt
import pytest
from cryptography.fernet import Fernet
from sqlalchemy import select

from app.core.config import settings
from app.main import app
from app.models import Event, FraudEvent, Session
from app.services.protection_service import enqueue_exclusion_for_session, is_routable_ip
from tests.conftest import BACKEND_DIR, HUMAN_UA


def event(world, session: str, **extra) -> dict:
    return {
        "site_token": world.website.tracking_token, "visitor_token": "v_qa_regress_01", "session_token": session,
        "event_type": extra.pop("event_type", "page_view"),
        "page_url": extra.pop("page_url", f"https://{world.website.domain}/landing"),
        "timestamp": datetime.now(timezone.utc).isoformat(), **extra,
    }


async def post(world, *events, headers: dict | None = None, ip: str = "198.51.100.77") -> httpx.Response:
    transport = httpx.ASGITransport(app=app, client=(ip, 51000))
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.post("/api/v1/track", content=json.dumps({"events": list(events)}), headers={
            "user-agent": HUMAN_UA, "origin": f"https://{world.website.domain}", **(headers or {})})


async def stored_session(world, token: str) -> Session:
    async with world.sessionmaker() as db:
        return (await db.execute(select(Session).where(Session.session_token == token))).scalar_one()


def token() -> str:
    return f"s_qa_{uuid.uuid4().hex[:12]}"


# ---- tracking input that passed the schema but broke the database / parser ----------

async def test_overlong_attribution_values_are_truncated_not_500(world):
    session = token()
    response = await post(world, event(world, session, utm_source="g" * 150, utm_medium="m" * 150,
                                       utm_campaign="c" * 300, utm_term="t" * 300, utm_content="x" * 300))
    assert response.status_code == 200, response.text
    stored = await stored_session(world, session)
    assert len(stored.utm_source) == 100 and len(stored.utm_medium) == 100
    assert len(stored.utm_campaign) == len(stored.utm_term) == len(stored.utm_content) == 255


async def test_long_accept_language_header_is_truncated(world):
    session = token()
    response = await post(world, event(world, session), headers={"accept-language": "x" * 60 + ",en;q=0.8"})
    assert response.status_code == 200, response.text
    assert (await stored_session(world, session)).language == "x" * 20


@pytest.mark.parametrize("literal", ["Infinity", "-Infinity", "NaN", "1e999"])
async def test_non_standard_json_numbers_are_refused(world, literal):
    """Python's json accepts these; JSONB doesn't (500) and browsers never send them."""
    body = json.dumps({"events": [event(world, token(), event_type="scroll", payload={"depth": 0})]})
    body = body.replace('"depth": 0', f'"depth": {literal}')
    transport = httpx.ASGITransport(app=app, client=("198.51.100.77", 51000))
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/v1/track", content=body, headers={
            "user-agent": HUMAN_UA, "origin": f"https://{world.website.domain}"})
    assert response.status_code == 400 and "not valid JSON" in response.text


@pytest.mark.parametrize("depth", [{"a": 1}, [50], "deep", "inf", "-inf", "nan", True])
async def test_malformed_scroll_depth_is_ignored_and_session_stays_readable(world, depth):
    session = token()
    response = await post(world, event(world, session, event_type="scroll", payload={"depth": depth}))
    assert response.status_code == 200, response.text
    stored = await stored_session(world, session)
    assert stored.scroll_depth == 0.0
    # A stored Infinity used to make the session detail endpoint fail on every read.
    async with world.api() as client:
        detail = await client.get(f"/api/v1/dashboard/sessions/{stored.id}")
    assert detail.status_code == 200, detail.text


async def test_scroll_depth_is_clamped_to_percent(world):
    session = token()
    response = await post(world, event(world, session, event_type="scroll", payload={"depth": 250}))
    assert response.status_code == 200
    assert (await stored_session(world, session)).scroll_depth == 100.0


@pytest.mark.parametrize("touch_points", [[1, 2], {"n": 3}, "many", None])
async def test_malformed_touch_points_do_not_break_ingestion(world, touch_points):
    response = await post(world, event(world, token(), payload={"touch_points": touch_points}))
    assert response.status_code == 200, response.text


async def test_nul_bytes_are_stripped_from_strings_and_payload(world):
    session = token()
    response = await post(world, event(world, session, page_url=f"https://{world.website.domain}/a\u0000b",
                                       utm_source="goo\u0000gle", payload={"k\u0000": "v\u0000", "list": ["a\u0000"]}))
    assert response.status_code == 200, response.text
    stored = await stored_session(world, session)
    assert stored.landing_page == f"https://{world.website.domain}/ab" and stored.utm_source == "google"
    async with world.sessionmaker() as db:
        payload = (await db.execute(select(Event.payload).where(Event.session_id == stored.id))).scalar_one()
    assert payload == {"k": "v", "list": ["a"]}


# ---- the client payload must not pre-seed server-computed signals --------------------

async def test_client_cannot_inject_human_actions_to_evade_bounce_rules(world):
    session = token()
    # A 0-second, one-page visit: UNUSUAL_SESSION must fire whatever the payload claims.
    response = await post(world, event(world, session, payload={"human_actions": 50, "rate_limited": 0}))
    assert response.status_code == 200, response.text
    stored = await stored_session(world, session)
    assert "human_actions" not in (stored.extra_signals or {})
    async with world.sessionmaker() as db:
        fired = set((await db.execute(select(FraudEvent.rule_name).where(
            FraudEvent.session_id == stored.id, FraudEvent.triggered.is_(True)))).scalars())
    assert "UNUSUAL_SESSION" in fired


@pytest.mark.parametrize("payload", [{"human_actions": {"x": 1}}, {"rate_limited": [1]}, {"repeat_visitor": "x"},
                                     {"event_intervals": 5}, {"source_platform": "google_ads"}])
async def test_type_confused_server_keys_are_ignored(world, payload):
    session = token()
    response = await post(world, event(world, session, payload=payload))
    assert response.status_code == 200, response.text
    signals = (await stored_session(world, session)).extra_signals
    assert signals["source_platform"] == "other"
    for key, value in payload.items():
        assert signals.get(key) != value


async def test_real_tracker_payload_keys_are_kept(world):
    session = token()
    automation = {"webdriver": True, "headless": False}
    response = await post(world, event(world, session, payload={"screen_width": 1920, "touch_points": 0,
                                                                 "automation": automation}))
    assert response.status_code == 200
    signals = (await stored_session(world, session)).extra_signals
    assert signals["screen_width"] == 1920 and signals["automation"] == automation


# ---- registration ----------------------------------------------------------------------

def _signup(email: str, org: str, slug: str | None = None) -> dict:
    body = {"full_name": "QA User", "email": email, "password": "Qa-Passw0rd!", "organization_name": org}
    if slug:
        body["organization_slug"] = slug
    return body


async def _register(body: dict, ip: str = "198.51.100.90") -> httpx.Response:
    transport = httpx.ASGITransport(app=app, client=(ip, 52000))
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.post("/api/v1/auth/register", json=body)


async def test_concurrent_duplicate_registrations_never_500(world):
    body = _signup(f"race-{uuid.uuid4().hex[:6]}@example.com", "Race Org", slug=f"race-{uuid.uuid4().hex[:6]}")
    responses = await asyncio.gather(*[_register(body, ip=f"198.51.100.{100 + i}") for i in range(4)])
    codes = sorted(r.status_code for r in responses)
    assert codes.count(201) == 1 and set(codes) <= {201, 409}, codes


async def test_same_organization_name_twice_gets_distinct_slugs(world):
    first = await _register(_signup(f"a-{uuid.uuid4().hex[:6]}@example.com", "Acme Plumbing"))
    second = await _register(_signup(f"b-{uuid.uuid4().hex[:6]}@example.com", "Acme Plumbing"))
    assert first.status_code == second.status_code == 201, second.text
    assert first.json()["organization"]["slug"] == "acme-plumbing"
    assert second.json()["organization"]["slug"].startswith("acme-plumbing-")


async def test_explicit_duplicate_slug_is_still_refused(world):
    slug = f"taken-{uuid.uuid4().hex[:6]}"
    assert (await _register(_signup(f"c-{uuid.uuid4().hex[:6]}@example.com", "One", slug=slug))).status_code == 201
    again = await _register(_signup(f"d-{uuid.uuid4().hex[:6]}@example.com", "Two", slug=slug))
    assert again.status_code == 409


async def test_long_organization_name_fits_the_slug_column(world):
    response = await _register(_signup(f"e-{uuid.uuid4().hex[:6]}@example.com", "L" * 120))
    assert response.status_code == 201, response.text
    assert len(response.json()["organization"]["slug"]) <= 100


async def test_token_lifetimes_follow_settings(world, monkeypatch):
    monkeypatch.setattr(settings, "REFRESH_TOKEN_EXPIRE_DAYS", 2)
    monkeypatch.setattr(settings, "ACCESS_TOKEN_EXPIRE_MINUTES", 15)
    response = await _register(_signup(f"f-{uuid.uuid4().hex[:6]}@example.com", "Lifetimes"))
    tokens = response.json()["tokens"]
    assert tokens["expires_in_minutes"] == 15
    claims = jwt.decode(tokens["refresh_token"], settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    assert timedelta(days=2) - timedelta(minutes=1) < timedelta(seconds=claims["exp"] - claims["iat"]) <= timedelta(days=2)

    transport = httpx.ASGITransport(app=app, client=("198.51.100.91", 52000))
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        refreshed = (await client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})).json()
    assert refreshed["expires_in_minutes"] == 15
    claims = jwt.decode(refreshed["refresh_token"], settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    assert claims["exp"] - claims["iat"] == 2 * 86400


# ---- exclusions: only routable IPs (spec §38) -------------------------------------------

@pytest.mark.parametrize("ip", ["10.1.2.3", "172.28.0.10", "192.168.1.5", "100.64.0.9", "127.0.0.1",
                                "169.254.1.1", "fd00::1", "::1", "::ffff:10.0.0.5"])
async def test_non_routable_fraud_ip_is_never_queued_for_google(world, ip):
    session = await world.fraud_session(ip)
    async with world.sessionmaker() as db:
        session = await db.get(Session, session.id)
        result = await enqueue_exclusion_for_session(db, session)
        await db.commit()
    assert result.outcome == "ip_not_routable"
    assert await world.exclusions() == [] and await world.actions() == []


async def test_public_fraud_ip_is_still_queued(world):
    session = await world.fraud_session("203.0.113.50")
    async with world.sessionmaker() as db:
        session = await db.get(Session, session.id)
        result = await enqueue_exclusion_for_session(db, session)
        await db.commit()
    assert result.outcome == "queued"


def test_routable_ip_helper():
    assert is_routable_ip("8.8.8.8") and is_routable_ip("2001:4860:4860::8888")
    assert not is_routable_ip("not-an-ip") and not is_routable_ip("0.0.0.0")


# ---- interactive API docs are a development aid ------------------------------------------

def test_api_docs_are_not_published_outside_development():
    env = {**os.environ, "ENVIRONMENT": "production", "SECRET_KEY": "p" * 48, "LOG_TO_FILE": "false",
           "TOKEN_ENCRYPTION_KEYS": Fernet.generate_key().decode(), "API_CORS_ORIGINS": "https://app.example.com",
           "GOOGLE_CLIENT_ID": "", "GOOGLE_CLIENT_SECRET": ""}
    code = "from app.main import app; print(app.docs_url, app.redoc_url, app.openapi_url)"
    out = subprocess.run([sys.executable, "-c", code], cwd=BACKEND_DIR, env=env, capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert out.stdout.split() == ["None", "None", "None"]


async def test_api_docs_are_published_in_development(world):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        assert (await client.get("/openapi.json")).status_code == 200

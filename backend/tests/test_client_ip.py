"""Task 001: client IP must not be spoofable via X-Forwarded-For."""
from __future__ import annotations

import uuid

import httpx
import pytest
from fastapi import Request

from app.core.client_ip import ClientIPError, parse_trusted_networks, resolve_client_ip
from app.core.database import get_db
from app.main import app
from app.schemas.tracking import TrackingResponse
from app.services.tracking_service import TrackingService

LB = parse_trusted_networks("10.0.0.0/8")
NONE: tuple = ()


def make_request(peer: str | None, *xff: str) -> Request:
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/v1/track",
        "headers": [(b"x-forwarded-for", value.encode()) for value in xff],
        "client": (peer, 51234) if peer is not None else None,
    }
    return Request(scope)


@pytest.mark.parametrize(
    ("peer", "xff", "trusted", "expected"),
    [
        # Table from the task file
        ("1.1.1.1", ["8.8.8.8"], NONE, "1.1.1.1"),
        ("10.0.0.5", ["8.8.8.8"], LB, "8.8.8.8"),
        ("10.0.0.5", ["6.6.6.6, 8.8.8.8"], LB, "8.8.8.8"),
        ("10.0.0.5", ["6.6.6.6, 8.8.8.8, 10.0.0.9"], LB, "8.8.8.8"),
        ("1.1.1.1", ["not-an-ip"], NONE, "1.1.1.1"),
        # Peer outside the trusted list: header ignored even when proxies are configured
        ("1.1.1.1", ["8.8.8.8"], LB, "1.1.1.1"),
        # Trusted peer, no header
        ("10.0.0.5", [], LB, "10.0.0.5"),
        # Multiple XFF headers behave like one comma-joined header
        ("10.0.0.5", ["6.6.6.6", "8.8.8.8"], LB, "8.8.8.8"),
        # Every hop is our own proxy -> leftmost hop
        ("10.0.0.5", ["10.1.1.1, 10.2.2.2"], LB, "10.1.1.1"),
        # Ports appended by some proxies
        ("10.0.0.5", ["8.8.8.8:4431"], LB, "8.8.8.8"),
        ("10.0.0.5", ["[2001:db8::7]:443"], LB, "2001:db8::7"),
        # IPv6
        ("2001:db8::1", [], NONE, "2001:db8::1"),
        ("10.0.0.5", ["2001:db8::7"], LB, "2001:db8::7"),
        # IPv4-mapped IPv6 is normalized to IPv4, for peer and header entries
        ("::ffff:1.1.1.1", [], NONE, "1.1.1.1"),
        ("::ffff:10.0.0.5", ["::ffff:8.8.8.8"], LB, "8.8.8.8"),
    ],
)
def test_resolve_client_ip(peer, xff, trusted, expected):
    assert resolve_client_ip(make_request(peer, *xff), trusted) == expected


@pytest.mark.parametrize(
    ("peer", "xff"),
    [
        ("10.0.0.5", ["not-an-ip"]),          # malformed entry from a trusted proxy
        ("10.0.0.5", ["8.8.8.8, garbage"]),
        ("testclient", []),                    # non-IP peer address
        (None, []),                            # no peer at all
    ],
)
def test_resolve_client_ip_rejects_invalid(peer, xff):
    with pytest.raises(ClientIPError):
        resolve_client_ip(make_request(peer, *xff), LB)


def test_default_settings_trust_nobody():
    # TRUSTED_PROXY_CIDRS defaults to empty: a loopback peer is not trusted either.
    assert resolve_client_ip(make_request("127.0.0.1", "8.8.8.8")) == "127.0.0.1"


# ---- Endpoint wiring --------------------------------------------------------

def _batch() -> dict:
    return {
        "events": [
            {
                "site_token": "site_token_test",
                "visitor_token": "v_visitor_test",
                "session_token": "s_session_test",
                "event_type": "page_view",
                "page_url": "https://example.test/",
                "timestamp": "2026-10-06T12:00:00Z",
            }
        ]
    }


@pytest.fixture
def captured_ip(monkeypatch):
    seen: dict[str, str] = {}

    async def fake_ingest(self, payload, client_ip, request):
        seen["ip"] = client_ip
        return TrackingResponse(
            status="ok", session_id=uuid.uuid4(), risk_score=0, confidence_score=0, verdict="SAFE"
        )

    async def no_db():
        yield None

    monkeypatch.setattr(TrackingService, "ingest_batch", fake_ingest)
    app.dependency_overrides[get_db] = no_db
    yield seen
    app.dependency_overrides.pop(get_db, None)


async def _post(peer: str, headers: dict[str, str]) -> httpx.Response:
    transport = httpx.ASGITransport(app=app, client=(peer, 51234))
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.post("/api/v1/track", json=_batch(), headers=headers)


async def test_track_ignores_spoofed_forwarded_for(captured_ip):
    resp = await _post("203.0.113.10", {"X-Forwarded-For": "8.8.8.8"})
    assert resp.status_code == 200
    assert captured_ip["ip"] == "203.0.113.10"


async def test_track_rejects_invalid_peer_ip(captured_ip):
    resp = await _post("not-an-ip", {})
    assert resp.status_code == 400
    assert "ip" not in captured_ip

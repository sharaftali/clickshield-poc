"""ActionWorker outcome handling (tasks 003, 008, 009). No database: lookups are stubbed."""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from types import SimpleNamespace
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.dialects import postgresql

from app.adapters.google_ads_adapter import ErrorCategory, GoogleAdsApiResult
from app.core.config import settings
from app.core.crypto import encrypt
from app.models import (
    ActionStatus,
    ActionType,
    Exclusion,
    ExclusionStatus,
    GoogleConnection,
    Platform,
    PlatformAction,
)
from app.services.google_oauth import GoogleAuthError, classify_token_error
from app.models import Verdict
from app.services.protection_service import enqueue_exclusion_for_session
from app.workers import action_worker as worker_module
from app.workers.action_worker import (
    ActionWorker,
    build_claim_query,
    build_connection_by_campaign_query,
    build_connection_by_customer_query,
    build_reap_stuck_actions,
    compute_next_attempt,
)

CID = "1234567890"
CRITERION = f"customers/{CID}/campaignCriteria/555~777"


class StubDB:
    """Collects audit rows; campaign lookups find nothing (no capacity rebalance)."""

    def __init__(self):
        self.added = []

    def add(self, obj):
        self.added.append(obj)

    async def execute(self, stmt):
        return SimpleNamespace(first=lambda: None, scalar_one_or_none=lambda: None)

    async def flush(self):
        pass


@dataclass
class Env:
    worker: ActionWorker
    action: PlatformAction
    exclusion: Exclusion
    connection: GoogleConnection
    adapter_calls: list = field(default_factory=list)
    token_calls: list = field(default_factory=list)
    blocked: list = field(default_factory=list)
    adapter_result: GoogleAdsApiResult | None = None
    token_error: Exception | None = None

    db: "StubDB" = field(default_factory=lambda: StubDB())

    async def run(self) -> str:
        return await self.worker._process_action(self.db, self.action)

    def audit(self, action: str) -> list:
        return [row for row in self.db.added if getattr(row, "action", None) == action]


@pytest.fixture
def env(monkeypatch) -> Env:
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_ID", "client-id")
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_SECRET", "client-secret")
    monkeypatch.setattr(settings, "GOOGLE_ADS_DRY_RUN", False)

    org_id = uuid.uuid4()
    exclusion = Exclusion(
        id=uuid.uuid4(), organization_id=org_id, google_customer_id=CID, campaign_id="555",
        ip_address="203.0.113.7", reason="Abnormal click velocity", risk_score=92, confidence=95,
        status=ExclusionStatus.PENDING,
    )
    action = PlatformAction(
        id=uuid.uuid4(), organization_id=org_id, platform=Platform.GOOGLE,
        action_type=ActionType.ADD_IP_EXCLUSION, reference_id=exclusion.id,
        status=ActionStatus.PROCESSING, attempts=1, max_attempts=5,
    )
    connection = GoogleConnection(
        id=uuid.uuid4(), organization_id=org_id, refresh_token_encrypted=encrypt("refresh-token"),
        customer_id=CID, login_customer_id=None, is_active=True, needs_reauth=False,
    )
    e = Env(worker=ActionWorker(), action=action, exclusion=exclusion, connection=connection)

    async def get_exclusion(db, exclusion_id, organization_id):
        if exclusion_id == e.exclusion.id and organization_id == e.exclusion.organization_id:
            return e.exclusion
        return None

    async def get_connection(db, exclusion):
        return e.connection

    async def increment_blocked(db, organization_id, ip):
        assert organization_id == e.exclusion.organization_id
        e.blocked.append(ip)

    monkeypatch.setattr(e.worker, "_get_exclusion", get_exclusion)
    monkeypatch.setattr(e.worker, "_get_connection_for_exclusion", get_connection)
    monkeypatch.setattr(e.worker, "_increment_blocked_count", increment_blocked)

    async def fake_refresh(refresh_token):
        e.token_calls.append(refresh_token)
        if e.token_error is None and refresh_token.startswith("rt-"):
            return {"access_token": f"token-for-{refresh_token}"}
        if e.token_error:
            raise e.token_error
        return {"access_token": "access-token"}

    class FakeAdapter:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        async def create_ip_exclusion(self, **kwargs):
            e.adapter_calls.append(("create", self.kwargs, kwargs))
            return e.adapter_result

        async def remove_ip_exclusion(self, **kwargs):
            e.adapter_calls.append(("remove", self.kwargs, kwargs))
            return e.adapter_result

    monkeypatch.setattr(worker_module, "refresh_access_token", fake_refresh)
    monkeypatch.setattr(worker_module, "GoogleAdsAdapter", FakeAdapter)
    return e


# ---- task 003: never report success without Google --------------------------

async def test_success_marks_active_with_real_resource_name(env):
    env.adapter_result = GoogleAdsApiResult(ok=True, resource_name=CRITERION, api_request_id="req-1")
    assert await env.run() == "successful"
    assert env.action.status == ActionStatus.SUCCESS
    assert env.exclusion.status == ExclusionStatus.ACTIVE
    assert env.exclusion.google_resource_name == CRITERION
    assert env.exclusion.api_request_id == "req-1"
    assert env.blocked == ["203.0.113.7"]


async def test_revoked_refresh_token_fails_and_flags_connection(env):
    env.token_error = GoogleAuthError("invalid_grant: Token has been revoked", permanent=True)
    assert await env.run() == "failed"
    assert env.action.status == ActionStatus.FAILED
    assert env.exclusion.status == ExclusionStatus.FAILED
    assert env.connection.needs_reauth is True
    assert "invalid_grant" in env.connection.auth_error
    assert env.adapter_calls == []
    assert env.blocked == []
    assert env.exclusion.api_request_id is None  # no fake request id


async def test_token_network_error_is_retried_not_failed(env):
    env.token_error = GoogleAuthError("network error", permanent=False)
    assert await env.run() == "retrying"
    assert env.action.status == ActionStatus.RETRYING
    assert env.exclusion.status == ExclusionStatus.PENDING
    assert env.connection.needs_reauth is False


async def test_undecryptable_refresh_token_is_permanent(env):
    env.connection.refresh_token_encrypted = "not-a-fernet-token"
    assert await env.run() == "failed"
    assert env.connection.needs_reauth is True
    assert env.token_calls == []


async def test_connection_already_flagged_skips_token_refresh(env):
    env.connection.needs_reauth = True
    env.connection.auth_error = "revoked"
    assert await env.run() == "failed"
    assert env.token_calls == [] and env.adapter_calls == []
    assert "re-authorization" in env.exclusion.last_error


async def test_google_not_configured_fails_clearly(env, monkeypatch):
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_ID", "")
    assert await env.run() == "failed"
    assert env.exclusion.status == ExclusionStatus.FAILED
    assert "not configured" in env.action.last_error
    assert env.blocked == []


async def test_dry_run_is_skipped_never_active(env, monkeypatch):
    monkeypatch.setattr(settings, "GOOGLE_ADS_DRY_RUN", True)
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_ID", "")
    assert await env.run() == "skipped"
    assert env.exclusion.status == ExclusionStatus.SKIPPED
    assert env.exclusion.google_resource_name is None
    assert env.blocked == []
    assert env.adapter_calls == [] and env.token_calls == []


async def test_adapter_auth_failure_flags_connection(env):
    env.adapter_result = GoogleAdsApiResult(
        ok=False, error_category=ErrorCategory.AUTH, error_code="authenticationError.OAUTH_TOKEN_REVOKED",
        message="revoked", api_request_id="req-auth",
    )
    assert await env.run() == "failed"
    assert env.connection.needs_reauth is True
    assert env.exclusion.api_request_id == "req-auth"  # Google's id, not ours
    assert "authenticationError.OAUTH_TOKEN_REVOKED" in env.exclusion.last_error


async def test_permanent_adapter_failure_fails_immediately(env):
    env.adapter_result = GoogleAdsApiResult(
        ok=False, retryable=False, error_category=ErrorCategory.INVALID_REQUEST, message="bad ip",
    )
    assert await env.run() == "failed"
    assert env.action.status == ActionStatus.FAILED
    assert env.exclusion.status == ExclusionStatus.FAILED


async def test_remove_success_marks_removed(env):
    env.action.action_type = ActionType.REMOVE_IP_EXCLUSION
    env.exclusion.status = ExclusionStatus.ACTIVE
    env.exclusion.google_resource_name = CRITERION
    env.adapter_result = GoogleAdsApiResult(ok=True, resource_name=None, message="not present")
    assert await env.run() == "successful"
    assert env.exclusion.status == ExclusionStatus.REMOVED
    assert env.adapter_calls[0][2]["resource_name"] == CRITERION


@pytest.mark.parametrize(
    ("status", "body", "permanent"),
    [
        (400, {"error": "invalid_grant", "error_description": "Token has been expired or revoked."}, True),
        (401, {"error": "invalid_client"}, True),
        (400, {"error": "unauthorized_client"}, True),
        (500, {"error": "internal_failure"}, False),
        (503, None, False),
        (429, None, False),
        (400, None, True),
    ],
)
def test_classify_token_error(status, body, permanent):
    error = classify_token_error(status, body)
    assert isinstance(error, GoogleAuthError) and isinstance(error, ValueError)
    assert error.permanent is permanent


# ---- task 008: exponential backoff, statuses, claiming ----------------------

T0 = datetime(2026, 10, 6, 12, 0, tzinfo=timezone.utc)


def test_backoff_doubles_from_configured_base_and_is_capped(monkeypatch):
    monkeypatch.setattr(settings, "ACTION_QUEUE_RETRY_BACKOFF_SECONDS", 30)
    monkeypatch.setattr(settings, "ACTION_QUEUE_RETRY_MAX_BACKOFF_SECONDS", 3600)
    no_jitter = lambda: 0.5  # noqa: E731
    delays = [(compute_next_attempt(n, T0, rand=no_jitter) - T0).total_seconds() for n in range(1, 10)]
    assert delays[:5] == [30, 60, 120, 240, 480]
    assert max(delays) == 3600


def test_backoff_jitter_stays_within_twenty_percent():
    low = compute_next_attempt(3, T0, rand=lambda: 0.0) - T0
    high = compute_next_attempt(3, T0, rand=lambda: 1.0) - T0
    assert low == timedelta(seconds=120 * 0.8) and high == timedelta(seconds=120 * 1.2)


async def test_retryable_failure_schedules_backoff_and_keeps_exclusion_pending(env):
    env.adapter_result = GoogleAdsApiResult(ok=False, retryable=True, error_category=ErrorCategory.TRANSIENT, message="503")
    before = datetime.now(timezone.utc)
    assert await env.run() == "retrying"
    assert env.action.status == ActionStatus.RETRYING
    assert env.exclusion.status == ExclusionStatus.PENDING
    delay = (env.action.scheduled_at - before).total_seconds()
    assert 30 * 0.8 - 1 <= delay <= 30 * 1.2 + 1
    assert "attempt 1/5" in env.exclusion.last_error and "next retry" in env.exclusion.last_error


async def test_retryable_failure_on_last_attempt_fails(env):
    env.adapter_result = GoogleAdsApiResult(ok=False, retryable=True, error_category=ErrorCategory.TRANSIENT, message="503")
    env.action.attempts = env.action.max_attempts
    assert await env.run() == "failed"
    assert env.action.status == ActionStatus.FAILED
    assert env.exclusion.status == ExclusionStatus.FAILED


async def test_transient_then_success_ends_active(env):
    env.adapter_result = GoogleAdsApiResult(ok=False, retryable=True, error_category=ErrorCategory.TRANSIENT, message="503")
    assert await env.run() == "retrying"
    env.action.attempts += 1  # the claim step increments on the next pass
    env.adapter_result = GoogleAdsApiResult(ok=True, resource_name=CRITERION, api_request_id="req-2")
    assert await env.run() == "successful"
    assert env.exclusion.status == ExclusionStatus.ACTIVE and env.exclusion.last_error is None


def test_max_attempts_default_comes_from_settings(monkeypatch):
    monkeypatch.setattr(settings, "ACTION_QUEUE_MAX_ATTEMPTS", 3)
    column_default = PlatformAction.__table__.c.max_attempts.default
    assert column_default.arg(None) == 3


def test_claim_query_skips_rows_locked_by_other_workers():
    sql = str(build_claim_query(T0).compile(dialect=postgresql.dialect()))
    assert "FOR UPDATE SKIP LOCKED" in sql
    assert "LIMIT" in sql


def test_reaper_requeues_only_stale_processing_actions(monkeypatch):
    monkeypatch.setattr(settings, "ACTION_QUEUE_STUCK_AFTER_SECONDS", 600)
    compiled = build_reap_stuck_actions(T0).compile(dialect=postgresql.dialect())
    sql, params = str(compiled), list(compiled.params.values())
    assert "platform_actions.status = " in sql and ActionStatus.PROCESSING in params
    assert "platform_actions.updated_at < " in sql and T0 - timedelta(seconds=600) in params
    assert ActionStatus.RETRYING in params


class ClaimDB:
    """Hands out queued actions one at a time, the way FOR UPDATE SKIP LOCKED would."""

    def __init__(self, actions):
        self.queue = list(actions)
        self.commits = 0

    async def execute(self, stmt):
        if getattr(stmt, "is_select", False):
            action = self.queue.pop(0) if self.queue else None
            return type("R", (), {"scalar_one_or_none": lambda self: action})()
        return None

    async def commit(self):
        self.commits += 1

    async def rollback(self):
        pass


async def test_process_pending_claims_each_action_once(env, monkeypatch):
    env.adapter_result = GoogleAdsApiResult(ok=True, resource_name=CRITERION)
    env.action.status = ActionStatus.PENDING
    env.action.attempts = 0
    seen = []

    async def record(db, action):
        seen.append((action.id, action.status, action.attempts))
        return "successful"

    monkeypatch.setattr(env.worker, "_process_action", record)
    metrics = await env.worker.process_pending(ClaimDB([env.action]))
    assert metrics["processed"] == 1 and metrics["successful"] == 1
    assert seen == [(env.action.id, ActionStatus.PROCESSING, 1)]


# ---- task 009: the exclusion's own connection and customer ------------------


def pg_sql(stmt):
    compiled = stmt.compile(dialect=postgresql.dialect())
    return str(compiled), list(compiled.params.values())


async def test_worker_uses_connection_and_customer_of_the_exclusions_campaign(env, monkeypatch):
    org = env.exclusion.organization_id
    c1 = GoogleConnection(id=uuid.uuid4(), organization_id=org, refresh_token_encrypted=encrypt("rt-c1"),
                          customer_id="1111111111", login_customer_id="9999999999", is_active=True, needs_reauth=False)
    c2 = GoogleConnection(id=uuid.uuid4(), organization_id=org, refresh_token_encrypted=encrypt("rt-c2"),
                          customer_id="2222222222", login_customer_id=None, is_active=True, needs_reauth=False)
    env.exclusion.google_customer_id = "1111111111"
    env.exclusion.google_campaign_id = uuid.uuid4()

    async def by_campaign(db, exclusion):  # C2 is newer, but the campaign belongs to C1
        return c1 if exclusion.google_campaign_id == env.exclusion.google_campaign_id else c2

    monkeypatch.setattr(env.worker, "_get_connection_for_exclusion", by_campaign)
    env.adapter_result = GoogleAdsApiResult(ok=True, resource_name=CRITERION)

    assert await env.run() == "successful"
    _, adapter_kwargs, _ = env.adapter_calls[0]
    assert adapter_kwargs == {"customer_id": "1111111111", "access_token": "token-for-rt-c1", "login_customer_id": "9999999999"}


async def test_changed_selected_customer_does_not_redirect_pending_exclusion(env):
    env.exclusion.google_customer_id = "1111111111"
    env.connection.customer_id = "2222222222"  # user selected another account afterwards
    env.adapter_result = GoogleAdsApiResult(ok=True, resource_name=CRITERION)
    await env.run()
    assert env.adapter_calls[0][1]["customer_id"] == "1111111111"


async def test_legacy_exclusion_without_customer_uses_its_connection(env):
    env.exclusion.google_customer_id = ""
    env.adapter_result = GoogleAdsApiResult(ok=True, resource_name=CRITERION)
    await env.run()
    assert env.adapter_calls[0][1]["customer_id"] == CID
    assert env.exclusion.google_customer_id == CID


async def test_disconnected_connection_fails_without_calling_google(env):
    env.connection.is_active = False
    assert await env.run() == "failed"
    assert "disconnected" in env.action.last_error
    assert env.token_calls == [] and env.adapter_calls == []


async def test_missing_connection_fails(env, monkeypatch):
    async def none(db, exclusion):
        return None

    monkeypatch.setattr(env.worker, "_get_connection_for_exclusion", none)
    assert await env.run() == "failed"
    assert CID in env.action.last_error


def test_connection_lookup_queries_are_org_scoped():
    exclusion = Exclusion(id=uuid.uuid4(), organization_id=uuid.uuid4(), google_campaign_id=uuid.uuid4(),
                          google_customer_id=CID, campaign_id="555", ip_address="203.0.113.7")
    sql, params = pg_sql(build_connection_by_campaign_query(exclusion))
    assert "JOIN google_campaigns ON google_campaigns.connection_id = google_connections.id" in sql
    assert exclusion.google_campaign_id in params and exclusion.organization_id in params

    sql, params = pg_sql(build_connection_by_customer_query(exclusion))
    assert "google_connections.customer_id = " in sql and CID in params
    assert exclusion.organization_id in params
    assert "ORDER BY google_connections.is_active DESC" in sql


async def test_enqueue_skips_connection_without_valid_customer():
    fraud = SimpleNamespace(id=uuid.uuid4(), organization_id=uuid.uuid4(), google_campaign_id=uuid.uuid4(),
                            ip_address="203.0.113.7", risk_score=95, confidence_score=95, verdict=Verdict.FRAUD)
    campaign = SimpleNamespace(id=fraud.google_campaign_id, campaign_id="555", protection_enabled=True,
                               campaign_type=None)
    connection = SimpleNamespace(id=uuid.uuid4(), customer_id="")

    class DB:
        added = []

        async def execute(self, stmt):
            return SimpleNamespace(first=lambda: (campaign, connection))

        def add(self, obj):
            self.added.append(obj)

    db = DB()
    result = await enqueue_exclusion_for_session(db, fraud)
    assert result.outcome == "no_customer" and result.actions == []
    assert db.added == []

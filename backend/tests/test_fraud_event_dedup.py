"""Task 005: re-scoring a session keeps one fraud_events row per rule."""
from __future__ import annotations

import uuid
from types import SimpleNamespace

from sqlalchemy.dialects import postgresql
from sqlalchemy.sql.dml import Insert, Update

from app.models import FraudEvent, Session, Verdict
from app.services.fraud_engine import (
    FraudEngine,
    build_rule_results_upsert,
    build_untrigger_stale_rules,
)
from app.services.risk_scorer import RiskRule

RULES = [
    RiskRule("CLICK_VELOCITY_RULE", "ABNORMAL_CLICK_VELOCITY", 25, 70, "velocity"),
    RiskRule("SESSION_BEHAVIOR_RULE", "ABNORMAL_SESSION_BEHAVIOR", 18, 60, "short"),
]


def pg(stmt) -> str:
    return str(stmt.compile(dialect=postgresql.dialect()))


def bot_session() -> Session:
    return Session(
        id=uuid.uuid4(), organization_id=uuid.uuid4(), website_id=uuid.uuid4(),
        session_token="s_session_test", ip_address=None, page_count=1, click_count=0,
        interaction_count=0, scroll_depth=0.0, session_duration_seconds=0.5,
        clicks_10_seconds=8, clicks_30_seconds=8, clicks_60_seconds=8, clicks_5_minutes=8,
        clicks_1_hour=8, clicks_24_hours=8, is_vpn=False, is_proxy=False, is_tor=False,
        is_datacenter=False, verdict=Verdict.SAFE, system_verdict=Verdict.SAFE,
    )


def test_upsert_targets_session_rule_constraint_and_retriggers():
    sql = pg(build_rule_results_upsert(bot_session(), RULES))
    assert "ON CONFLICT ON CONSTRAINT uq_fraud_events_session_rule DO UPDATE" in sql
    for column in ("score_contribution", "rule_confidence", "reason_text", "triggered", "updated_at"):
        assert f"{column} = " in sql.split("DO UPDATE", 1)[1]


def test_untrigger_only_touches_this_sessions_stale_rules():
    session_id = uuid.uuid4()
    sql = pg(build_untrigger_stale_rules(session_id, ["CLICK_VELOCITY_RULE"]))
    assert "UPDATE fraud_events SET triggered=" in sql
    assert "fraud_events.session_id = " in sql
    assert "fraud_events.rule_name NOT IN" in sql

    # No rule fires any more: every triggered row of the session is untriggered.
    assert "NOT IN" not in pg(build_untrigger_stale_rules(session_id, []))


class RecordingDB:
    def __init__(self):
        self.statements: list = []
        self.added: list = []

    async def execute(self, stmt):
        self.statements.append(stmt)
        return SimpleNamespace(scalar_one_or_none=lambda: None)

    def add(self, obj):
        self.added.append(obj)


async def test_rescoring_never_adds_fraud_event_rows_through_the_orm():
    db = RecordingDB()
    session = bot_session()
    engine = FraudEngine()

    for i in range(20):  # 20 tracking flushes of one session
        await engine.score(db, session, is_new_session=(i == 0), previous_verdict=session.verdict)

    assert not any(isinstance(obj, FraudEvent) for obj in db.added)
    upserts = [s for s in db.statements if isinstance(s, Insert)]
    untriggers = [s for s in db.statements if isinstance(s, Update)]
    assert len(upserts) == 20 and len(untriggers) == 20
    # Every upsert carries the same (session, rule) keys, so the table ends with one row per rule.
    keys = set()
    for stmt in upserts:
        params = stmt.compile(dialect=postgresql.dialect()).params
        rows = sum(1 for name in params if name.startswith("rule_name_m"))
        keys |= {(params[f"session_id_m{i}"], params[f"rule_name_m{i}"]) for i in range(rows)}
    assert {session_id for session_id, _ in keys} == {session.id}
    assert {"CLICK_VELOCITY_RULE", "SESSION_BEHAVIOR_RULE"} <= {rule for _, rule in keys}

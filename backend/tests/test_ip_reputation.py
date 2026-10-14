"""Tasks 006 / 020: reputation decays, needs history, follows feedback, never feeds on itself,
and feeds two rules: KNOWN_HIGH_RISK_IP (average past risk) and HIGH_FRAUD_HISTORY (fraud ratio)."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy.dialects import postgresql
from sqlalchemy.sql.dml import Insert

from app.models import Session, Verdict
from app.services.fraud_engine import FraudEngine
from app.services.ip_reputation import (
    ReputationEvidence,
    build_history_query,
    build_reputation_upsert,
    compute_reputation,
    counter_deltas,
    decay_weight,
)
from app.services.rules import FeatureContext, evaluate
from app.services.rules.repository import catalog_configs

NOW = datetime(2026, 10, 6, 12, 0, tzinfo=timezone.utc)
FRAUD, SAFE, MONITOR, FLAG_V = Verdict.FRAUD, Verdict.SAFE, Verdict.MONITOR, Verdict.FLAG


def history(*rows: tuple[float, Verdict, Verdict | None]):
    """rows: (age in days, system verdict, client final_label)."""
    return [(NOW - timedelta(days=age), verdict, label) for age, verdict, label in rows]


def make_session(**overrides) -> Session:
    fields = dict(
        id=uuid.uuid4(), organization_id=uuid.uuid4(), website_id=uuid.uuid4(),
        session_token="s_session_test", ip_address="203.0.113.7", page_count=3, click_count=2,
        interaction_count=4, scroll_depth=60.0, session_duration_seconds=90.0,
        clicks_10_seconds=1, clicks_30_seconds=1, clicks_60_seconds=1, clicks_5_minutes=1,
        clicks_1_hour=1, clicks_24_hours=1, is_vpn=False, is_proxy=False, is_tor=False,
        is_datacenter=False, verdict=SAFE, system_verdict=SAFE,
    )
    fields.update(overrides)
    return Session(**fields)


def rule_hits(evidence: ReputationEvidence, code: str) -> list:
    results = evaluate(FeatureContext(session=make_session(), reputation=evidence), catalog_configs())
    return [result for result in results if result.code == code]


def reputation_reasons(evidence: ReputationEvidence) -> list:
    return rule_hits(evidence, "KNOWN_HIGH_RISK_IP")


def history_reasons(evidence: ReputationEvidence) -> list:
    return rule_hits(evidence, "HIGH_FRAUD_HISTORY")


def test_decay_weight_halves_every_half_life():
    assert decay_weight(timedelta(0), 7) == 1.0
    assert decay_weight(timedelta(days=7), 7) == pytest.approx(0.5)
    assert decay_weight(timedelta(days=14), 7) == pytest.approx(0.25)


def test_known_suspicious_ip_triggers_rule():
    # Spec §75 test 3: several recent fraud sessions from this IP.
    evidence = compute_reputation(history(*[(0.1 * i, FRAUD, None) for i in range(5)]), now=NOW)
    assert evidence.score == 100 and evidence.has_enough_history
    [rule] = reputation_reasons(evidence)
    assert 0 < rule.score <= 30


def test_shared_ip_with_legitimate_history_does_not_trigger():
    # Spec §75 test 6: one bad session behind an office/carrier IP with many real users.
    evidence = compute_reputation(history((0.5, FRAUD, None), *[(0.1 * i, SAFE, None) for i in range(20)]), now=NOW)
    assert evidence.score < 10
    assert reputation_reasons(evidence) == []


def test_single_old_high_risk_session_does_not_trigger():
    evidence = compute_reputation(history((10, FRAUD, None)), now=NOW)
    assert not evidence.has_enough_history and evidence.score == 0
    assert reputation_reasons(evidence) == []


def test_old_fraud_decays_below_recent_legitimate_traffic():
    evidence = compute_reputation(
        history((28, FRAUD, None), (29, FRAUD, None), (30, FRAUD, None), (0, SAFE, None), (1, SAFE, None)),
        now=NOW,
    )
    assert evidence.sessions == 5
    assert evidence.score < 10
    assert reputation_reasons(evidence) == []


def test_client_feedback_overrides_system_verdict():
    flagged = history(*[(0.1 * i, FRAUD, None) for i in range(5)])
    cleared = history(*[(0.1 * i, FRAUD, SAFE) for i in range(5)])
    assert compute_reputation(flagged, now=NOW).score == 100
    assert compute_reputation(cleared, now=NOW).score == 0


def test_monitor_sessions_are_not_evidence():
    evidence = compute_reputation(history(*[(0, MONITOR, None)] * 10), now=NOW)
    assert evidence.sessions == 0 and evidence.score == 0 and evidence.fraud_ratio == 0


def test_contribution_scales_with_confidence():
    few = compute_reputation(history(*[(0, FRAUD, None)] * 3), now=NOW)   # 3 decayed sessions
    many = compute_reputation(history(*[(0, FRAUD, None)] * 10), now=NOW)  # full confidence
    assert reputation_reasons(few)[0].score < reputation_reasons(many)[0].score == 30


def test_history_query_excludes_current_session_and_is_org_scoped():
    session = make_session()
    compiled = build_history_query(session, now=NOW).compile(dialect=postgresql.dialect())
    sql, params = str(compiled), list(compiled.params.values())
    assert "sessions.id != " in sql and session.id in params
    assert "sessions.organization_id = " in sql and session.organization_id in params
    assert "sessions.ip_address = " in sql
    assert NOW - timedelta(days=30) in params
    # The current burst (last hour) is velocity's job, not history.
    assert "sessions.created_at < " in sql and NOW - timedelta(hours=1) in params


@pytest.mark.parametrize(
    ("is_new", "previous", "current", "expected"),
    [
        (True, None, FRAUD, (1, 1, 0)),
        (True, None, SAFE, (1, 0, 1)),
        (False, SAFE, SAFE, (0, 0, 0)),
        (False, SAFE, FRAUD, (0, 1, -1)),
        (False, FRAUD, MONITOR, (0, -1, 1)),
    ],
)
def test_counter_deltas(is_new, previous, current, expected):
    assert counter_deltas(is_new_session=is_new, previous_verdict=previous, current_verdict=current) == expected


def test_score_is_decayed_average_risk_of_past_sessions():
    rows = [(NOW - timedelta(days=1), MONITOR, None, 70), (NOW - timedelta(days=1), MONITOR, None, 50),
            (NOW - timedelta(days=1), FLAG_V, None, 66)]
    evidence = compute_reputation(rows, now=NOW)
    assert evidence.score == 62           # MONITOR / FLAG risk counts for KNOWN_HIGH_RISK_IP …
    assert evidence.sessions == 0         # … but they are not fraud / legit labels
    assert history_reasons(evidence) == []


# ---- HIGH_FRAUD_HISTORY (task 020) ----

def test_fraud_history_fires_on_mostly_fraud_ip():
    # 8 fraud and 2 legitimate sessions within 7 days.
    evidence = compute_reputation(
        history(*[(0.5 * i, FRAUD, None) for i in range(8)], (1, SAFE, None), (2, SAFE, None)), now=NOW
    )
    assert evidence.fraud_ratio >= 0.6
    [hit] = history_reasons(evidence)
    assert 0 < hit.score <= 35 and hit.category == "REPUTATION"


def test_fraud_history_ignores_mostly_legitimate_ip():
    evidence = compute_reputation(
        history(*[(0.5, FRAUD, None)] * 2, *[(0.1 * i, SAFE, None) for i in range(18)]), now=NOW
    )
    assert history_reasons(evidence) == []


def test_fraud_history_needs_minimum_sample():
    evidence = compute_reputation(history((0.1, FRAUD, None), (0.2, FRAUD, None)), now=NOW)
    assert evidence.fraud_ratio == 1.0
    assert history_reasons(evidence) == []


def test_client_marking_sessions_legitimate_stops_fraud_history():
    rows = [(0.2 * i, FRAUD, None) for i in range(6)] + [(0.3, SAFE, None)] * 2
    assert history_reasons(compute_reputation(history(*rows), now=NOW))
    # The client marks 5 of the fraud sessions legitimate.
    relabelled = [(age, verdict, SAFE if i < 5 else label) for i, (age, verdict, label) in enumerate(rows)]
    evidence = compute_reputation(history(*relabelled), now=NOW)
    assert evidence.fraud_ratio < 0.6
    assert history_reasons(evidence) == []


def test_reputation_upsert_is_atomic_per_org_ip():
    stmt = build_reputation_upsert(make_session(), ReputationEvidence(5, 0, 5), (0, 1, -1), now=NOW)
    sql = str(stmt.compile(dialect=postgresql.dialect()))
    assert "ON CONFLICT (organization_id, ip) DO UPDATE" in sql
    assert "total_sessions = (ip_reputation.total_sessions +" in sql
    assert "greatest(" in sql
    # The cached score is replaced by the decayed score, never max(old, new).
    assert "risk_score = excluded.risk_score" in sql


class HistoryDB:
    """execute(): history query -> fixed rows; anything else is recorded."""

    def __init__(self, rows):
        self.rows = rows
        self.writes = []

    async def execute(self, stmt):
        if getattr(stmt, "is_select", False):
            return SimpleNamespace(all=lambda: list(self.rows))
        self.writes.append(stmt)
        return SimpleNamespace()


async def test_rescoring_the_same_session_does_not_raise_its_own_risk(monkeypatch):
    # Before task 006: a session at ~72 pushed reputation to 72, and its next batch
    # read that back as +30. Now history excludes the session being scored.
    db = HistoryDB(history((1, FRAUD, None), *[(0.5 * i, SAFE, None) for i in range(6)]))
    session = make_session(
        session_duration_seconds=0.5, page_count=1, click_count=4, scroll_depth=0.0,
        clicks_10_seconds=8, clicks_30_seconds=8, clicks_60_seconds=8, clicks_5_minutes=8,
        clicks_1_hour=8, clicks_24_hours=8,
    )
    from app.core.config import settings

    monkeypatch.setattr(settings, "RULES_SOURCE", "code")
    engine = FraudEngine()
    scores = []
    for i in range(10):
        await engine.score(db, session, is_new_session=(i == 0), previous_verdict=session.verdict)
        scores.append(session.risk_score)
    assert len(set(scores)) == 1
    assert any(isinstance(stmt, Insert) and stmt.table.name == "ip_reputation" for stmt in db.writes)

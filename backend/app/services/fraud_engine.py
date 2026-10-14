"""
Fraud engine v1 (spec §21–28, §76): rules → categories → risk / confidence /
diversity → verdict under the organization's protection policy.

    features (app/services/features.py)
      → rule evaluation (app/services/rules, configuration from the database)
      → aggregation (app/services/scoring.py)
      → decision (app/services/protection_policy.py)

Every triggered rule is stored in fraud_events with its category and the rule
configuration used, so each verdict stays explainable (spec §33, §52).
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import func, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models import FraudEvent, Session, Verdict
from app.services.features import build_context
from app.services.ip_reputation import build_reputation_upsert, counter_deltas, load_reputation
from app.services.protection_policy import ProtectionPolicy, decide, decide_legacy, get_policy, risk_band
from app.services.rules.evaluators import RuleResult, evaluate
from app.services.rules.repository import load_rules
from app.services.scoring import aggregate, aggregate_legacy, verdict_confidence


def build_rule_results_upsert(session: Session, results: list[RuleResult]):
    """Insert triggered rules, or refresh the existing row for (session, rule)."""
    stmt = pg_insert(FraudEvent).values(
        [
            {
                "id": uuid.uuid4(),
                "session_id": session.id,
                "organization_id": session.organization_id,
                "rule_name": result.code,
                "reason_code": result.code,
                "reason_text": result.description,
                "score_contribution": result.score,
                "rule_confidence": result.confidence,
                "triggered": True,
                "category": result.category,
                "rule_version": result.version,
                "rule_config": result.config,
            }
            for result in results
        ]
    )
    return stmt.on_conflict_do_update(
        constraint="uq_fraud_events_session_rule",
        set_={
            "reason_code": stmt.excluded.reason_code,
            "reason_text": stmt.excluded.reason_text,
            "score_contribution": stmt.excluded.score_contribution,
            "rule_confidence": stmt.excluded.rule_confidence,
            "category": stmt.excluded.category,
            "rule_version": stmt.excluded.rule_version,
            "rule_config": stmt.excluded.rule_config,
            "triggered": True,
            "updated_at": func.now(),
        },
    )


def build_untrigger_stale_rules(session_id: uuid.UUID, current_rule_names: list[str]):
    """Rules that no longer fire stay as history with triggered=false."""
    stmt = update(FraudEvent).where(
        FraudEvent.session_id == session_id,
        FraudEvent.triggered.is_(True),
    )
    if current_rule_names:
        stmt = stmt.where(FraudEvent.rule_name.not_in(current_rule_names))
    return stmt.values(triggered=False, updated_at=func.now())


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    risk: int
    confidence: int
    diversity: int
    categories: dict[str, int]
    results: list[RuleResult]


def decide_session(session: Session, results: list[RuleResult], policy: ProtectionPolicy) -> Decision:
    """Pure: rule results → verdict (both scoring versions)."""
    agg = aggregate(results, session)
    if settings.SCORING_VERSION == 1:
        risk, confidence = aggregate_legacy(results)
        verdict = decide_legacy(risk, confidence)
    else:
        risk = agg.risk
        verdict = decide(risk, agg.evidence_confidence, agg.diversity, policy)
        confidence = verdict_confidence(verdict, agg)
    return Decision(verdict, risk, confidence, agg.diversity, agg.categories, results)


class FraudEngine:
    """Rule-based fraud scorer that combines independent signals into a verdict."""

    async def score(
        self,
        db: AsyncSession,
        session: Session,
        *,
        is_new_session: bool,
        previous_verdict: Verdict,
        policy: ProtectionPolicy | None = None,
    ) -> Decision:
        policy = policy or get_policy(None)
        rules = await load_rules(db, session.organization_id)
        # Built from this org's OTHER, earlier sessions on the IP, with decay (tasks 006, 020).
        reputation = await load_reputation(db, session)
        ctx = await build_context(db, session, rules, reputation)
        decision = decide_session(session, evaluate(ctx, rules), policy)

        # Sessions are re-scored on every tracking batch: keep one row per rule.
        await db.execute(build_untrigger_stale_rules(session.id, [r.code for r in decision.results]))
        if decision.results:
            await db.execute(build_rule_results_upsert(session, decision.results))

        session.risk_score = decision.risk
        session.confidence_score = decision.confidence
        session.risk_band = risk_band(decision.risk).value
        session.signal_diversity = decision.diversity
        session.risk_categories = decision.categories
        session.scoring_version = settings.SCORING_VERSION
        session.verdict = decision.verdict
        session.system_verdict = decision.verdict

        if reputation is not None:
            if session.final_label is not None and not is_new_session:
                deltas = (0, 0, 0)  # the client's label decides the counters (task 020)
            else:
                deltas = counter_deltas(
                    is_new_session=is_new_session,
                    previous_verdict=previous_verdict,
                    current_verdict=decision.verdict,
                )
            await db.execute(
                build_reputation_upsert(session, reputation, deltas, now=datetime.now(timezone.utc))
            )
        return decision

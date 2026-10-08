from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import func, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models import FraudEvent, Session, Verdict
from app.services.ip_reputation import build_reputation_upsert, counter_deltas, load_reputation
from app.services.risk_scorer import RiskRule, RiskScorer


def build_rule_results_upsert(session: Session, rules: list[RiskRule]):
    """Insert triggered rules, or refresh the existing row for (session, rule)."""
    stmt = pg_insert(FraudEvent).values(
        [
            {
                "id": uuid.uuid4(),
                "session_id": session.id,
                "organization_id": session.organization_id,
                "rule_name": rule.name,
                "reason_code": rule.reason_code,
                "reason_text": rule.description,
                "score_contribution": rule.score,
                "rule_confidence": rule.confidence,
                "triggered": True,
            }
            for rule in rules
        ]
    )
    return stmt.on_conflict_do_update(
        constraint="uq_fraud_events_session_rule",
        set_={
            "reason_code": stmt.excluded.reason_code,
            "reason_text": stmt.excluded.reason_text,
            "score_contribution": stmt.excluded.score_contribution,
            "rule_confidence": stmt.excluded.rule_confidence,
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


class FraudEngine:
    """Rule-based fraud scorer that combines several weak signals into a final risk verdict."""

    async def score(
        self,
        db: AsyncSession,
        session: Session,
        *,
        is_new_session: bool,
        previous_verdict: Verdict,
    ) -> None:
        # Built from this org's OTHER sessions on the IP, with decay (task 006).
        reputation = await load_reputation(db, session)
        rules, risk_score, confidence = RiskScorer.score_session(session, reputation)

        verdict = self._decide(risk_score, confidence)

        # Sessions are re-scored on every tracking batch: keep one row per rule.
        await db.execute(build_untrigger_stale_rules(session.id, [rule.name for rule in rules]))
        if rules:
            await db.execute(build_rule_results_upsert(session, rules))

        session.risk_score = risk_score
        session.confidence_score = confidence
        session.verdict = verdict
        session.system_verdict = verdict

        if reputation is not None:
            deltas = counter_deltas(
                is_new_session=is_new_session,
                previous_verdict=previous_verdict,
                current_verdict=verdict,
            )
            await db.execute(
                build_reputation_upsert(session, reputation, deltas, now=datetime.now(timezone.utc))
            )

    def _decide(self, risk: int, confidence: int) -> Verdict:
        if (
            risk >= settings.FRAUD_RISK_FRAUD_THRESHOLD
            and confidence >= settings.FRAUD_CONFIDENCE_MIN_FOR_BLOCK
        ):
            return Verdict.FRAUD
        if risk >= settings.FRAUD_RISK_MONITOR_THRESHOLD:
            return Verdict.MONITOR
        return Verdict.SAFE

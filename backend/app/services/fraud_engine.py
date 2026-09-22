from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models import FraudEvent, IPReputation, Session, Verdict
from app.services.risk_scorer import RiskScorer


class FraudEngine:
    """Rule-based fraud scorer that combines several weak signals into a final risk verdict."""

    async def score(self, db: AsyncSession, session: Session) -> None:
        rep = await self._get_ip_reputation(db, session.ip_address)
        rules, risk_score, confidence = RiskScorer.score_session(session, rep)

        verdict = self._decide(risk_score, confidence)

        for rule in rules:
            db.add(
                FraudEvent(
                    session_id=session.id,
                    organization_id=session.organization_id,
                    rule_name=rule.name,
                    reason_code=rule.reason_code,
                    reason_text=rule.description,
                    score_contribution=rule.score,
                    rule_confidence=rule.confidence,
                    triggered=True,
                )
            )

        session.risk_score = risk_score
        session.confidence_score = confidence
        session.verdict = verdict
        session.system_verdict = verdict

    async def _get_ip_reputation(
        self, db: AsyncSession, ip: str | None
    ) -> IPReputation | None:
        if not ip:
            return None
        result = await db.execute(
            select(IPReputation).where(IPReputation.ip == ip)
        )
        return result.scalar_one_or_none()

    def _decide(self, risk: int, confidence: int) -> Verdict:
        if (
            risk >= settings.FRAUD_RISK_FRAUD_THRESHOLD
            and confidence >= settings.FRAUD_CONFIDENCE_MIN_FOR_BLOCK
        ):
            return Verdict.FRAUD
        if risk >= settings.FRAUD_RISK_MONITOR_THRESHOLD:
            return Verdict.MONITOR
        return Verdict.SAFE

from __future__ import annotations

import math

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models import FraudEvent, IPReputation, Session, Verdict
from app.services.risk_scorer import RiskScorer
from app.services.fraud_ml import FraudMLService


class FraudEngine:
    """Rule-based fraud scorer that combines several weak signals into a final risk verdict."""

    def __init__(self) -> None:
        self.ml = FraudMLService()

    async def score(
        self,
        db: AsyncSession,
        session: Session,
        *,
        is_new_session: bool,
        previous_verdict: Verdict,
    ) -> None:
        rep = await self._get_ip_reputation(db, session.ip_address)
        rules, risk_score, confidence = RiskScorer.score_session(session, rep)
        ml_prediction = await self.ml.predict(db, session, rep)
        ml_weight = self._ml_weight(ml_prediction.sample_count)

        blended_risk = self._blend_score(risk_score, ml_prediction.risk_score, ml_weight)
        blended_confidence = self._blend_score(
            confidence, ml_prediction.confidence_score, ml_weight
        )
        verdict = self._decide(blended_risk, blended_confidence)

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

        if ml_prediction.sample_count > 0 and (ml_prediction.risk_score >= 50 or verdict == Verdict.FRAUD):
            db.add(
                FraudEvent(
                    session_id=session.id,
                    organization_id=session.organization_id,
                    rule_name="ML_ADAPTIVE_MODEL",
                    reason_code="ML_PREDICTION_SIGNAL",
                    reason_text=(
                        f"Adaptive model predicted {ml_prediction.risk_score}% fraud risk"
                        + (
                            f" using {ml_prediction.feature_summary}."
                            if ml_prediction.feature_summary
                            else "."
                        )
                    ),
                    score_contribution=max(0, blended_risk - risk_score),
                    rule_confidence=ml_prediction.confidence_score,
                    triggered=verdict == Verdict.FRAUD,
                )
            )

        session.risk_score = blended_risk
        session.confidence_score = blended_confidence
        session.verdict = verdict
        session.system_verdict = verdict
        extra_signals = dict(session.extra_signals or {})
        extra_signals["ml_risk_score"] = ml_prediction.risk_score
        extra_signals["ml_confidence_score"] = ml_prediction.confidence_score
        extra_signals["ml_model_version"] = ml_prediction.model_version
        extra_signals["ml_sample_count"] = ml_prediction.sample_count
        if ml_prediction.feature_summary:
            extra_signals["ml_feature_summary"] = ml_prediction.feature_summary
        session.extra_signals = extra_signals

        await self._upsert_ip_reputation(
            db,
            session=session,
            rep=rep,
            previous_verdict=previous_verdict,
            is_new_session=is_new_session,
        )

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

    def _blend_score(self, rule_score: int, ml_score: int, ml_weight: float) -> int:
        if ml_weight <= 0:
            return rule_score
        blended = rule_score * (1 - ml_weight) + ml_score * ml_weight
        return min(100, max(0, int(round(blended))))

    def _ml_weight(self, sample_count: int) -> float:
        if sample_count <= 0:
            return 0.0
        return min(0.35, 0.1 + math.log1p(sample_count) / 30.0)

    async def _upsert_ip_reputation(
        self,
        db: AsyncSession,
        *,
        session: Session,
        rep: IPReputation | None,
        previous_verdict: Verdict,
        is_new_session: bool,
    ) -> None:
        if not session.ip_address:
            return

        if rep is None:
            rep = IPReputation(
                ip=str(session.ip_address),
                first_seen=session.created_at,
                total_sessions=0,
                fraud_sessions=0,
                legitimate_sessions=0,
                blocked_count=0,
            )
            db.add(rep)

        rep.last_seen = session.created_at
        rep.country = session.country
        rep.asn = session.asn
        rep.isp = session.isp
        rep.is_vpn = bool(session.is_vpn)
        rep.is_proxy = bool(session.is_proxy)
        rep.is_tor = bool(session.is_tor)
        rep.is_datacenter = bool(session.is_datacenter)
        rep.risk_score = max(int(rep.risk_score or 0), int(session.risk_score or 0))
        rep.confidence = max(int(rep.confidence or 0), int(session.confidence_score or 0))

        if is_new_session:
            rep.total_sessions = int(rep.total_sessions or 0) + 1

        previous_was_fraud = previous_verdict == Verdict.FRAUD
        current_is_fraud = session.verdict == Verdict.FRAUD

        if is_new_session:
            if current_is_fraud:
                rep.fraud_sessions = int(rep.fraud_sessions or 0) + 1
            else:
                rep.legitimate_sessions = int(rep.legitimate_sessions or 0) + 1
            return

        if previous_was_fraud == current_is_fraud:
            return

        if current_is_fraud:
            rep.fraud_sessions = int(rep.fraud_sessions or 0) + 1
            rep.legitimate_sessions = max(0, int(rep.legitimate_sessions or 0) - 1)
        else:
            rep.fraud_sessions = max(0, int(rep.fraud_sessions or 0) - 1)
            rep.legitimate_sessions = int(rep.legitimate_sessions or 0) + 1

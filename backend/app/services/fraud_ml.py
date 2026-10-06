from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import FraudModelState, IPReputation, Session, Verdict


MODEL_VERSION = "online-logreg-v1"
MAX_ABS_WEIGHT = 6.0
BASE_LEARNING_RATE = 0.2
L2_PENALTY = 0.01


@dataclass(frozen=True)
class MLPrediction:
    risk_score: int
    confidence_score: int
    sample_count: int
    model_version: str
    feature_summary: str | None = None


class FraudMLService:
    """Small online learner that adapts fraud scoring from feedback labels."""

    def __init__(self) -> None:
        self.model_version = MODEL_VERSION

    async def predict(
        self,
        db: AsyncSession,
        session: Session,
        rep: IPReputation | None,
    ) -> MLPrediction:
        state = await self._get_state(db, session.organization_id)
        if state is None:
            return MLPrediction(
                risk_score=0,
                confidence_score=0,
                sample_count=0,
                model_version=self.model_version,
            )

        features = self._build_features(session=session, rep=rep)
        raw_score = float(state.bias or 0.0)
        contributions: list[tuple[str, float]] = []
        weights = state.weights or {}

        for name, value in features.items():
            if name == "bias":
                continue
            weight = float(weights.get(name, 0.0))
            contribution = weight * value
            raw_score += contribution
            contributions.append((name, contribution))

        probability = self._sigmoid(raw_score)
        confidence = self._prediction_confidence(state.sample_count, probability)
        summary = self._summarize_contributions(contributions)

        return MLPrediction(
            risk_score=int(round(probability * 100)),
            confidence_score=confidence,
            sample_count=state.sample_count,
            model_version=state.model_version or self.model_version,
            feature_summary=summary,
        )

    async def learn_from_feedback(
        self,
        db: AsyncSession,
        session: Session,
    ) -> FraudModelState | None:
        if session.final_label is None:
            return None

        extra_signals = dict(session.extra_signals or {})
        already_applied = (
            extra_signals.get("ml_feedback_applied") is True
            and extra_signals.get("ml_feedback_applied_label") == session.final_label.value
        )
        if already_applied:
            return await self._get_state(db, session.organization_id)

        state = await self._get_or_create_state(db, session.organization_id)
        rep = await self._get_ip_reputation(db, session.ip_address)
        features = self._build_features(session=session, rep=rep)
        target = 1.0 if session.final_label == Verdict.FRAUD else 0.0

        raw_score = float(state.bias or 0.0)
        weights = dict(state.weights or {})
        for name, value in features.items():
            if name == "bias":
                continue
            raw_score += float(weights.get(name, 0.0)) * value

        probability = self._sigmoid(raw_score)
        error = target - probability
        learning_rate = self._learning_rate(state.sample_count)

        for name, value in features.items():
            if name == "bias":
                continue
            current_weight = float(weights.get(name, 0.0))
            updated_weight = current_weight + learning_rate * (
                error * value - L2_PENALTY * current_weight
            )
            weights[name] = self._clip(updated_weight)

        state.weights = weights
        state.bias = self._clip(float(state.bias or 0.0) + learning_rate * error)
        state.sample_count = int(state.sample_count or 0) + 1
        if session.final_label == Verdict.FRAUD:
            state.fraud_samples = int(state.fraud_samples or 0) + 1
        else:
            state.legitimate_samples = int(state.legitimate_samples or 0) + 1
        state.model_version = self.model_version
        state.last_trained_at = datetime.now(timezone.utc)

        extra_signals["ml_feedback_applied"] = True
        extra_signals["ml_feedback_applied_label"] = session.final_label.value
        extra_signals["ml_feedback_trained_at"] = state.last_trained_at.isoformat()
        session.extra_signals = extra_signals

        return state

    async def _get_state(
        self, db: AsyncSession, organization_id
    ) -> FraudModelState | None:
        result = await db.execute(
            select(FraudModelState).where(
                FraudModelState.organization_id == organization_id
            )
        )
        return result.scalar_one_or_none()

    async def _get_or_create_state(
        self, db: AsyncSession, organization_id
    ) -> FraudModelState:
        state = await self._get_state(db, organization_id)
        if state is not None:
            return state

        state = FraudModelState(
            organization_id=organization_id,
            model_version=self.model_version,
            weights={},
            bias=0.0,
            sample_count=0,
            fraud_samples=0,
            legitimate_samples=0,
        )
        db.add(state)
        await db.flush()
        return state

    async def _get_ip_reputation(
        self, db: AsyncSession, ip: str | None
    ) -> IPReputation | None:
        if not ip:
            return None
        result = await db.execute(select(IPReputation).where(IPReputation.ip == ip))
        return result.scalar_one_or_none()

    def _build_features(
        self,
        *,
        session: Session,
        rep: IPReputation | None,
    ) -> dict[str, float]:
        page_count = max(float(session.page_count or 0), 0.0)
        click_count = max(float(session.click_count or 0), 0.0)
        duration = max(float(session.session_duration_seconds or 0.0), 0.0)
        scroll_depth = max(float(session.scroll_depth or 0.0), 0.0)
        clicks_30 = max(float(session.clicks_30_seconds or 0), 0.0)
        clicks_60 = max(float(session.clicks_60_seconds or 0), 0.0)
        clicks_5m = max(float(session.clicks_5_minutes or 0), 0.0)
        clicks_1h = max(float(session.clicks_1_hour or 0), 0.0)
        click_density = click_count / max(page_count, 1.0)
        user_agent = (session.user_agent or "").casefold()

        return {
            "bias": 1.0,
            "rule_risk": min(max(float(session.risk_score or 0) / 100.0, 0.0), 1.0),
            "rule_confidence": min(max(float(session.confidence_score or 0) / 100.0, 0.0), 1.0),
            "click_velocity_30": min(clicks_30 / 6.0, 2.0),
            "click_velocity_60": min(clicks_60 / 8.0, 2.0),
            "click_velocity_5m": min(clicks_5m / 12.0, 2.0),
            "click_velocity_1h": min(clicks_1h / 20.0, 2.0),
            "session_short": max(0.0, (30.0 - duration) / 30.0),
            "low_page_depth": max(0.0, (3.0 - page_count) / 3.0),
            "low_scroll": max(0.0, (50.0 - scroll_depth) / 50.0),
            "high_click_density": min(click_density / 5.0, 2.0),
            "vpn_proxy": 1.0 if session.is_vpn or session.is_proxy or session.is_tor else 0.0,
            "datacenter": 1.0 if session.is_datacenter else 0.0,
            "bot_signature": 1.0 if any(token in user_agent for token in ("bot", "crawler", "spider")) else 0.0,
            "ip_risk": min(max(float(rep.risk_score or 0) / 100.0, 0.0), 1.0) if rep else 0.0,
            "ip_confidence": min(max(float(rep.confidence or 0) / 100.0, 0.0), 1.0) if rep else 0.0,
            "ip_fraud_ratio": self._fraud_ratio(rep),
        }

    def _prediction_confidence(self, sample_count: int, probability: float) -> int:
        if sample_count <= 0:
            return 0
        sample_signal = min(35.0, math.log1p(sample_count) * 7.0)
        certainty_signal = abs(probability - 0.5) * 2.0 * 40.0
        return min(100, int(round(25.0 + sample_signal + certainty_signal)))

    def _learning_rate(self, sample_count: int) -> float:
        return BASE_LEARNING_RATE / math.sqrt(max(sample_count, 0) + 1.0)

    def _summarize_contributions(self, contributions: list[tuple[str, float]]) -> str | None:
        if not contributions:
            return None
        top = sorted(contributions, key=lambda item: abs(item[1]), reverse=True)[:3]
        if not top:
            return None
        return ", ".join(
            f"{name}={value:+.2f}" for name, value in top if abs(value) > 0.01
        ) or None

    def _clip(self, value: float) -> float:
        return max(-MAX_ABS_WEIGHT, min(MAX_ABS_WEIGHT, value))

    def _sigmoid(self, value: float) -> float:
        if value >= 0:
            z = math.exp(-value)
            return 1.0 / (1.0 + z)
        z = math.exp(value)
        return z / (1.0 + z)

    def _fraud_ratio(self, rep: IPReputation | None) -> float:
        if rep is None:
            return 0.0
        total = max(int(rep.total_sessions or 0), 1)
        fraud = max(int(rep.fraud_sessions or 0), 0)
        return min(fraud / total, 1.0)

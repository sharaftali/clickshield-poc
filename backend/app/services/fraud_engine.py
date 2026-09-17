from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models import FraudEvent, IPReputation, Session, Verdict


class FraudEngine:
    """
    Rule-based fraud scorer. No ML. Signals combine — a single signal
    never triggers FRAUD (spec §23, §27, §73).
    """

    async def score(self, db: AsyncSession, session: Session) -> None:
        contributions: list[tuple[str, str, int, int]] = []
        # (rule_name, reason_code, score, confidence)

        # Rule 1: Click velocity
        if session.clicks_60_seconds >= 8:
            contributions.append(
                ("CLICK_VELOCITY_RULE", "ABNORMAL_CLICK_VELOCITY", 20, 60)
            )

        # Rule 2: IP reputation (historical)
        rep = await self._get_ip_reputation(db, session.ip_address)
        if rep and rep.risk_score > 70:
            contributions.append(
                ("IP_REPUTATION_RULE", "HIGH_RISK_IP_REPUTATION", 25, 70)
            )

        # Rule 3: VPN/Proxy — signal only, low weight
        if session.is_vpn or session.is_proxy:
            contributions.append(
                ("VPN_PROXY_RULE", "VPN_PROXY_DETECTED", 10, 40)
            )

        # Rule 4: Datacenter
        if session.is_datacenter:
            contributions.append(
                ("DATACENTER_RULE", "DATACENTER_DETECTED", 10, 40)
            )

        # Rule 5: Abnormal session behavior (bounce)
        if session.session_duration_seconds < 2 and session.page_count <= 1:
            contributions.append(
                ("SESSION_BEHAVIOR_RULE", "ABNORMAL_SESSION_BEHAVIOR", 15, 50)
            )

        # Compute raw score
        raw_score = sum(c[2] for c in contributions)
        risk_score = min(raw_score, 100)

        # Confidence scales with signal diversity — more signals, more confidence
        signal_count = len(contributions)
        if signal_count == 0:
            confidence = 0
        else:
            # Base confidence + diversity bonus
            base = sum(c[3] for c in contributions) / signal_count
            diversity_bonus = min(signal_count * 10, 30)
            confidence = min(int(base + diversity_bonus), 100)

        # Decision
        verdict = self._decide(risk_score, confidence)

        # Persist fraud events
        for rule_name, reason_code, score, conf in contributions:
            db.add(
                FraudEvent(
                    session_id=session.id,
                    organization_id=session.organization_id,
                    rule_name=rule_name,
                    reason_code=reason_code,
                    score_contribution=score,
                    rule_confidence=conf,
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

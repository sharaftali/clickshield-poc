from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from app.core.config import settings
from app.models.traffic import Session

if TYPE_CHECKING:
    from app.services.ip_reputation import ReputationEvidence


@dataclass(frozen=True)
class RiskRule:
    name: str
    reason_code: str
    score: int
    confidence: int
    description: str


class RiskScorer:
    """Combine weak fraud signals into a single risk score without relying on any single indicator."""

    @staticmethod
    def score_session(
        session: Session, reputation: ReputationEvidence | None
    ) -> tuple[list[RiskRule], int, int]:
        rules: list[RiskRule] = []

        clicks_60_seconds = int(session.clicks_60_seconds or 0)
        clicks_30_seconds = int(session.clicks_30_seconds or 0)
        page_count = int(session.page_count or 0)
        click_count = int(session.click_count or 0)
        scroll_depth = float(session.scroll_depth or 0.0)
        session_duration_seconds = float(session.session_duration_seconds or 0.0)
        user_agent = (session.user_agent or "").lower()

        # clicks_* = paid ad landings from the same IP/visitor across sessions (spec §16),
        # not on-page clicks. click_count below is on-page clicks (engagement only).
        if clicks_60_seconds >= settings.VELOCITY_CLICKS_60S_THRESHOLD:
            rules.append(
                RiskRule(
                    name="CLICK_VELOCITY_RULE",
                    reason_code="ABNORMAL_CLICK_VELOCITY",
                    score=25,
                    confidence=70,
                    description="The same IP or visitor clicked the ad unusually often within 60 seconds.",
                )
            )

        if (
            clicks_30_seconds >= settings.BURST_CLICKS_30S_THRESHOLD
            and session_duration_seconds < settings.BURST_MAX_SESSION_SECONDS
        ):
            rules.append(
                RiskRule(
                    name="BURST_CLICK_RULE",
                    reason_code="BURST_CLICK_PATTERN",
                    score=15,
                    confidence=65,
                    description="Repeated ad clicks occurred in a short burst with minimal browsing time.",
                )
            )

        # Decayed history of this org's other sessions on the IP (spec §14): contributes in
        # proportion to its score and confidence, and only with enough history.
        if (
            reputation is not None
            and reputation.has_enough_history
            and reputation.score >= settings.REPUTATION_RULE_MIN_SCORE
        ):
            contribution = round(
                settings.REPUTATION_RULE_MAX_WEIGHT * (reputation.score / 100) * (reputation.confidence / 100)
            )
            if contribution > 0:
                rules.append(
                    RiskRule(
                        name="IP_REPUTATION_RULE",
                        reason_code="HIGH_RISK_IP_REPUTATION",
                        score=contribution,
                        confidence=min(90, 50 + reputation.confidence // 2),
                        description=(
                            f"Recent sessions from this IP were mostly fraudulent "
                            f"({reputation.score}% of {reputation.sessions} labelled sessions, decayed)."
                        ),
                    )
                )

        if session.is_vpn or session.is_proxy or session.is_tor:
            rules.append(
                RiskRule(
                    name="ANONYMITY_RULE",
                    reason_code="VPN_PROXY_DETECTED",
                    score=10,
                    confidence=55,
                    description="The session originates from a VPN, proxy or TOR exit path.",
                )
            )

        if session.is_datacenter:
            rules.append(
                RiskRule(
                    name="DATACENTER_RULE",
                    reason_code="DATACENTER_DETECTED",
                    score=12,
                    confidence=60,
                    description="The traffic appears to originate from a datacenter or hosting network.",
                )
            )

        if session_duration_seconds < 2 and page_count <= 1:
            rules.append(
                RiskRule(
                    name="SESSION_BEHAVIOR_RULE",
                    reason_code="ABNORMAL_SESSION_BEHAVIOR",
                    score=18,
                    confidence=60,
                    description="The session had a very short lifetime and almost no browsing depth.",
                )
            )

        if page_count <= 1 and click_count >= 3 and scroll_depth < 20:
            rules.append(
                RiskRule(
                    name="LOW_ENGAGEMENT_RULE",
                    reason_code="LOW_ENGAGEMENT_WITH_HIGH_CLICKS",
                    score=14,
                    confidence=58,
                    description="High click activity without corresponding page engagement suggests automation or bot behavior.",
                )
            )

        if user_agent and ("bot" in user_agent or "crawler" in user_agent or "spider" in user_agent):
            rules.append(
                RiskRule(
                    name="BOT_SIGNATURE_RULE",
                    reason_code="BOT_USER_AGENT_DETECTED",
                    score=18,
                    confidence=65,
                    description="The browser user-agent matches a known bot, crawler, or automated client signature.",
                )
            )

        risk_score = min(100, sum(rule.score for rule in rules))
        if not rules:
            return [], 0, 0

        confidence = min(
            100,
            int(sum(rule.confidence for rule in rules) / len(rules) + min(len(rules) * 8, 22)),
        )

        return rules, risk_score, confidence

"""
Turning rule results into risk, confidence and signal diversity (spec §24, §27, §28; task 014).

- Risk: within a category the strongest rule counts fully and the next ones less
  (SCORING_DIMINISHING_FACTORS), each category is capped (SCORING_CATEGORY_CAPS),
  and the category totals are summed (max 100). Correlated rules — velocity,
  burst and repeat clicks are all "the same source clicks a lot" — can no longer
  stack into FRAUD on their own.
- Diversity: categories contributing at least SCORING_MIN_CATEGORY_CONTRIBUTION.
- Confidence describes the verdict:
  * suspicious verdicts — how strong the independent evidence is: the strongest
    rule confidence per category, combined as independent evidence
    (1 − Π(1 − cᵢ)), slightly reduced without IP intelligence;
  * SAFE — how completely the session was observed (IP data, duration, events)
    and how little fired. A clean, long, engaged session is confidently SAFE.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from math import prod

from app.core.config import settings
from app.models import Session, Verdict
from app.services.rules.evaluators import RuleResult

MAX_CONFIDENCE = 99
# Evidence confidence when the IP couldn't be enriched: network rules had no chance to fire.
MISSING_IP_DATA_FACTOR = 0.9
COMPLETENESS_WEIGHTS = {"ip_data": 0.35, "duration": 0.35, "events": 0.30}


@dataclass(frozen=True)
class Aggregate:
    risk: int
    evidence_confidence: int
    diversity: int
    categories: dict[str, int] = field(default_factory=dict)
    completeness: float = 0.0


def has_ip_data(session: Session) -> bool:
    return bool(session.country or session.asn or session.isp)


def data_completeness(session: Session) -> float:
    """0–1: how much of the session we could observe."""
    duration = min(1.0, float(session.session_duration_seconds or 0) / settings.SCORING_FULL_OBSERVATION_SECONDS)
    events = min(1.0, (int(session.page_count or 0) + int(session.interaction_count or 0)) / settings.SCORING_FULL_EVENT_COUNT)
    parts = {"ip_data": 1.0 if has_ip_data(session) else 0.0, "duration": duration, "events": events}
    return sum(COMPLETENESS_WEIGHTS[name] * value for name, value in parts.items())


def category_contributions(results: list[RuleResult]) -> dict[str, int]:
    factors = settings.SCORING_DIMINISHING_FACTORS or [1.0]
    by_category: dict[str, list[int]] = defaultdict(list)
    for result in results:
        by_category[result.category].append(result.score)
    contributions = {}
    for category, scores in by_category.items():
        scores.sort(reverse=True)
        total = sum(score * factors[min(i, len(factors) - 1)] for i, score in enumerate(scores))
        cap = settings.SCORING_CATEGORY_CAPS.get(category, 100)
        contributions[category] = min(cap, round(total))
    return contributions


def aggregate(results: list[RuleResult], session: Session) -> Aggregate:
    categories = category_contributions(results)
    risk = min(100, sum(categories.values()))
    diversity = sum(1 for value in categories.values() if value >= settings.SCORING_MIN_CATEGORY_CONTRIBUTION)

    strongest: dict[str, int] = {}
    for result in results:
        strongest[result.category] = max(strongest.get(result.category, 0), result.confidence)
    evidence = 1 - prod(1 - min(100, c) / 100 for c in strongest.values()) if strongest else 0.0
    if not has_ip_data(session):
        evidence *= MISSING_IP_DATA_FACTOR
    return Aggregate(
        risk=risk,
        evidence_confidence=min(MAX_CONFIDENCE, round(100 * evidence)),
        diversity=diversity,
        categories=categories,
        completeness=data_completeness(session),
    )


def verdict_confidence(verdict: Verdict, agg: Aggregate) -> int:
    if verdict != Verdict.SAFE:
        return agg.evidence_confidence
    return min(MAX_CONFIDENCE, round(100 * agg.completeness * (1 - agg.risk / 100)))


def aggregate_legacy(results: list[RuleResult]) -> tuple[int, int]:
    """SCORING_VERSION=1: the original sum of scores and average confidence + count bonus."""
    if not results:
        return 0, 0
    risk = min(100, sum(result.score for result in results))
    confidence = min(
        100,
        int(sum(result.confidence for result in results) / len(results) + min(len(results) * 8, 22)),
    )
    return risk, confidence

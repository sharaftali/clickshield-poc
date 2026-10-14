"""Tasks 014 (signal diversity, confidence), 016 (protection modes) and 017 (bands, FLAG)."""
from __future__ import annotations

import uuid

import pytest

from app.models import Organization, ProtectionMode, Session, Verdict
from app.services.fraud_engine import decide_session
from app.services.protection_policy import (
    ProtectionPolicy,
    RiskBand,
    decide,
    get_policy,
    mode_defaults,
    risk_band,
    validate_custom_settings,
)
from app.services.rules import FeatureContext, RuleResult, evaluate
from app.services.rules.repository import catalog_configs
from app.services.scoring import aggregate, category_contributions, data_completeness, verdict_confidence

BALANCED = get_policy(None)
SAFE, MONITOR, FLAG, FRAUD = Verdict.SAFE, Verdict.MONITOR, Verdict.FLAG, Verdict.FRAUD


def result(code: str, category: str, score: int, confidence: int = 65) -> RuleResult:
    return RuleResult(code, code.title(), category, score, confidence, code, 1, {})


def session(**overrides) -> Session:
    fields = dict(
        id=uuid.uuid4(), organization_id=uuid.uuid4(), website_id=uuid.uuid4(), session_token="s_test_0001",
        ip_address="203.0.113.9", page_count=1, click_count=0, interaction_count=0, scroll_depth=0.0,
        session_duration_seconds=0.5, clicks_10_seconds=1, clicks_30_seconds=1, clicks_60_seconds=1,
        clicks_5_minutes=1, clicks_1_hour=1, clicks_24_hours=1, is_vpn=False, is_proxy=False,
        is_tor=False, is_datacenter=False, country="US", verdict=SAFE, system_verdict=SAFE,
    )
    fields.update(overrides)
    return Session(**fields)


def scored(s: Session, policy: ProtectionPolicy = BALANCED):
    return decide_session(s, evaluate(FeatureContext(session=s), catalog_configs()), policy)


# ---- aggregation (task 014) ----

def test_rules_in_one_category_have_diminishing_returns_and_a_cap():
    contributions = category_contributions([
        result("A", "VELOCITY", 25), result("B", "VELOCITY", 20), result("C", "VELOCITY", 15),
    ])
    assert contributions == {"VELOCITY": 39}  # 25 + 10 + 3.75, under the cap of 40
    capped = category_contributions([result("A", "NETWORK", 12), result("B", "NETWORK", 10)] * 3)
    assert capped["NETWORK"] == 25


def test_vpn_only_is_never_fraud_whatever_its_risk():
    # Spec §27: risk 85 from VPN alone → do not block. Even an absurd VPN weight stays one category.
    agg = aggregate([result("VPN_DETECTED", "NETWORK", 85, 99)], session(is_vpn=True))
    assert agg.diversity == 1
    assert decide(85, 99, agg.diversity, BALANCED) != FRAUD


def test_datacenter_plus_vpn_is_still_one_category():
    agg = aggregate([result("VPN_DETECTED", "NETWORK", 10), result("DATACENTER_DETECTED", "NETWORK", 12)], session())
    assert agg.diversity == 1 and agg.risk == 17


def test_correlated_click_and_behaviour_rules_alone_are_not_fraud():
    # Velocity + burst + low engagement + short session: two categories only.
    s = session(clicks_30_seconds=12, clicks_60_seconds=12, click_count=5, session_duration_seconds=0.5)
    decision = scored(s)
    assert {r.code for r in decision.results} >= {
        "ABNORMAL_CLICK_VELOCITY", "BURST_CLICK_PATTERN", "UNUSUAL_SESSION", "LOW_ENGAGEMENT_WITH_HIGH_CLICKS"}
    assert decision.diversity == 2
    assert decision.verdict != FRAUD


def test_spec_27_many_independent_signals_are_high_confidence_fraud():
    results = [
        result("VPN_DETECTED", "NETWORK", 10, 55),
        result("ABNORMAL_CLICK_VELOCITY", "VELOCITY", 25, 70),
        result("KNOWN_HIGH_RISK_IP", "REPUTATION", 27, 85),
        result("UNUSUAL_SESSION", "BEHAVIOR", 18, 60),
        result("REPEATED_IDENTICAL_SESSIONS", "AUTOMATION", 20, 65),
    ]
    s = session(is_vpn=True)
    agg = aggregate(results, s)
    verdict = decide(agg.risk, agg.evidence_confidence, agg.diversity, BALANCED)
    assert verdict == FRAUD
    assert agg.diversity == 5 and verdict_confidence(verdict, agg) >= 90


def test_velocity_reputation_automation_is_fraud_when_risk_and_confidence_pass():
    results = [result("V", "VELOCITY", 35, 70), result("R", "REPUTATION", 30, 85), result("A", "AUTOMATION", 20, 65)]
    agg = aggregate(results, session())
    assert agg.diversity == 3 and agg.risk == 85
    assert decide(agg.risk, agg.evidence_confidence, agg.diversity, BALANCED) == FRAUD


def test_clean_complete_session_is_confidently_safe():
    s = session(session_duration_seconds=180.0, page_count=4, interaction_count=8, scroll_depth=80.0)
    decision = scored(s)
    assert decision.results == [] and decision.verdict == SAFE
    assert decision.confidence >= 80


def test_clean_but_barely_observed_session_has_low_confidence():
    s = session(country=None, session_duration_seconds=0.0, page_count=1, interaction_count=0)
    decision = scored(s)
    assert decision.verdict == SAFE and decision.confidence < 30
    assert data_completeness(s) < 0.2


def test_scoring_version_1_reproduces_the_old_aggregation(monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "SCORING_VERSION", 1)
    s = session(clicks_60_seconds=9, clicks_30_seconds=9)
    decision = scored(s)
    # velocity 25 + burst 15 + short session 18; confidence avg(70, 65, 60) + 22
    assert decision.risk == 58 and decision.confidence == 87 and decision.verdict == MONITOR


# ---- bands and verdict matrix (task 017) ----

@pytest.mark.parametrize(("risk", "band"), [(0, "LOW"), (29, "LOW"), (30, "MODERATE"), (59, "MODERATE"),
                                            (60, "HIGH"), (79, "HIGH"), (80, "VERY_HIGH"), (100, "VERY_HIGH")])
def test_risk_bands(risk, band):
    assert risk_band(risk) == RiskBand(band)


@pytest.mark.parametrize(
    ("risk", "confidence", "diversity", "expected"),
    [
        (10, 99, 5, SAFE),       # LOW → SAFE, whatever else
        (35, 20, 1, MONITOR),    # MODERATE → MONITOR (was SAFE before task 017)
        (55, 95, 4, MONITOR),
        (65, 85, 3, FLAG),       # HIGH + high confidence + diversity → FLAG
        (65, 85, 1, MONITOR),    # … one category only → MONITOR
        (65, 60, 3, MONITOR),    # … medium confidence → MONITOR
        (82, 51, 3, MONITOR),    # spec §28: risk 82, confidence 51 → MONITOR
        (82, 70, 3, FLAG),       # VERY HIGH, medium confidence → FLAG
        (82, 95, 2, FLAG),       # VERY HIGH, confident, diversity below Balanced's 3 → FLAG
        (82, 95, 1, MONITOR),    # one category never even reaches review
        (88, 93, 3, FRAUD),      # spec §28: risk 88, confidence 93 → FRAUD
    ],
)
def test_verdict_matrix_balanced(risk, confidence, diversity, expected):
    assert decide(risk, confidence, diversity, BALANCED) == expected


# ---- protection modes (task 016) ----

def org(mode: ProtectionMode, settings: dict | None = None) -> Organization:
    return Organization(name="x", slug="x", protection_mode=mode, protection_settings=settings)


@pytest.mark.parametrize("mode", [ProtectionMode.CONSERVATIVE, ProtectionMode.BALANCED, ProtectionMode.AGGRESSIVE])
def test_each_mode_resolves_to_its_configured_policy(mode):
    policy = get_policy(org(mode))
    assert policy.mode == mode
    assert {k: getattr(policy, k) for k in mode_defaults(mode)} == mode_defaults(mode)


def test_borderline_session_depends_on_mode():
    # risk 75, confidence 75, diversity 3
    verdicts = {mode: decide(75, 75, 3, get_policy(org(mode))) for mode in
                (ProtectionMode.CONSERVATIVE, ProtectionMode.BALANCED, ProtectionMode.AGGRESSIVE)}
    assert verdicts[ProtectionMode.AGGRESSIVE] == FRAUD
    assert verdicts[ProtectionMode.BALANCED] in (FLAG, MONITOR)
    assert verdicts[ProtectionMode.CONSERVATIVE] in (FLAG, MONITOR)


def test_aggressive_never_produces_fewer_fraud_verdicts_than_conservative():
    conservative, aggressive = get_policy(org(ProtectionMode.CONSERVATIVE)), get_policy(org(ProtectionMode.AGGRESSIVE))
    for risk in range(0, 101, 5):
        for confidence in range(0, 101, 5):
            for diversity in range(0, 6):
                if decide(risk, confidence, diversity, conservative) == FRAUD:
                    assert decide(risk, confidence, diversity, aggressive) == FRAUD


def test_custom_mode_uses_stored_thresholds():
    policy = get_policy(org(ProtectionMode.CUSTOM, {"flag_risk": 55, "fraud_risk": 75, "fraud_confidence": 70,
                                                    "min_diversity": 2, "auto_exclude": False}))
    assert (policy.fraud_risk, policy.min_diversity, policy.auto_exclude) == (75, 2, False)
    assert decide(76, 71, 2, policy) == FRAUD


@pytest.mark.parametrize(
    "values",
    [{"min_diversity": 1}, {"min_diversity": 0}, {"fraud_risk": 20}, {"fraud_confidence": 10},
     {"flag_risk": 90, "fraud_risk": 80}, {"surprise": 1}],
)
def test_custom_settings_enforce_safety_floors(values):
    with pytest.raises(ValueError):
        validate_custom_settings(values)


def test_invalid_stored_custom_settings_fall_back_to_balanced():
    policy = get_policy(org(ProtectionMode.CUSTOM, {"min_diversity": 1}))
    assert policy.min_diversity == BALANCED.min_diversity

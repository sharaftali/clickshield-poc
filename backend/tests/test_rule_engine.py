"""Task 015: rules are configuration. Regression against the hard-coded scorer that came before."""
from __future__ import annotations

import uuid
from dataclasses import replace
from types import SimpleNamespace

import pytest

from app.models import RuleOverride, Session, Verdict
from app.services.rules import CATALOG, EVALUATORS, FeatureContext, evaluate, validate_params
from app.services.rules.evaluators import RuleConfig
from app.services.rules.repository import apply_override, catalog_configs
from app.services.scoring import aggregate_legacy

LEGACY_CODES = {
    "ABNORMAL_CLICK_VELOCITY", "BURST_CLICK_PATTERN", "KNOWN_HIGH_RISK_IP", "VPN_DETECTED", "PROXY_DETECTED",
    "TOR_DETECTED", "DATACENTER_DETECTED", "UNUSUAL_SESSION", "LOW_ENGAGEMENT_WITH_HIGH_CLICKS",
    "BOT_USER_AGENT_DETECTED",
}


def legacy_score(session: Session, reputation) -> tuple[int, int]:
    """risk_scorer.py as it was before task 015 (frozen copy, the regression oracle)."""
    scores: list[tuple[int, int]] = []
    if (session.clicks_60_seconds or 0) >= 8:
        scores.append((25, 70))
    if (session.clicks_30_seconds or 0) >= 4 and (session.session_duration_seconds or 0) < 10:
        scores.append((15, 65))
    if reputation is not None and reputation.has_enough_history and reputation.score >= 60:
        contribution = round(30 * (reputation.score / 100) * (reputation.confidence / 100))
        if contribution > 0:
            scores.append((contribution, min(90, 50 + reputation.confidence // 2)))
    if session.is_vpn or session.is_proxy or session.is_tor:
        scores.append((10, 55))
    if session.is_datacenter:
        scores.append((12, 60))
    if (session.session_duration_seconds or 0) < 2 and (session.page_count or 0) <= 1:
        scores.append((18, 60))
    if (session.page_count or 0) <= 1 and (session.click_count or 0) >= 3 and (session.scroll_depth or 0) < 20:
        scores.append((14, 58))
    ua = (session.user_agent or "").lower()
    if ua and ("bot" in ua or "crawler" in ua or "spider" in ua):
        scores.append((18, 65))
    if not scores:
        return 0, 0
    risk = min(100, sum(score for score, _ in scores))
    confidence = min(100, int(sum(c for _, c in scores) / len(scores) + min(len(scores) * 8, 22)))
    return risk, confidence


def session(**overrides) -> Session:
    fields = dict(
        id=uuid.uuid4(), organization_id=uuid.uuid4(), website_id=uuid.uuid4(), session_token="s_test_0001",
        ip_address="203.0.113.9", page_count=3, click_count=2, interaction_count=4, scroll_depth=60.0,
        session_duration_seconds=90.0, clicks_10_seconds=1, clicks_30_seconds=1, clicks_60_seconds=1,
        clicks_5_minutes=1, clicks_1_hour=1, clicks_24_hours=1, is_vpn=False, is_proxy=False, is_tor=False,
        is_datacenter=False, verdict=Verdict.SAFE, system_verdict=Verdict.SAFE,
    )
    fields.update(overrides)
    return Session(**fields)


def reputation(score: int, confidence: int):
    return SimpleNamespace(has_enough_history=True, score=score, confidence=confidence, all_sessions=10,
                           sessions=0, labelled_weight=0.0, fraud_ratio=0.0)


FIXTURES = [
    ("normal human", session(), None),
    ("bounce", session(session_duration_seconds=1.0, page_count=1), None),
    ("click burst", session(clicks_30_seconds=9, clicks_60_seconds=9, session_duration_seconds=0.5, page_count=1), None),
    ("vpn human", session(is_vpn=True), None),
    ("proxy bounce", session(is_proxy=True, session_duration_seconds=0.3, page_count=1), None),
    ("tor", session(is_tor=True), None),
    ("datacenter bot", session(is_datacenter=True, user_agent="python-requests crawler/1.0", page_count=1,
                               click_count=4, scroll_depth=0.0, session_duration_seconds=1.0), None),
    ("bot ua", session(user_agent="Mozilla/5.0 (compatible; Googlebot/2.1)"), None),
    ("known bad ip", session(session_duration_seconds=1.5, page_count=1), reputation(100, 100)),
    ("weak reputation", session(), reputation(70, 40)),
]


@pytest.mark.parametrize(("name", "fixture", "rep"), FIXTURES, ids=[f[0] for f in FIXTURES])
def test_seeded_rules_reproduce_the_old_scorer(name, fixture, rep):
    rules = [rule for rule in catalog_configs() if rule.code in LEGACY_CODES]
    results = evaluate(FeatureContext(session=fixture, reputation=rep), rules)
    assert aggregate_legacy(results) == legacy_score(fixture, rep)


def test_vpn_proxy_and_tor_are_separate_rules_now():
    # The one intended difference: the old combined rule counted once when several flags were set.
    results = evaluate(FeatureContext(session=session(is_vpn=True, is_proxy=True)), catalog_configs())
    assert {"VPN_DETECTED", "PROXY_DETECTED"} <= {r.code for r in results}
    assert all(r.category == "NETWORK" for r in results if r.code.endswith("_DETECTED") and r.code != "BOT_USER_AGENT_DETECTED")


def test_every_catalog_rule_has_an_evaluator_and_valid_params():
    assert {rule.code for rule in CATALOG} == set(EVALUATORS)
    for rule in CATALOG:
        assert validate_params(rule.code, rule.params) == validate_params(rule.code, dict(rule.params))


def test_evaluation_code_has_no_numeric_literals_for_thresholds_or_weights():
    import ast
    import inspect

    from app.services.rules import evaluators

    tree = ast.parse(inspect.getsource(evaluators))
    allowed = {0, 1, 0.0, 1.0, 2, 100}   # bounds / unit conversions, not tuning values
    offenders, checked = [], 0
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and any(
            isinstance(base, ast.Name) and base.id in {"Evaluator", "_FlagRule"} for base in node.bases
        ):
            for method in (n for n in node.body if isinstance(n, ast.FunctionDef) and n.name == "evaluate"):
                checked += 1
                for const in ast.walk(method):
                    if isinstance(const, ast.Constant) and isinstance(const.value, (int, float)) \
                            and not isinstance(const.value, bool) and const.value not in allowed:
                        offenders.append((node.name, const.value))
    assert checked >= 15 and offenders == []


@pytest.mark.parametrize(
    ("code", "params"),
    [("ABNORMAL_CLICK_VELOCITY", {"clicks_60_seconds_gte": 0, "clicks_5_minutes_gte": None}),
     ("ABNORMAL_CLICK_VELOCITY", {"clicks_60_seconds_gte": 8}),
     ("BOT_USER_AGENT_DETECTED", {"patterns": []}),
     ("GEO_ANOMALY", {"interest_factor": 2, "region_factor": 0.4}),
     ("VPN_DETECTED", {"anything": 1})],
)
def test_invalid_params_are_rejected(code, params):
    with pytest.raises(ValueError):
        validate_params(code, params)


def _velocity() -> RuleConfig:
    return next(rule for rule in catalog_configs() if rule.code == "ABNORMAL_CLICK_VELOCITY")


def test_override_merges_over_global_values():
    override = RuleOverride(rule_code="ABNORMAL_CLICK_VELOCITY", weight=40, params={"clicks_60_seconds_gte": 5}, version=3)
    effective = apply_override(_velocity(), override)
    assert effective.weight == 40 and effective.enabled is True
    assert effective.params == {"clicks_60_seconds_gte": 5, "clicks_5_minutes_gte": None}
    assert effective.override_version == 3
    assert apply_override(_velocity(), None) == _velocity()


def test_invalid_stored_override_params_are_ignored():
    override = RuleOverride(rule_code="ABNORMAL_CLICK_VELOCITY", params={"clicks_60_seconds_gte": -1}, version=1)
    assert apply_override(_velocity(), override).params == _velocity().params


def test_disabled_or_zero_weight_rules_never_fire():
    bot = session(user_agent="ClickBot/1.0")
    rules = catalog_configs()
    assert "BOT_USER_AGENT_DETECTED" in {r.code for r in evaluate(FeatureContext(session=bot), rules)}
    disabled = [replace(r, enabled=False) if r.code == "BOT_USER_AGENT_DETECTED" else r for r in rules]
    assert "BOT_USER_AGENT_DETECTED" not in {r.code for r in evaluate(FeatureContext(session=bot), disabled)}


def test_results_carry_category_version_and_configuration():
    rules = [replace(r, version=4) for r in catalog_configs()]
    [hit] = [r for r in evaluate(FeatureContext(session=session(is_datacenter=True)), rules)
             if r.code == "DATACENTER_DETECTED"]
    assert hit.category == "NETWORK" and hit.version == 4
    assert hit.config["weight"] == 12 and hit.config["version"] == 4

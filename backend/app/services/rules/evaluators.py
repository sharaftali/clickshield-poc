"""
Rule evaluators (spec §21–22, task 015). The logic of each rule lives here; every
number it uses comes from its configuration (`RuleConfig.params`, `weight`,
`confidence`), loaded from the `rules` table and organization overrides.

An evaluator returns a `Hit` with a strength in 0..1; the rule's contribution is
`round(weight × strength)`. Evaluators are pure: everything they need is in the
`FeatureContext` built by app/services/features.py.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, ClassVar, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.services.geo import GeoTarget, match_campaign_geo, timezone_countries
from app.services.rules.catalog import Category

if TYPE_CHECKING:
    from app.models import Session
    from app.services.ip_reputation import ReputationEvidence

logger = logging.getLogger(__name__)


# ---- inputs / outputs -------------------------------------------------------

@dataclass
class FeatureContext:
    """Everything the rules may look at for one session (spec §81 "Feature Engine")."""
    session: Session
    reputation: ReputationEvidence | None = None
    identical_sessions: int = 0
    geo_targets: list[GeoTarget] = field(default_factory=list)
    geo_target_type: str | None = None
    traffic_anomaly_level: str | None = None   # MEDIUM / HIGH anomaly active on the campaign

    def signal(self, name: str) -> dict[str, Any]:
        """A feature block stored in session.extra_signals (repeat_visitor, ad_click_intervals, …)."""
        value = (self.session.extra_signals or {}).get(name)
        return value if isinstance(value, dict) else {}


@dataclass(frozen=True)
class RuleConfig:
    """Effective configuration of one rule for one organization."""
    code: str
    name: str
    description: str
    category: Category
    enabled: bool
    weight: int
    confidence: int
    params: dict[str, Any]
    version: int = 1
    override_version: int | None = None

    def snapshot(self) -> dict[str, Any]:
        return {
            "weight": self.weight, "confidence": self.confidence, "params": self.params,
            "version": self.version, "override_version": self.override_version,
        }


@dataclass(frozen=True)
class Hit:
    strength: float = 1.0
    description: str | None = None
    confidence: int | None = None   # data-dependent confidence, capped by the configured one


@dataclass(frozen=True)
class RuleResult:
    code: str
    name: str
    category: str
    score: int
    confidence: int
    description: str
    version: int
    config: dict[str, Any]


class Params(BaseModel):
    """Base for per-rule parameter schemas: every key required, nothing unknown."""
    model_config = ConfigDict(extra="forbid")


class Evaluator:
    code: ClassVar[str]
    Params: ClassVar[type[Params]] = Params

    def evaluate(self, ctx: FeatureContext, params: Any) -> Hit | None:  # pragma: no cover - interface
        raise NotImplementedError


EVALUATORS: dict[str, Evaluator] = {}


def register(cls: type[Evaluator]) -> type[Evaluator]:
    EVALUATORS[cls.code] = cls()
    return cls


def validate_params(code: str, params: dict[str, Any]) -> dict[str, Any]:
    """Validated, normalized params for a rule. Raises ValueError (unknown rule / bad params)."""
    evaluator = EVALUATORS.get(code)
    if evaluator is None:
        raise ValueError(f"Unknown rule {code!r}")
    try:
        return evaluator.Params.model_validate(params).model_dump()
    except ValidationError as exc:
        raise ValueError(f"Invalid parameters for {code}: {exc.errors(include_url=False)}") from exc


def evaluate(ctx: FeatureContext, rules: list[RuleConfig]) -> list[RuleResult]:
    results: list[RuleResult] = []
    for rule in rules:
        evaluator = EVALUATORS.get(rule.code)
        if evaluator is None or not rule.enabled or rule.weight <= 0:
            continue
        try:
            params = evaluator.Params.model_validate(rule.params)
        except ValidationError:
            logger.error("Rule %s has invalid parameters %s; skipped", rule.code, rule.params)
            continue
        hit = evaluator.evaluate(ctx, params)
        if hit is None:
            continue
        score = round(rule.weight * max(0.0, min(1.0, hit.strength)))
        if score <= 0:
            continue
        results.append(
            RuleResult(
                code=rule.code,
                name=rule.name,
                category=str(rule.category),
                score=score,
                confidence=rule.confidence if hit.confidence is None else min(rule.confidence, hit.confidence),
                description=hit.description or rule.description,
                version=rule.version,
                config=rule.snapshot(),
            )
        )
    return results


def _f(value: Any) -> float:
    return float(value or 0)


# ---- VELOCITY ---------------------------------------------------------------

@register
class AbnormalClickVelocity(Evaluator):
    code = "ABNORMAL_CLICK_VELOCITY"

    class Params(Params):
        clicks_60_seconds_gte: int = Field(ge=1)
        clicks_5_minutes_gte: int | None = Field(ge=1)

    def evaluate(self, ctx, p):
        s = ctx.session
        if int(s.clicks_60_seconds or 0) >= p.clicks_60_seconds_gte:
            return Hit(description=f"{s.clicks_60_seconds} ad clicks from the same IP or visitor within 60 seconds.")
        if p.clicks_5_minutes_gte is not None and int(s.clicks_5_minutes or 0) >= p.clicks_5_minutes_gte:
            return Hit(description=f"{s.clicks_5_minutes} ad clicks from the same IP or visitor within 5 minutes.")
        return None


@register
class BurstClickPattern(Evaluator):
    code = "BURST_CLICK_PATTERN"

    class Params(Params):
        clicks_30_seconds_gte: int = Field(ge=1)
        max_session_seconds: float = Field(ge=0)

    def evaluate(self, ctx, p):
        s = ctx.session
        if int(s.clicks_30_seconds or 0) >= p.clicks_30_seconds_gte and _f(s.session_duration_seconds) < p.max_session_seconds:
            return Hit()
        return None


@register
class RepeatedVisitor(Evaluator):
    """Spec §17. Counts come from features.repeat_counts (stored at landing time)."""
    code = "REPEATED_VISITOR"

    class Params(Params):
        visitor_campaign_short_gte: int = Field(ge=1)
        visitor_campaign_long_gte: int = Field(ge=1)
        ip_campaign_short_gte: int = Field(ge=1)
        ip_campaign_long_gte: int = Field(ge=1)
        ip_landing_short_gte: int = Field(ge=1)
        ip_landing_long_gte: int = Field(ge=1)
        device_campaign_gte: int = Field(ge=1)
        device_min_distinct_ips: int = Field(ge=1)
        device_burst_factor: float = Field(ge=1)
        shared_ip_factor: float = Field(ge=0, le=1)
        base_strength: float = Field(gt=0, le=1)

    def evaluate(self, ctx, p):
        counts = ctx.signal("repeat_visitor")
        if not counts:
            return None
        ip_factor = p.shared_ip_factor if counts.get("ip_shared") else 1.0
        candidates: list[tuple[float, float, str]] = []  # (ratio, factor, label)

        def add(count: int, threshold: int, factor: float, label: str) -> None:
            if count >= threshold:
                candidates.append((count / threshold, factor, f"{count} {label}"))

        for window in ("short", "long"):
            hours = counts.get("windows_hours", {}).get(window, "?")
            add(int(counts.get("visitor_campaign", {}).get(window, 0)),
                getattr(p, f"visitor_campaign_{window}_gte"), 1.0, f"ad clicks by this visitor on the campaign in {hours}h")
            add(int(counts.get("ip_campaign", {}).get(window, 0)),
                getattr(p, f"ip_campaign_{window}_gte"), ip_factor, f"ad clicks from this IP on the campaign in {hours}h")
            add(int(counts.get("ip_landing", {}).get(window, 0)),
                getattr(p, f"ip_landing_{window}_gte"), ip_factor, f"ad clicks from this IP to this landing page in {hours}h")
        # Coarse device keys collide (a popular phone in one timezone): only a burst well above
        # the profile's usual volume on this campaign is the rotating-proxy pattern.
        device_count = int(counts.get("device_campaign", 0))
        usual = float(counts.get("device_campaign_usual", 0.0))
        if (
            int(counts.get("device_distinct_ips", 0)) >= p.device_min_distinct_ips
            and device_count >= p.device_burst_factor * (usual + 1)
        ):
            add(device_count, p.device_campaign_gte, 1.0,
                f"ad clicks from one device profile across {counts.get('device_distinct_ips')} IPs "
                f"in {counts.get('device_window_minutes', '?')} minutes")
        if not candidates:
            return None

        def strength(ratio: float, factor: float) -> float:
            # base_strength at the threshold, approaching 1 as the count grows (diminishing).
            return factor * (1 - (1 - p.base_strength) / ratio)

        ratio, factor, label = max(candidates, key=lambda c: strength(c[0], c[1]))
        shared = " (shared IP: many different visitors, weight reduced)" if factor < 1.0 else ""
        return Hit(strength=strength(ratio, factor), description=f"Repeated paid clicks: {label}{shared}.")


# ---- REPUTATION -------------------------------------------------------------

@register
class KnownHighRiskIp(Evaluator):
    code = "KNOWN_HIGH_RISK_IP"

    class Params(Params):
        min_score: int = Field(ge=0, le=100)
        confidence_floor: int = Field(ge=0, le=100)

    def evaluate(self, ctx, p):
        rep = ctx.reputation
        if rep is None or not rep.has_enough_history or rep.score < p.min_score:
            return None
        return Hit(
            strength=(rep.score / 100) * (rep.confidence / 100),
            confidence=p.confidence_floor + rep.confidence // 2,
            description=(
                f"Earlier sessions from this IP averaged risk {rep.score} "
                f"({rep.all_sessions} sessions, decayed)."
            ),
        )


@register
class HighFraudHistory(Evaluator):
    code = "HIGH_FRAUD_HISTORY"

    class Params(Params):
        min_sessions: int = Field(ge=1)
        min_ratio: float = Field(gt=0, le=1)
        full_weight: float = Field(gt=0)

    def evaluate(self, ctx, p):
        rep = ctx.reputation
        if rep is None or rep.sessions < p.min_sessions or rep.labelled_weight <= 0:
            return None
        ratio = rep.fraud_ratio
        if ratio < p.min_ratio:
            return None
        sample = min(1.0, rep.labelled_weight / p.full_weight)
        return Hit(
            strength=ratio * sample,
            description=(
                f"{round(ratio * 100)}% of this IP's {rep.sessions} labelled past sessions were fraud "
                "(decayed; client feedback included)."
            ),
        )


# ---- NETWORK ----------------------------------------------------------------

class _FlagRule(Evaluator):
    attribute: ClassVar[str]

    def evaluate(self, ctx, p):
        return Hit() if getattr(ctx.session, self.attribute, False) else None


@register
class VpnDetected(_FlagRule):
    code = "VPN_DETECTED"
    attribute = "is_vpn"


@register
class ProxyDetected(_FlagRule):
    code = "PROXY_DETECTED"
    attribute = "is_proxy"


@register
class TorDetected(_FlagRule):
    code = "TOR_DETECTED"
    attribute = "is_tor"


@register
class DatacenterDetected(_FlagRule):
    code = "DATACENTER_DETECTED"
    attribute = "is_datacenter"


# ---- BEHAVIOR ---------------------------------------------------------------

@register
class UnusualSession(Evaluator):
    code = "UNUSUAL_SESSION"

    class Params(Params):
        max_duration_seconds: float = Field(ge=0)
        max_pages: int = Field(ge=0)

    def evaluate(self, ctx, p):
        s = ctx.session
        if _f(s.session_duration_seconds) < p.max_duration_seconds and int(s.page_count or 0) <= p.max_pages:
            return Hit()
        return None


@register
class LowEngagementWithHighClicks(Evaluator):
    code = "LOW_ENGAGEMENT_WITH_HIGH_CLICKS"

    class Params(Params):
        max_pages: int = Field(ge=0)
        min_clicks: int = Field(ge=1)
        max_scroll_depth: float = Field(ge=0, le=100)

    def evaluate(self, ctx, p):
        s = ctx.session
        if (
            int(s.page_count or 0) <= p.max_pages
            and int(s.click_count or 0) >= p.min_clicks
            and _f(s.scroll_depth) < p.max_scroll_depth
        ):
            return Hit()
        return None


# ---- AUTOMATION -------------------------------------------------------------

@register
class BotUserAgent(Evaluator):
    code = "BOT_USER_AGENT_DETECTED"

    class Params(Params):
        patterns: list[str] = Field(min_length=1)

    def evaluate(self, ctx, p):
        user_agent = (ctx.session.user_agent or "").casefold()
        if user_agent and any(pattern.casefold() in user_agent for pattern in p.patterns if pattern):
            return Hit()
        return None


@register
class RepeatedIdenticalSessions(Evaluator):
    """Spec §20. ctx.identical_sessions is counted by features.count_identical_sessions
    with this rule's window / tolerance params."""
    code = "REPEATED_IDENTICAL_SESSIONS"

    class Params(Params):
        min_matches: int = Field(ge=1)
        window_minutes: int = Field(ge=1)
        duration_tolerance_seconds: float = Field(ge=0)
        min_duration_seconds: float = Field(ge=0)

    def evaluate(self, ctx, p):
        if ctx.identical_sessions >= p.min_matches:
            return Hit(description=(
                f"{ctx.identical_sessions} other sessions from this IP and device in the last "
                f"{p.window_minutes} minutes behaved identically."
            ))
        return None


@register
class SubSecondClickInterval(Evaluator):
    """Spec §31 "click interval 0.2–1 s". Same evidence family as velocity / burst."""
    code = "SUB_SECOND_CLICK_INTERVAL"

    class Params(Params):
        min_landings: int = Field(ge=2)
        min_interval_seconds: float = Field(ge=0)

    def evaluate(self, ctx, p):
        s = ctx.session
        landings = int(ctx.signal("ad_click_intervals").get("landings", 0))
        if landings < p.min_landings or s.ad_click_interval_min_s is None:
            return None
        if s.ad_click_interval_min_s < p.min_interval_seconds:
            return Hit(description=f"{landings} ad clicks, some only {s.ad_click_interval_min_s:.2f}s apart.")
        return None


@register
class AbnormalClickTiming(Evaluator):
    """Machine-regular ad clicks (spec §16 "unnatural repetition"): catches slow, steady
    bots under the velocity thresholds. Sub-second bursts are SUB_SECOND_CLICK_INTERVAL."""
    code = "ABNORMAL_CLICK_TIMING"

    class Params(Params):
        min_landings: int = Field(ge=2)
        max_cv: float = Field(ge=0)
        min_mean_interval_seconds: float = Field(ge=0)

    def evaluate(self, ctx, p):
        s = ctx.session
        landings = int(ctx.signal("ad_click_intervals").get("landings", 0))
        if landings < p.min_landings or s.ad_click_interval_cv is None or s.ad_click_interval_avg_s is None:
            return None
        if s.ad_click_interval_avg_s >= p.min_mean_interval_seconds and s.ad_click_interval_cv < p.max_cv:
            return Hit(description=(
                f"{landings} ad clicks at machine-regular intervals "
                f"(every {s.ad_click_interval_avg_s:.1f}s, variation {s.ad_click_interval_cv:.2f})."
            ))
        return None


@register
class ImpossibleInteractionTiming(Evaluator):
    code = "IMPOSSIBLE_INTERACTION_TIMING"

    class Params(Params):
        min_events: int = Field(ge=2)
        min_interval_ms: float = Field(ge=0)
        max_cv: float = Field(ge=0)

    def evaluate(self, ctx, p):
        s = ctx.session
        events = int(ctx.signal("event_intervals").get("events", 0))
        if events < p.min_events or s.event_interval_cv is None:
            return None
        if s.event_interval_min_ms is not None and s.event_interval_min_ms < p.min_interval_ms:
            return Hit(description=f"{events} on-page actions, some only {s.event_interval_min_ms:.0f} ms apart.")
        if s.event_interval_cv < p.max_cv:
            return Hit(description=f"{events} on-page actions at machine-regular intervals (variation {s.event_interval_cv:.2f}).")
        return None


# ---- GEO --------------------------------------------------------------------

@register
class GeoAnomaly(Evaluator):
    code = "GEO_ANOMALY"

    class Params(Params):
        interest_factor: float = Field(ge=0, le=1)
        region_factor: float = Field(ge=0, le=1)

    def evaluate(self, ctx, p):
        s = ctx.session
        match = match_campaign_geo(ctx.geo_targets, country=s.country, region=s.region, city=s.city)
        if match is None:
            return None
        strength = p.region_factor if match.kind == "outside_regions" else 1.0
        # PRESENCE_OR_INTEREST (Google's default) also shows ads to people *interested in*
        # the location, so a mismatch is expected more often.
        interest = (ctx.geo_target_type or "").upper() == "PRESENCE_OR_INTEREST" and match.kind != "excluded_location"
        if interest:
            strength *= p.interest_factor
        note = " (campaign also targets people interested in the area)" if interest else ""
        return Hit(strength=strength, description=f"Geo mismatch: {match.detail}{note}.")


@register
class GeoTimezoneMismatch(Evaluator):
    code = "GEO_TIMEZONE_MISMATCH"

    def evaluate(self, ctx, p):
        s = ctx.session
        countries = timezone_countries(s.timezone)
        if not s.country or not countries or s.country.upper() in countries:
            return None
        return Hit(description=f"Browser timezone {s.timezone} is not used in the IP's country ({s.country}).")


# ---- ANOMALY ----------------------------------------------------------------

LEVEL_ORDER = {"MEDIUM": 1, "HIGH": 2}


@register
class TrafficAnomalyRule(Evaluator):
    code = "TRAFFIC_ANOMALY"

    class Params(Params):
        min_level: Literal["MEDIUM", "HIGH"]

    def evaluate(self, ctx, p):
        level = ctx.traffic_anomaly_level
        if level and LEVEL_ORDER.get(level, 0) >= LEVEL_ORDER[p.min_level]:
            return Hit(description=f"The click arrived during a {level} traffic anomaly on this campaign.")
        return None

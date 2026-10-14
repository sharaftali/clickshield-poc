"""
Decision policy (spec §24, §26, §28, §53–54; tasks 016, 017).

Verdicts map to the spec's decision words (§26):
    SAFE    = ALLOW    (no action)
    MONITOR = MONITOR  (keep watching)
    FLAG    = FLAG     (needs human review; never excluded automatically)
    FRAUD   = BLOCK    (eligible for automatic exclusion)

Each organization's protection mode resolves to a `ProtectionPolicy`. The risk
bands (LOW / MODERATE / HIGH / VERY HIGH) are global and describe the score; the
policy decides what a score means for that organization.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any

from app.core.config import settings
from app.models import Organization, ProtectionMode, Verdict

POLICY_FIELDS = ("flag_risk", "fraud_risk", "fraud_confidence", "min_diversity", "auto_exclude")


class RiskBand(StrEnum):
    LOW = "LOW"              # 0–29
    MODERATE = "MODERATE"    # 30–59
    HIGH = "HIGH"            # 60–79
    VERY_HIGH = "VERY_HIGH"  # 80–100


def risk_band(risk: int) -> RiskBand:
    if risk >= settings.RISK_BAND_VERY_HIGH:
        return RiskBand.VERY_HIGH
    if risk >= settings.RISK_BAND_HIGH:
        return RiskBand.HIGH
    if risk >= settings.RISK_BAND_MODERATE:
        return RiskBand.MODERATE
    return RiskBand.LOW


@dataclass(frozen=True)
class ProtectionPolicy:
    mode: ProtectionMode
    flag_risk: int          # FLAG (review) from this risk, with high confidence
    fraud_risk: int         # FRAUD from this risk …
    fraud_confidence: int   # … with this confidence …
    min_diversity: int      # … and this many independent signal categories
    auto_exclude: bool      # FRAUD creates Google Ads exclusions

    def as_dict(self) -> dict[str, Any]:
        return {**asdict(self), "mode": self.mode.value}


def mode_defaults(mode: ProtectionMode) -> dict[str, Any]:
    policies = settings.PROTECTION_MODE_POLICIES
    return dict(policies.get(mode.value) or policies[ProtectionMode.BALANCED.value])


def validate_custom_settings(values: dict[str, Any]) -> dict[str, Any]:
    """Complete and check Custom thresholds (missing keys = Balanced). Raises ValueError."""
    merged = {**mode_defaults(ProtectionMode.BALANCED), **{k: v for k, v in values.items() if v is not None}}
    unknown = set(merged) - set(POLICY_FIELDS)
    if unknown:
        raise ValueError(f"Unknown protection settings: {', '.join(sorted(unknown))}")
    for key in ("flag_risk", "fraud_risk", "fraud_confidence", "min_diversity"):
        if isinstance(merged[key], bool) or not isinstance(merged[key], int):
            raise ValueError(f"{key} must be an integer")
    if not isinstance(merged["auto_exclude"], bool):
        raise ValueError("auto_exclude must be true or false")
    if merged["min_diversity"] < settings.CUSTOM_MIN_DIVERSITY_FLOOR:
        raise ValueError(
            f"min_diversity must be at least {settings.CUSTOM_MIN_DIVERSITY_FLOOR}: "
            "one kind of suspicious signal must never block on its own (spec §73)."
        )
    if merged["min_diversity"] > 7:
        raise ValueError("min_diversity cannot exceed the 7 signal categories")
    if not settings.CUSTOM_MIN_FRAUD_RISK <= merged["fraud_risk"] <= 100:
        raise ValueError(f"fraud_risk must be between {settings.CUSTOM_MIN_FRAUD_RISK} and 100")
    if not settings.CUSTOM_MIN_FRAUD_CONFIDENCE <= merged["fraud_confidence"] <= 100:
        raise ValueError(f"fraud_confidence must be between {settings.CUSTOM_MIN_FRAUD_CONFIDENCE} and 100")
    if not settings.RISK_BAND_MODERATE <= merged["flag_risk"] <= merged["fraud_risk"]:
        raise ValueError(f"flag_risk must be between {settings.RISK_BAND_MODERATE} and fraud_risk")
    return merged


def get_policy(organization: Organization | None) -> ProtectionPolicy:
    mode = organization.protection_mode if organization is not None else ProtectionMode.BALANCED
    values = mode_defaults(mode)
    if mode == ProtectionMode.CUSTOM:
        try:
            values = validate_custom_settings(organization.protection_settings or {})
        except ValueError:
            values = mode_defaults(ProtectionMode.BALANCED)  # stored values became invalid: stay safe
    return ProtectionPolicy(mode=mode, **{key: values[key] for key in POLICY_FIELDS})


def decide(risk: int, confidence: int, diversity: int, policy: ProtectionPolicy) -> Verdict:
    """The verdict matrix (task 017), with thresholds from the organization's policy.

    | risk                          | confidence & diversity                       | verdict |
    |-------------------------------|----------------------------------------------|---------|
    | < RISK_BAND_MODERATE (30)     | —                                            | SAFE    |
    | ≥ fraud_risk                  | ≥ fraud_confidence and ≥ min_diversity       | FRAUD   |
    | ≥ fraud_risk                  | ≥ CONFIDENCE_MEDIUM and ≥ FLAG_MIN_DIVERSITY | FLAG    |
    | ≥ flag_risk                   | ≥ CONFIDENCE_HIGH and ≥ FLAG_MIN_DIVERSITY   | FLAG    |
    | otherwise                     |                                              | MONITOR |
    """
    if risk < settings.RISK_BAND_MODERATE:
        return Verdict.SAFE
    flag_diversity = diversity >= settings.FLAG_MIN_DIVERSITY
    if risk >= policy.fraud_risk:
        if confidence >= policy.fraud_confidence and diversity >= policy.min_diversity:
            return Verdict.FRAUD
        if confidence >= settings.CONFIDENCE_MEDIUM and flag_diversity:
            return Verdict.FLAG
        return Verdict.MONITOR
    if risk >= policy.flag_risk and confidence >= settings.CONFIDENCE_HIGH and flag_diversity:
        return Verdict.FLAG
    return Verdict.MONITOR


# SCORING_VERSION=1 rollback: the decision used before tasks 014/016/017.
LEGACY_FRAUD_RISK = 80
LEGACY_FRAUD_CONFIDENCE = 80
LEGACY_MONITOR_RISK = 50


def decide_legacy(risk: int, confidence: int) -> Verdict:
    if risk >= LEGACY_FRAUD_RISK and confidence >= LEGACY_FRAUD_CONFIDENCE:
        return Verdict.FRAUD
    if risk >= LEGACY_MONITOR_RISK:
        return Verdict.MONITOR
    return Verdict.SAFE

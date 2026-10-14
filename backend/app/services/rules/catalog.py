"""
The rule catalog (spec §21–22, task 015): every rule's code, category and
default numbers. It seeds the `rules` table (migration 015 + later P2 migrations
insert exactly these values) and is the configuration used when
RULES_SOURCE=code. Changing a value here does not change a running system —
change the database row (or an organization override) instead.

Spec §24: all values are "initial engineering defaults only", to be tuned with real data.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Category(StrEnum):
    """Independent kinds of evidence (task 014). Rules in one category measure the
    same thing, so they share diminishing returns; diversity counts categories."""
    NETWORK = "NETWORK"          # VPN, proxy, Tor, datacenter
    REPUTATION = "REPUTATION"    # this IP's history
    VELOCITY = "VELOCITY"        # how often the same source clicks the ad
    BEHAVIOR = "BEHAVIOR"        # what the visitor does on the site
    AUTOMATION = "AUTOMATION"    # bot user agents, machine timing, cloned sessions
    GEO = "GEO"                  # location vs. targeting / timezone
    ANOMALY = "ANOMALY"          # campaign-level traffic anomaly


@dataclass(frozen=True)
class RuleDefinition:
    code: str
    name: str
    category: Category
    weight: int        # contribution (risk points) at full strength
    confidence: int    # how reliable the rule is when it fires (0–100)
    description: str
    params: dict[str, Any] = field(default_factory=dict)
    enabled: bool = True


CATALOG: tuple[RuleDefinition, ...] = (
    # ---- VELOCITY ----
    RuleDefinition(
        "ABNORMAL_CLICK_VELOCITY", "Abnormal click velocity", Category.VELOCITY, 25, 70,
        "The same IP or visitor clicked the ad unusually often in a short window.",
        {"clicks_60_seconds_gte": 8, "clicks_5_minutes_gte": None},
    ),
    RuleDefinition(
        "BURST_CLICK_PATTERN", "Burst click pattern", Category.VELOCITY, 15, 65,
        "Repeated ad clicks in a short burst with minimal browsing time.",
        {"clicks_30_seconds_gte": 4, "max_session_seconds": 10.0},
    ),
    RuleDefinition(
        "REPEATED_VISITOR", "Repeated visitor", Category.VELOCITY, 20, 65,
        "The same visitor, IP or device clicked the same campaign's ad repeatedly over hours or days.",
        {
            "visitor_campaign_short_gte": 3, "visitor_campaign_long_gte": 6,
            "ip_campaign_short_gte": 5, "ip_campaign_long_gte": 10,
            "ip_landing_short_gte": 5, "ip_landing_long_gte": 10,
            "device_campaign_gte": 5, "device_min_distinct_ips": 3, "device_burst_factor": 3.0,
            "shared_ip_factor": 0.2, "base_strength": 0.5,
        },
    ),
    RuleDefinition(
        "SUB_SECOND_CLICK_INTERVAL", "Sub-second ad clicks", Category.VELOCITY, 15, 65,
        "Ad clicks from this source came less than a second apart (spec §31).",
        {"min_landings": 4, "min_interval_seconds": 1.0},
    ),
    # ---- REPUTATION ----
    RuleDefinition(
        "KNOWN_HIGH_RISK_IP", "Known high-risk IP", Category.REPUTATION, 30, 90,
        "Earlier sessions from this IP scored high risk (decayed average risk of this "
        "organization's past sessions on the IP).",
        {"min_score": 60, "confidence_floor": 50},
    ),
    RuleDefinition(
        "HIGH_FRAUD_HISTORY", "High fraud history", Category.REPUTATION, 35, 85,
        "Most of this IP's labelled past sessions were fraud (decayed fraud ratio; client "
        "feedback overrides the system verdict).",
        {"min_sessions": 5, "min_ratio": 0.6, "full_weight": 10.0},
    ),
    # ---- NETWORK ----
    RuleDefinition(
        "VPN_DETECTED", "VPN detected", Category.NETWORK, 10, 55,
        "The session comes from a VPN exit node.",
    ),
    RuleDefinition(
        "PROXY_DETECTED", "Proxy detected", Category.NETWORK, 10, 55,
        "The session comes through an open or anonymous proxy.",
    ),
    RuleDefinition(
        "TOR_DETECTED", "Tor detected", Category.NETWORK, 10, 55,
        "The session comes from a Tor exit node.",
    ),
    RuleDefinition(
        "DATACENTER_DETECTED", "Datacenter traffic", Category.NETWORK, 12, 60,
        "The traffic comes from a datacenter or hosting network.",
    ),
    # ---- BEHAVIOR ----
    RuleDefinition(
        "UNUSUAL_SESSION", "Unusual session", Category.BEHAVIOR, 18, 60,
        "The session had a very short lifetime and almost no browsing depth.",
        {"max_duration_seconds": 2.0, "max_pages": 1},
    ),
    RuleDefinition(
        "LOW_ENGAGEMENT_WITH_HIGH_CLICKS", "Low engagement with high clicks", Category.BEHAVIOR, 14, 58,
        "Many clicks without matching page engagement.",
        {"max_pages": 1, "min_clicks": 3, "max_scroll_depth": 20.0},
    ),
    # ---- AUTOMATION ----
    RuleDefinition(
        "BOT_USER_AGENT_DETECTED", "Bot user agent", Category.AUTOMATION, 18, 65,
        "The user agent matches a known bot, crawler or automated client.",
        {"patterns": ["bot", "crawler", "spider"]},
    ),
    RuleDefinition(
        "AUTOMATION_SIGNAL", "Automation signal", Category.AUTOMATION, 25, 75,
        "The browser reported automation indicators (webdriver, headless, no languages, tiny viewport), "
        "or the client sent no Origin / was rate-limited.",
        {"min_indicators": 1},
    ),
    RuleDefinition(
        "REPEATED_IDENTICAL_SESSIONS", "Repeated identical sessions", Category.AUTOMATION, 20, 65,
        "Several recent sessions from the same IP and device behaved identically (same landing "
        "page, pages and duration). Bounces are left to UNUSUAL_SESSION.",
        {"min_matches": 3, "window_minutes": 60, "duration_tolerance_seconds": 1.0, "min_duration_seconds": 3.0},
    ),
    RuleDefinition(
        "ABNORMAL_CLICK_TIMING", "Abnormal click timing", Category.AUTOMATION, 20, 65,
        "Ad clicks from this source arrive at machine-regular intervals (a slow, steady bot "
        "below the velocity thresholds).",
        {"min_landings": 4, "max_cv": 0.15, "min_mean_interval_seconds": 2.0},
    ),
    RuleDefinition(
        "IMPOSSIBLE_INTERACTION_TIMING", "Impossible interaction timing", Category.AUTOMATION, 20, 70,
        "On-page actions happened faster or more regularly than a person can act.",
        {"min_events": 10, "min_interval_ms": 50.0, "max_cv": 0.1},
    ),
    # ---- GEO ----
    RuleDefinition(
        "GEO_ANOMALY", "Geo anomaly", Category.GEO, 15, 55,
        "The visitor's location is outside the campaign's location targeting.",
        {"interest_factor": 0.5, "region_factor": 0.4},
    ),
    RuleDefinition(
        "GEO_TIMEZONE_MISMATCH", "Timezone mismatch", Category.GEO, 8, 50,
        "The browser's timezone is not used in the IP's country.",
    ),
    # ---- ANOMALY ----
    RuleDefinition(
        "TRAFFIC_ANOMALY", "Campaign traffic anomaly", Category.ANOMALY, 10, 50,
        "The ad click arrived during a detected traffic spike on its campaign.",
        {"min_level": "HIGH"},
    ),
)

CATALOG_BY_CODE: dict[str, RuleDefinition] = {rule.code: rule for rule in CATALOG}

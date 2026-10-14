from __future__ import annotations

import ipaddress
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # ---- Application ----
    APP_NAME: str = "Click Shield"
    APP_VERSION: str = "0.1.0"
    ENVIRONMENT: str = Field(
        default="development",
        description="development | staging | production",
    )
    DEBUG: bool = False
    # Containers (Docker / ECS) log to stdout only; the rotating file under logs/
    # is for running directly on a developer machine.
    LOG_TO_FILE: bool = True

    # ---- Database ----
    DATABASE_URL: str = Field(
        default="postgresql+asyncpg://postgres:postgres@localhost:5432/clickshield",
        description="PostgreSQL async connection string (postgresql+asyncpg://...)",
    )
    DATABASE_URL_SYNC: str = Field(
        default="postgresql+psycopg://postgres:postgres@localhost:5432/clickshield",
        description="PostgreSQL sync connection string for Alembic (postgresql+psycopg://...)",
    )
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20
    DB_ECHO: bool = False

    # ---- Redis ----
    REDIS_URL: str = Field(
        default="redis://localhost:6379/0",
        description="Redis connection string for cache + action queue",
    )

    # ---- Security / Auth ----
    SECRET_KEY: str = Field(
        default="dev-secret-key-change-me-in-production-environment",
        min_length=32,
        description="JWT signing secret. Must be overridden in production.",
    )
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # ---- Token Encryption (spec §63) ----
    # Use a stable local dev key; override in production with a generated Fernet key.
    TOKEN_ENCRYPTION_KEY: str = Field(
        default="cAtLjrcYUAo7VMkGP1GscEXLFY-KfbIGS3fO_oYoBjg=",
        description="Fernet key used to encrypt Google OAuth refresh tokens at rest",
    )

    # ---- Google Ads API (spec §34–36) ----
    GOOGLE_CLIENT_ID: str = Field(
        default="",
        description="Google OAuth client ID",
    )
    GOOGLE_CLIENT_SECRET: str = Field(
        default="",
        description="Google OAuth client secret",
    )
    GOOGLE_OAUTH_REDIRECT_URI: str = Field(
        default="http://localhost:8000/api/v1/google/callback",
        description="OAuth callback URL, e.g. https://api.clickshield.com/api/v1/google/callback",
    )
    GOOGLE_DEVELOPER_TOKEN: str | None = Field(
        default=None,
        description="Legacy developer token. Accepted but ignored by Google Ads API.",
    )
    GOOGLE_ADS_API_VERSION: str = "v21"
    # Local development only: process actions without calling Google. Exclusions
    # are stored as SKIPPED (never ACTIVE) so the dashboard can't show fake protection.
    GOOGLE_ADS_DRY_RUN: bool = False

    # ---- IP Intelligence (spec §13) ----
    IPINFO_API_KEY: str | None = Field(
        default=None,
        description="IPinfo API key for IP intelligence lookups",
    )
    IPINFO_TIMEOUT_SECONDS: int = 3

    # ---- Tracking API (spec §8, §61) ----
    TRACKING_RATE_LIMIT_PER_MINUTE: int = 300
    TRACKING_SNIPPET_BASE_URL: str = Field(
        default="http://localhost:8000",
        description="Public base URL for the tracking script CDN",
    )
    TRACKING_CORS_ORIGINS: str = Field(
        default="*",
        description="Comma-separated origins allowed to POST to /track",
    )

    # ---- Client IP resolution (spec §13, §62) ----
    # X-Forwarded-For is only honoured when the direct peer is in one of these
    # networks. Empty = trust nobody and always use the socket peer address.
    TRUSTED_PROXY_CIDRS: str = Field(
        default="",
        description="Comma-separated CIDRs of our own proxies/load balancers, e.g. '10.0.0.0/8,172.16.0.0/12'",
    )

    # ---- Dashboard / API CORS ----
    API_CORS_ORIGINS: str = Field(
        default="http://localhost:5173",
        description="Comma-separated origins for the dashboard frontend",
    )
    FRONTEND_APP_URL: str = Field(
        default="http://localhost:5173",
        description="Public dashboard frontend URL used for OAuth return redirects",
    )

    # ---- Rules (spec §21–22, task 015) ----
    # Rule weights, confidences and thresholds live in the `rules` table (seeded with
    # app/services/rules/catalog.py) plus per-organization `rule_overrides`.
    # "code" ignores the database and uses the catalog defaults (rollback switch).
    RULES_SOURCE: Literal["db", "code"] = "db"
    RULES_CACHE_TTL_SECONDS: int = 60

    # ---- Risk aggregation (spec §24, §27, task 014) ----
    # 2 = categories with diminishing returns + signal diversity; 1 = the original
    # sum / average-confidence scoring and 80/80 decision (rollback switch).
    SCORING_VERSION: Literal[1, 2] = 2
    # Within one category the strongest rule counts fully, the next ones less.
    SCORING_DIMINISHING_FACTORS: list[float] = [1.0, 0.5, 0.25]
    SCORING_CATEGORY_CAPS: dict[str, int] = {
        "NETWORK": 25, "REPUTATION": 45, "VELOCITY": 40, "BEHAVIOR": 30,
        "AUTOMATION": 40, "GEO": 20, "ANOMALY": 15,
    }
    # A category counts towards signal diversity from this contribution up.
    SCORING_MIN_CATEGORY_CONTRIBUTION: int = 8
    # Data completeness (confidence of SAFE verdicts): observation needed for "complete".
    SCORING_FULL_OBSERVATION_SECONDS: float = 30.0
    SCORING_FULL_EVENT_COUNT: int = 5

    # ---- Risk bands and decision matrix (spec §24, §26, §28, task 017) ----
    RISK_BAND_MODERATE: int = 30
    RISK_BAND_HIGH: int = 60
    RISK_BAND_VERY_HIGH: int = 80
    CONFIDENCE_MEDIUM: int = 60   # very high risk below the FRAUD confidence: FLAG from here, else MONITOR
    CONFIDENCE_HIGH: int = 75     # high-band risk needs this confidence to be FLAGged
    FLAG_MIN_DIVERSITY: int = 2   # FLAG (human review) needs at least two independent categories

    # ---- Protection modes (spec §54, task 016) — engineering defaults, tune with real data ----
    PROTECTION_MODE_POLICIES: dict[str, dict[str, int | bool]] = {
        "conservative": {"flag_risk": 70, "fraud_risk": 90, "fraud_confidence": 90, "min_diversity": 3, "auto_exclude": True},
        "balanced": {"flag_risk": 60, "fraud_risk": 80, "fraud_confidence": 80, "min_diversity": 3, "auto_exclude": True},
        "aggressive": {"flag_risk": 50, "fraud_risk": 70, "fraud_confidence": 70, "min_diversity": 2, "auto_exclude": True},
    }
    # Safety floors for Custom mode (spec §73: one suspicious signal never blocks).
    CUSTOM_MIN_DIVERSITY_FLOOR: int = 2
    CUSTOM_MIN_FRAUD_RISK: int = 50
    CUSTOM_MIN_FRAUD_CONFIDENCE: int = 50

    # ---- Click velocity (spec §16) — paid ad landings per IP/visitor ----
    # Rule thresholds are in the rules table; these only shape the counting.
    SHARED_IP_MIN_DISTINCT_VISITORS: int = 5  # an IP with this many visitors (24h) is treated as shared

    # ---- Repeat visitors (spec §17, task 019) ----
    REPEAT_SHORT_WINDOW_HOURS: int = 24
    REPEAT_LONG_WINDOW_HOURS: int = 168
    DEVICE_KEY_WINDOW_MINUTES: int = 60       # rotating-proxy check: same device key, many IPs
    # Salt for the per-organization device key hash; empty = derived from SECRET_KEY.
    DEVICE_KEY_SALT: str = ""

    # ---- Click / interaction timing (spec §16, §20, task 021) ----
    AD_CLICK_INTERVAL_LOOKBACK_HOURS: int = 24
    INTERVAL_MIN_SAMPLES: int = 3             # fewer intervals → no statistics, rules skipped

    # ---- IP reputation (spec §14) — per organization, decayed, never self-referencing ----
    REPUTATION_WINDOW_DAYS: int = 30          # history considered
    REPUTATION_HALF_LIFE_DAYS: float = 7.0    # a session 7 days old counts half
    REPUTATION_MIN_SAMPLE: int = 3            # past sessions before the risk reputation counts
    REPUTATION_FULL_CONFIDENCE_WEIGHT: float = 10.0  # decayed sessions for 100% confidence
    # History is evidence from the past: sessions younger than this belong to the current
    # burst, which velocity / repeat rules already score (no double counting).
    REPUTATION_MIN_AGE_SECONDS: int = 3600

    # ---- Statistical anomaly detection (spec §31, §76, task 022) ----
    ANOMALY_DETECTION_ENABLED: bool = True
    ANOMALY_BASELINE_DAYS: int = 14
    ANOMALY_MIN_HISTORY_DAYS: int = 7         # less history → campaign not scored (cold start)
    ANOMALY_MIN_SAME_HOUR_SAMPLES: int = 7    # same hour-of-day baseline needs this many days
    ANOMALY_Z_MEDIUM: float = 3.0
    ANOMALY_Z_HIGH: float = 4.0
    ANOMALY_MIN_LANDINGS: int = 10            # an hour needs this many landings to be a spike
    ANOMALY_SESSION_RULE_HOURS: int = 1       # sessions this long after a HIGH spike get TRAFFIC_ANOMALY

    # ---- Google Ads Exclusion Limits (spec §39, §73: configurable, never hard-coded) ----
    GOOGLE_MAX_IP_EXCLUSIONS_PER_CAMPAIGN: int = 500
    # Slots left free for IPs the advertiser excludes by hand in Google Ads.
    GOOGLE_EXCLUSION_RESERVED_SLOTS: int = 25
    # When a campaign is full, replace the lowest-priority exclusion with a stronger candidate.
    EXCLUSION_EVICTION_ENABLED: bool = True
    # Remove exclusions with no new fraud for this many days (0 = never expire).
    EXCLUSION_EXPIRY_DAYS: int = 0
    # A FAILED / SKIPPED exclusion is not re-attempted for the same IP sooner than this (spec §38).
    EXCLUSION_RETRY_COOLDOWN_SECONDS: int = 3600

    # ---- Automatic protection (spec §42) ----
    # FRAUD verdicts create exclusions automatically. Off = detect and report only.
    AUTO_PROTECTION_ENABLED: bool = True

    # ---- Action Queue (spec §42–43) ----
    ACTION_QUEUE_MAX_ATTEMPTS: int = 5
    ACTION_QUEUE_RETRY_BACKOFF_SECONDS: int = 30        # first retry delay; doubles each attempt
    ACTION_QUEUE_RETRY_MAX_BACKOFF_SECONDS: int = 3600  # cap on a single delay
    ACTION_QUEUE_STUCK_AFTER_SECONDS: int = 600         # PROCESSING longer than this = worker died
    ACTION_QUEUE_WORKER_CONCURRENCY: int = 4            # arq max_jobs
    WORKER_SWEEP_SECONDS: int = 15     # how often the worker sweeps for due actions / retries
    WORKER_BATCH_SIZE: int = 20        # actions per sweep

    # ---- Bootstrap Admin (first-run seeding only) ----
    DEFAULT_ORGANIZATION_NAME: str = "Default Organization"
    DEFAULT_ORGANIZATION_SLUG: str = "default"
    DEFAULT_ADMIN_EMAIL: str = "admin@gmail.com"
    DEFAULT_ADMIN_PASSWORD: str = "ChangeMe@123"
    DEFAULT_ADMIN_FULL_NAME: str = "Admin"

    # ---- Data Retention (spec §79) ----
    RAW_EVENTS_RETENTION_DAYS: int = 30
    SESSIONS_RETENTION_DAYS: int = 90

    @field_validator("TRUSTED_PROXY_CIDRS")
    @classmethod
    def validate_trusted_proxy_cidrs(cls, value: str) -> str:
        # Fail at startup on a typo rather than silently trusting nothing.
        for item in value.split(","):
            item = item.strip()
            if item:
                try:
                    ipaddress.ip_network(item, strict=False)
                except ValueError as exc:
                    raise ValueError(f"Invalid CIDR in TRUSTED_PROXY_CIDRS: {item!r}") from exc
        return value


settings = Settings()

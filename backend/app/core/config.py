from __future__ import annotations

import ipaddress

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

    # ---- Fraud Engine Defaults (spec §24, §28) ----
    FRAUD_RISK_FRAUD_THRESHOLD: int = 80
    FRAUD_RISK_MONITOR_THRESHOLD: int = 50
    FRAUD_CONFIDENCE_MIN_FOR_BLOCK: int = 80

    # ---- Click velocity rules (spec §16, §22) — paid ad landings per IP/visitor ----
    VELOCITY_CLICKS_60S_THRESHOLD: int = 8
    BURST_CLICKS_30S_THRESHOLD: int = 4
    BURST_MAX_SESSION_SECONDS: float = 10.0

    # ---- IP reputation (spec §14) — per organization, decayed, never self-referencing ----
    REPUTATION_WINDOW_DAYS: int = 30          # history considered
    REPUTATION_HALF_LIFE_DAYS: float = 7.0    # a session 7 days old counts half
    REPUTATION_MIN_SAMPLE: int = 3            # labelled past sessions before reputation counts
    REPUTATION_FULL_CONFIDENCE_WEIGHT: float = 10.0  # decayed sessions for 100% confidence
    REPUTATION_RULE_MIN_SCORE: int = 60       # decayed fraud ratio (0–100) to trigger the rule
    REPUTATION_RULE_MAX_WEIGHT: int = 30      # contribution at score 100 and full confidence

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

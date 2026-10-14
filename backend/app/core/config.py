from __future__ import annotations

import hashlib
import ipaddress
import secrets
from typing import Literal

from cryptography.fernet import Fernet
from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# sha256 of values that were once committed to this repository (task 032). They are
# public forever: refused outside development, warned about inside it.
COMPROMISED_SECRET_HASHES = {
    "0f7f382b253336b5ba3350445226f4bb7389e024be0586cf991c12be099eb443",
    "368a26cbb12389874fffd0571a356ee933f399a7240b55559543919cf4946ab6",
}

DEVELOPMENT_ENVIRONMENTS = {"development", "test"}

# Warnings collected while loading settings (logging isn't configured yet); main.py logs them.
STARTUP_WARNINGS: list[str] = []


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


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

    # ---- Security / Auth (task 032: no secret has a default in code) ----
    SECRET_KEY: str = Field(
        default="",
        description="JWT signing secret, at least 32 bytes. Required outside development.",
    )
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # ---- Token Encryption (spec §63) ----
    # Fernet keys for Google refresh tokens at rest. TOKEN_ENCRYPTION_KEYS is a comma-separated
    # list for rotation: the first key encrypts, all keys decrypt (`python -m app.cli
    # reencrypt-tokens` moves every row to the first key). TOKEN_ENCRYPTION_KEY = one key.
    TOKEN_ENCRYPTION_KEY: str = Field(default="", description="Single Fernet key (no rotation)")
    TOKEN_ENCRYPTION_KEYS: str = Field(default="", description="Comma-separated Fernet keys, newest first")

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

    # ---- Development seed (task 032: ENVIRONMENT=development only) ----
    # Production creates its first owner with `python -m app.cli create-admin`.
    # Without a password a random one is generated and logged once.
    DEFAULT_ORGANIZATION_NAME: str = "Default Organization"
    DEFAULT_ORGANIZATION_SLUG: str = "default"
    DEFAULT_ADMIN_EMAIL: str = "admin@localhost.test"
    DEFAULT_ADMIN_PASSWORD: str = ""
    DEFAULT_ADMIN_FULL_NAME: str = "Admin"

    # ---- Websites (task 023) ----
    # /track only accepts events whose Origin is one of the website's domains.
    TRACKING_ENFORCE_ORIGIN: bool = True
    WEBSITE_VERIFY_TIMEOUT_SECONDS: float = 5.0
    WEBSITE_VERIFY_MAX_BYTES: int = 512_000

    # ---- Rate limiting (spec §62, task 031) — Redis fixed windows, fail open ----
    RATE_LIMIT_ENABLED: bool = True
    TRACKING_RATE_LIMIT_PER_SITE_PER_MINUTE: int = 10_000
    TRACKING_MAX_BODY_BYTES: int = 65_536
    LOGIN_RATE_LIMIT_PER_IP_PER_MINUTE: int = 10
    LOGIN_FAILURES_PER_EMAIL: int = 5
    LOGIN_FAILURE_WINDOW_SECONDS: int = 900
    REGISTER_RATE_LIMIT_PER_IP_PER_HOUR: int = 5
    API_RATE_LIMIT_PER_USER_PER_MINUTE: int = 600
    # HSTS is sent on HTTPS requests (as seen by the app, i.e. behind a TLS-terminating proxy
    # only when X-Forwarded-Proto is trusted).
    HSTS_MAX_AGE_SECONDS: int = 31_536_000

    # ---- OAuth (task 033) ----
    OAUTH_STATE_TTL_SECONDS: int = 600

    # ---- Alerts (spec §66, task 028) ----
    ALERTS_ENABLED: bool = True
    ALERT_EMAILS_ENABLED: bool = True
    ALERT_EMAIL_MIN_SEVERITY: Literal["info", "warning", "critical"] = "warning"
    ALERT_EMAIL_THROTTLE_HOURS: int = 6
    EMAIL_BACKEND: Literal["console", "smtp"] = "console"
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_USE_TLS: bool = True
    ALERT_FROM_EMAIL: str = "alerts@clickshield.local"
    TRACKING_FAILURE_HOURS: int = 6           # verified site silent this long (with recent traffic) → alert
    FRAUD_SPIKE_FACTOR: float = 3.0           # last hour's fraud rate vs. the 7-day rate
    FRAUD_SPIKE_MIN_FRAUD_SESSIONS: int = 10
    WEBSITE_ORIGIN_MISMATCH_ALERT_COUNT: int = 20   # rejected foreign-origin batches per hour
    SYSTEM_ERROR_ALERT_COUNT: int = 5         # unhandled errors in SYSTEM_ERROR_WINDOW_SECONDS
    SYSTEM_ERROR_WINDOW_SECONDS: int = 300
    INVITE_EXPIRY_HOURS: int = 72

    # ---- System health (spec §65, task 027) ----
    HEALTH_QUEUE_OLDEST_PENDING_SECONDS: int = 900   # oldest due action older than this → DEGRADED
    HEALTH_WORKER_HEARTBEAT_SECONDS: int = 120

    # ---- Data Retention (spec §79, task 029) — engineering defaults, a business/legal decision ----
    RETENTION_ENABLED: bool = True
    # Only count what would be removed (and audit the counts). Review, back up, then set false.
    RETENTION_DRY_RUN: bool = True
    RETENTION_BATCH_SIZE: int = 5000
    RAW_EVENTS_RETENTION_DAYS: int = 30
    SESSIONS_RETENTION_DAYS: int = 90
    # anonymize keeps aggregates (country, device, verdict…); delete removes the rows.
    SESSIONS_RETENTION_MODE: Literal["anonymize", "delete"] = "anonymize"
    FRAUD_SESSION_RETENTION_DAYS: int = 365
    AUDIT_LOG_RETENTION_DAYS: int = 730
    ALERT_RETENTION_DAYS: int = 180
    IP_REPUTATION_RETENTION_DAYS: int = 90    # reputation rows not seen this long (decay made them irrelevant)

    @property
    def is_development(self) -> bool:
        return self.ENVIRONMENT.strip().lower() in DEVELOPMENT_ENVIRONMENTS

    @property
    def fernet_keys(self) -> list[str]:
        keys = [key.strip() for key in self.TOKEN_ENCRYPTION_KEYS.split(",") if key.strip()]
        if not keys and self.TOKEN_ENCRYPTION_KEY.strip():
            keys = [self.TOKEN_ENCRYPTION_KEY.strip()]
        return keys

    @model_validator(mode="after")
    def validate_secrets(self) -> "Settings":
        """Task 032: refuse to start outside development with missing, weak or leaked secrets."""
        problems: list[str] = []
        if not self.SECRET_KEY:
            problems.append("SECRET_KEY is not set")
        elif len(self.SECRET_KEY.encode("utf-8")) < 32:
            problems.append("SECRET_KEY must be at least 32 bytes")
        elif _sha256(self.SECRET_KEY) in COMPROMISED_SECRET_HASHES:
            problems.append("SECRET_KEY is a value that was committed to the repository")

        keys = self.fernet_keys
        if not keys:
            problems.append("TOKEN_ENCRYPTION_KEYS (or TOKEN_ENCRYPTION_KEY) is not set")
        for key in keys:
            if _sha256(key) in COMPROMISED_SECRET_HASHES:
                problems.append("a token encryption key is a value that was committed to the repository")
            try:
                Fernet(key.encode("utf-8"))
            except Exception:
                problems.append("a token encryption key is not a valid Fernet key")
        if self.GOOGLE_CLIENT_ID and not self.GOOGLE_CLIENT_SECRET:
            problems.append("GOOGLE_CLIENT_SECRET is required when GOOGLE_CLIENT_ID is set")
        if "*" in [o.strip() for o in self.API_CORS_ORIGINS.split(",")]:
            problems.append("API_CORS_ORIGINS must list origins; '*' is never allowed for the dashboard API")

        if not self.is_development:
            if problems:
                raise ValueError(
                    f"Refusing to start with ENVIRONMENT={self.ENVIRONMENT!r}: " + "; ".join(problems)
                    + ". See backend/.env.example and deploy/README.md (secrets)."
                )
            return self

        # Development: keep running, but say so loudly.
        if not self.SECRET_KEY or len(self.SECRET_KEY.encode("utf-8")) < 32:
            self.SECRET_KEY = secrets.token_urlsafe(48)
            STARTUP_WARNINGS.append("SECRET_KEY not set: using a random key for this process (logins end on restart).")
        if not keys:
            self.TOKEN_ENCRYPTION_KEYS = Fernet.generate_key().decode()
            STARTUP_WARNINGS.append(
                "No TOKEN_ENCRYPTION_KEYS: using a random key for this process; stored Google tokens "
                "will not decrypt after a restart. Copy backend/.env.example to backend/.env."
            )
        for problem in problems:
            STARTUP_WARNINGS.append(f"Insecure configuration (allowed in development only): {problem}.")
        return self

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

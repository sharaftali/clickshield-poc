from __future__ import annotations

from pydantic import Field
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
        default="MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
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

    # ---- Google Ads Exclusion Limits (spec §39) ----
    GOOGLE_MAX_IP_EXCLUSIONS_PER_CAMPAIGN: int = 500

    # ---- Action Queue (spec §42–43) ----
    ACTION_QUEUE_MAX_ATTEMPTS: int = 5
    ACTION_QUEUE_RETRY_BACKOFF_SECONDS: int = 30
    ACTION_QUEUE_WORKER_CONCURRENCY: int = 4

    # ---- Bootstrap Admin (first-run seeding only) ----
    DEFAULT_ORGANIZATION_NAME: str = "Default Organization"
    DEFAULT_ORGANIZATION_SLUG: str = "default"
    DEFAULT_ADMIN_EMAIL: str = "admin@gmail.com"
    DEFAULT_ADMIN_PASSWORD: str = "ChangeMe@123"
    DEFAULT_ADMIN_FULL_NAME: str = "Admin"

    # ---- Data Retention (spec §79) ----
    RAW_EVENTS_RETENTION_DAYS: int = 30
    SESSIONS_RETENTION_DAYS: int = 90


settings = Settings()

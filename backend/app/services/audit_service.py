"""
Audit trail (spec §44, §62): every automated action and security-relevant event.

`record()` adds an AuditLog row to the caller's transaction, so the change and
its audit row are committed — or rolled back — together. Rows are append-only:
there is no update or delete path anywhere in the API.
"""
from __future__ import annotations

import uuid
from enum import StrEnum
from typing import Any

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.client_ip import ClientIPError, resolve_client_ip
from app.models import AuditLog, AuditResult


class AuditAction(StrEnum):
    # Protection (Google Ads exclusions)
    EXCLUSION_QUEUED = "EXCLUSION_QUEUED"
    ADD_IP_EXCLUSION = "ADD_IP_EXCLUSION"
    REMOVE_IP_EXCLUSION = "REMOVE_IP_EXCLUSION"
    EXCLUSION_RETRY_SCHEDULED = "EXCLUSION_RETRY_SCHEDULED"
    EXCLUSION_FAILED = "EXCLUSION_FAILED"
    EXCLUSION_SKIPPED = "EXCLUSION_SKIPPED"
    EXCLUSION_EVICTED = "EXCLUSION_EVICTED"
    EXCLUSION_PROMOTED = "EXCLUSION_PROMOTED"
    EXCLUSION_EXPIRED = "EXCLUSION_EXPIRED"
    EXCLUSION_CAPACITY_WARNING = "EXCLUSION_CAPACITY_WARNING"
    EXCLUSION_LIMIT_REACHED = "EXCLUSION_LIMIT_REACHED"
    # Google
    GOOGLE_CONNECT = "GOOGLE_CONNECT"
    GOOGLE_AUTH_EXPIRED = "GOOGLE_AUTH_EXPIRED"
    GOOGLE_SELECT_CUSTOMER = "GOOGLE_SELECT_CUSTOMER"
    GOOGLE_CAMPAIGN_SYNC = "GOOGLE_CAMPAIGN_SYNC"
    CAMPAIGN_PROTECTION_TOGGLED = "CAMPAIGN_PROTECTION_TOGGLED"
    # Auth
    USER_REGISTER = "USER_REGISTER"
    USER_LOGIN_SUCCESS = "USER_LOGIN_SUCCESS"
    USER_LOGIN_FAILED = "USER_LOGIN_FAILED"
    # Feedback
    SESSION_FEEDBACK = "SESSION_FEEDBACK"
    # Fraud engine configuration (tasks 015, 016)
    RULE_CHANGED = "RULE_CHANGED"
    PROTECTION_MODE_CHANGED = "PROTECTION_MODE_CHANGED"
    # Detection (task 022)
    TRAFFIC_ANOMALY_DETECTED = "TRAFFIC_ANOMALY_DETECTED"
    # Members (task 030)
    USER_INVITED = "USER_INVITED"
    INVITATION_REVOKED = "INVITATION_REVOKED"
    INVITATION_ACCEPTED = "INVITATION_ACCEPTED"
    USER_ROLE_CHANGED = "USER_ROLE_CHANGED"
    USER_ACTIVATED = "USER_ACTIVATED"
    USER_DEACTIVATED = "USER_DEACTIVATED"
    # Websites (task 023)
    WEBSITE_CREATED = "WEBSITE_CREATED"
    WEBSITE_UPDATED = "WEBSITE_UPDATED"
    WEBSITE_VERIFIED = "WEBSITE_VERIFIED"
    WEBSITE_TOKEN_ROTATED = "WEBSITE_TOKEN_ROTATED"
    WEBSITE_DELETED = "WEBSITE_DELETED"
    # Google OAuth (task 033)
    GOOGLE_CONNECT_STARTED = "GOOGLE_CONNECT_STARTED"
    # Organization settings (task 025 timezone, task 029 retention)
    ORGANIZATION_SETTINGS_CHANGED = "ORGANIZATION_SETTINGS_CHANGED"
    # Alerts (task 028)
    ALERT_ACKNOWLEDGED = "ALERT_ACKNOWLEDGED"
    ALERT_RESOLVED = "ALERT_RESOLVED"
    # Platform administration (task 027)
    ADMIN_ACTION_RETRY = "ADMIN_ACTION_RETRY"
    ADMIN_RULE_CHANGED = "ADMIN_RULE_CHANGED"
    # Privacy / retention (task 029)
    RETENTION_RUN = "RETENTION_RUN"
    PRIVACY_ERASE = "PRIVACY_ERASE"


# Any details key containing one of these is replaced, at any nesting depth.
SENSITIVE_KEY_PARTS = (
    "password", "secret", "token", "authorization", "cookie",
    "api_key", "apikey", "credential", "private_key",
)
REDACTED = "[redacted]"
MAX_ERROR_LENGTH = 2000


def scrub(value: Any) -> Any:
    """Copy of `value` with secret-looking keys redacted and values made JSON-safe."""
    if isinstance(value, dict):
        return {
            str(key): REDACTED
            if any(part in str(key).lower() for part in SENSITIVE_KEY_PARTS)
            else scrub(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple, set)):
        return [scrub(item) for item in value]
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    return str(value)  # UUID, datetime, IP address, enum ...


def _request_ip(request: Request | None) -> str | None:
    if request is None:
        return None
    try:
        return resolve_client_ip(request)
    except ClientIPError:
        return None


def record(
    db: AsyncSession,
    *,
    action: AuditAction | str,
    result: AuditResult,
    organization_id: uuid.UUID | None = None,
    user_id: uuid.UUID | None = None,
    resource_type: str | None = None,
    resource_id: uuid.UUID | str | None = None,
    details: dict[str, Any] | None = None,
    request: Request | None = None,
    ip_address: str | None = None,
    google_request_id: str | None = None,
    error: str | None = None,
) -> AuditLog:
    """Stage an audit row in the current transaction (the caller commits)."""
    entry = AuditLog(
        organization_id=organization_id,
        user_id=user_id,
        action=str(action),
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id is not None else None,
        ip_address=ip_address or _request_ip(request),
        details=scrub(details) if details else None,
        result=result,
        error_message=error[:MAX_ERROR_LENGTH] if error else None,
        google_request_id=google_request_id,
    )
    db.add(entry)
    return entry

from __future__ import annotations

import logging
import random
import uuid
from collections.abc import Callable
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.google_ads_adapter import ErrorCategory, GoogleAdsAdapter, GoogleAdsApiResult
from app.core.config import settings
from app.core.crypto import decrypt
from app.models import (
    ActionStatus,
    ActionType,
    AuditResult,
    Exclusion,
    ExclusionStatus,
    GoogleCampaign,
    GoogleConnection,
    IPReputation,
    Platform,
    PlatformAction,
)
from app.services import audit_service
from app.services.audit_service import AuditAction
from app.services.exclusion_capacity import lock_campaign, rebalance
from app.services.google_oauth import GoogleAuthError, refresh_access_token

logger = logging.getLogger(__name__)


RETRY_JITTER = 0.2  # ±20%, so retries from one outage don't all fire at once


def compute_next_attempt(
    attempts: int,
    now: datetime,
    *,
    rand: Callable[[], float] = random.random,
) -> datetime:
    """Exponential backoff (spec §43): base, 2×base, 4×base … capped, with jitter."""
    base = settings.ACTION_QUEUE_RETRY_BACKOFF_SECONDS
    delay = min(settings.ACTION_QUEUE_RETRY_MAX_BACKOFF_SECONDS, base * 2 ** max(0, attempts - 1))
    delay *= 1 + RETRY_JITTER * (2 * rand() - 1)
    return now + timedelta(seconds=delay)


def build_claim_query(now: datetime, organization_id=None, *, action_id: uuid.UUID | None = None):
    filters = [
        PlatformAction.status.in_([ActionStatus.PENDING, ActionStatus.RETRYING]),
        PlatformAction.scheduled_at.is_(None) | (PlatformAction.scheduled_at <= now),
    ]
    if organization_id is not None:
        filters.append(PlatformAction.organization_id == organization_id)
    if action_id is not None:
        filters.append(PlatformAction.id == action_id)
    return (
        select(PlatformAction)
        .where(*filters)
        .order_by(PlatformAction.scheduled_at.asc().nulls_first(), PlatformAction.created_at.asc())
        .limit(1)
        .with_for_update(skip_locked=True)
    )


def build_connection_by_campaign_query(exclusion: Exclusion):
    return (
        select(GoogleConnection)
        .join(GoogleCampaign, GoogleCampaign.connection_id == GoogleConnection.id)
        .where(
            GoogleCampaign.id == exclusion.google_campaign_id,
            GoogleConnection.organization_id == exclusion.organization_id,
        )
    )


def build_connection_by_customer_query(exclusion: Exclusion):
    return (
        select(GoogleConnection)
        .where(
            GoogleConnection.organization_id == exclusion.organization_id,
            GoogleConnection.customer_id == exclusion.google_customer_id,
        )
        .order_by(GoogleConnection.is_active.desc(), GoogleConnection.created_at.desc())
        .limit(1)
    )


def build_reap_stuck_actions(now: datetime, organization_id=None):
    """Actions left PROCESSING by a crashed worker go back to the queue."""
    stmt = update(PlatformAction).where(
        PlatformAction.status == ActionStatus.PROCESSING,
        PlatformAction.updated_at < now - timedelta(seconds=settings.ACTION_QUEUE_STUCK_AFTER_SECONDS),
    )
    if organization_id is not None:
        stmt = stmt.where(PlatformAction.organization_id == organization_id)
    return stmt.values(
        status=ActionStatus.RETRYING,
        scheduled_at=now,
        last_error="Worker stopped while processing this action; re-queued.",
    )


def _describe(result: GoogleAdsApiResult) -> str:
    tags = "/".join(str(tag) for tag in (result.error_category, result.error_code) if tag)
    message = result.message or "Google Ads action failed."
    return f"[{tags}] {message}" if tags else message


class ActionWorker:
    """Processes queued Google Ads protection actions with retry + auditability.

    Never marks an exclusion ACTIVE without a real Google Ads resource name
    (spec §43 "Never silently fail"). Every outcome is written to the audit
    log in the same transaction (spec §44).
    """

    async def process_pending(
        self,
        db: AsyncSession,
        *,
        organization_id: str | None = None,
        limit: int = 50,
    ) -> dict[str, int]:
        metrics = {"processed": 0, "successful": 0, "failed": 0, "skipped": 0, "retrying": 0}

        await db.execute(build_reap_stuck_actions(datetime.now(timezone.utc), organization_id))
        await db.commit()

        for _ in range(limit):
            action = await self._claim(db, organization_id=organization_id)
            if action is None:
                break
            metrics["processed"] += 1
            outcome = await self._process_action(db, action)
            metrics[outcome] += 1
            await db.commit()

        return metrics

    async def process_action_id(self, db: AsyncSession, action_id: uuid.UUID) -> str | None:
        """Process one specific action (arq job). None if it is not due or already taken."""
        action = await self._claim(db, action_id=action_id)
        if action is None:
            return None
        outcome = await self._process_action(db, action)
        await db.commit()
        return outcome

    async def _claim(
        self, db: AsyncSession, *, organization_id=None, action_id: uuid.UUID | None = None
    ) -> PlatformAction | None:
        """Lock one due action, mark it PROCESSING and commit, so no other worker takes it."""
        result = await db.execute(
            build_claim_query(datetime.now(timezone.utc), organization_id, action_id=action_id)
        )
        action = result.scalar_one_or_none()
        if action is None:
            await db.rollback()  # release the (empty) transaction
            return None
        action.status = ActionStatus.PROCESSING
        action.attempts += 1
        await db.commit()
        return action

    async def _process_action(self, db: AsyncSession, action: PlatformAction) -> str:
        """Run one action. Returns the metrics bucket it ended in."""
        if action.platform != Platform.GOOGLE:
            return await self._fail(
                db, action, None, "Only Google Ads actions are currently supported by the protection worker."
            )

        exclusion = await self._get_exclusion(db, action.reference_id, action.organization_id)
        if exclusion is None:
            return await self._fail(db, action, None, "Exclusion reference was not found for this organization.")

        if action.action_type not in (ActionType.ADD_IP_EXCLUSION, ActionType.REMOVE_IP_EXCLUSION):
            await self._fail(db, action, exclusion, f"Unsupported action type: {action.action_type}")
            return "skipped"

        if settings.GOOGLE_ADS_DRY_RUN:
            return await self._dry_run(db, action, exclusion)

        if not settings.GOOGLE_CLIENT_ID or not settings.GOOGLE_CLIENT_SECRET:
            return await self._fail(
                db, action, exclusion,
                "Google Ads is not configured (GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET missing).",
            )

        # The connection that owns this exclusion's campaign — never "the newest one" (task 009).
        connection = await self._get_connection_for_exclusion(db, exclusion)
        if connection is None:
            customer = exclusion.google_customer_id or "(unknown)"
            return await self._fail(db, action, exclusion, f"No Google Ads connection found for customer {customer}.")
        if not connection.is_active:
            return await self._fail(
                db, action, exclusion, "The Google Ads connection for this campaign is disconnected."
            )
        if connection.needs_reauth:
            detail = connection.auth_error or "reconnect Google Ads"
            return await self._fail(
                db, action, exclusion, f"Google Ads connection needs re-authorization: {detail}"
            )

        try:
            access_token = await self._get_access_token(connection)
        except GoogleAuthError as exc:
            if exc.permanent:
                self._flag_reauth(db, connection, str(exc))
                return await self._fail(db, action, exclusion, str(exc))
            return await self._retry_or_fail(db, action, exclusion, str(exc))

        # Target the customer the exclusion was created for, even if the connection's
        # selected customer changed since (legacy rows without one use the connection's).
        if not exclusion.google_customer_id:
            exclusion.google_customer_id = connection.customer_id
        adapter = GoogleAdsAdapter(
            customer_id=exclusion.google_customer_id,
            access_token=access_token,
            login_customer_id=connection.login_customer_id,
        )

        if action.action_type == ActionType.ADD_IP_EXCLUSION:
            outcome = await adapter.create_ip_exclusion(
                campaign_id=exclusion.campaign_id,
                ip_address=str(exclusion.ip_address),
                reason=exclusion.reason,
            )
        else:
            outcome = await adapter.remove_ip_exclusion(
                campaign_id=exclusion.campaign_id,
                ip_address=str(exclusion.ip_address),
                resource_name=exclusion.google_resource_name,
            )

        if outcome.ok:
            return await self._succeed(db, action, exclusion, outcome)

        if outcome.api_request_id:
            exclusion.api_request_id = outcome.api_request_id
        if outcome.error_category == ErrorCategory.AUTH:
            self._flag_reauth(db, connection, _describe(outcome))
        if outcome.retryable:
            return await self._retry_or_fail(db, action, exclusion, _describe(outcome), outcome)
        return await self._fail(db, action, exclusion, _describe(outcome), outcome)

    # ---- outcomes -----------------------------------------------------------

    async def _succeed(
        self,
        db: AsyncSession,
        action: PlatformAction,
        exclusion: Exclusion,
        outcome: GoogleAdsApiResult,
    ) -> str:
        now = datetime.now(timezone.utc)
        if action.action_type == ActionType.ADD_IP_EXCLUSION and not outcome.resource_name:
            # The adapter guarantees a resource name; never mark ACTIVE without one.
            return await self._fail(
                db, action, exclusion, "Google Ads returned no resource name for the exclusion.", outcome
            )

        action.status = ActionStatus.SUCCESS
        action.completed_at = now
        action.last_error = None
        exclusion.last_error = None
        exclusion.api_request_id = outcome.api_request_id or exclusion.api_request_id
        if action.action_type == ActionType.ADD_IP_EXCLUSION:
            exclusion.status = ExclusionStatus.ACTIVE
            exclusion.overflow = False
            exclusion.google_resource_name = outcome.resource_name
            exclusion.submitted_at = now
            await self._increment_blocked_count(db, exclusion.organization_id, str(exclusion.ip_address))
            audit_action = AuditAction.ADD_IP_EXCLUSION
        else:
            exclusion.status = ExclusionStatus.REMOVED
            exclusion.removed_at = now
            audit_action = AuditAction.REMOVE_IP_EXCLUSION

        self._audit(db, action, exclusion, audit_action, AuditResult.SUCCESS, outcome=outcome)
        if action.action_type == ActionType.REMOVE_IP_EXCLUSION:
            await self._slot_freed(db, exclusion)  # eviction / expiry → promote the overflow queue
        return "successful"

    async def _dry_run(self, db: AsyncSession, action: PlatformAction, exclusion: Exclusion) -> str:
        message = "Dry-run (GOOGLE_ADS_DRY_RUN=true): no Google Ads call was made."
        action.status = ActionStatus.SUCCESS
        action.completed_at = datetime.now(timezone.utc)
        action.last_error = message
        if action.action_type == ActionType.ADD_IP_EXCLUSION:
            exclusion.status = ExclusionStatus.SKIPPED
            exclusion.last_error = message
        self._audit(
            db, action, exclusion, AuditAction.EXCLUSION_SKIPPED, AuditResult.SUCCESS,
            error=message, extra={"skip_reason": "dry_run"},
        )
        logger.info("Dry-run protection action %s for exclusion %s", action.id, exclusion.id)
        return "skipped"

    async def _fail(
        self,
        db: AsyncSession,
        action: PlatformAction,
        exclusion: Exclusion | None,
        message: str,
        outcome: GoogleAdsApiResult | None = None,
    ) -> str:
        action.status = ActionStatus.FAILED
        action.last_error = message
        action.completed_at = datetime.now(timezone.utc)
        freed_slot = False
        if exclusion is not None:
            if action.action_type == ActionType.ADD_IP_EXCLUSION:
                freed_slot = exclusion.status in (ExclusionStatus.PENDING, ExclusionStatus.SUBMITTED)
                exclusion.status = ExclusionStatus.FAILED
            exclusion.last_error = message
        self._audit(
            db, action, exclusion, AuditAction.EXCLUSION_FAILED, AuditResult.FAILED,
            outcome=outcome, error=message,
        )
        logger.error(
            "Protection action %s (%s) failed permanently: %s",
            action.id, action.action_type, message,
        )
        if freed_slot and exclusion is not None:
            await self._slot_freed(db, exclusion)
        return "failed"

    async def _retry_or_fail(
        self,
        db: AsyncSession,
        action: PlatformAction,
        exclusion: Exclusion,
        message: str,
        outcome: GoogleAdsApiResult | None = None,
    ) -> str:
        if action.attempts >= action.max_attempts:
            return await self._fail(
                db, action, exclusion, f"{message} (gave up after {action.attempts} attempts)", outcome
            )
        next_attempt = compute_next_attempt(action.attempts, datetime.now(timezone.utc))
        action.status = ActionStatus.RETRYING
        action.last_error = message
        action.scheduled_at = next_attempt
        # The exclusion stays PENDING while retries are outstanding (spec §43).
        exclusion.last_error = (
            f"{message} — attempt {action.attempts}/{action.max_attempts} failed, "
            f"next retry {next_attempt:%Y-%m-%d %H:%M:%S} UTC"
        )
        self._audit(
            db, action, exclusion, AuditAction.EXCLUSION_RETRY_SCHEDULED, AuditResult.PENDING,
            outcome=outcome, error=message, extra={"next_attempt_at": next_attempt},
        )
        logger.warning(
            "Protection action %s attempt %d/%d failed, retry at %s: %s",
            action.id, action.attempts, action.max_attempts, next_attempt.isoformat(), message,
        )
        return "retrying"

    async def _slot_freed(self, db: AsyncSession, exclusion: Exclusion) -> None:
        """A campaign slot opened: promote the overflow queue (task 012)."""
        if exclusion.google_campaign_id is None:
            return
        locked = await lock_campaign(db, exclusion.google_campaign_id, exclusion.organization_id)
        if locked is not None:
            await rebalance(db, locked[0])

    @staticmethod
    def _audit(
        db: AsyncSession,
        action: PlatformAction,
        exclusion: Exclusion | None,
        audit_action: AuditAction,
        result: AuditResult,
        *,
        outcome: GoogleAdsApiResult | None = None,
        error: str | None = None,
        extra: dict | None = None,
    ) -> None:
        details: dict = {
            "action_id": action.id,
            "action_type": action.action_type,
            "attempt": action.attempts,
            "max_attempts": action.max_attempts,
        }
        if exclusion is not None:
            details.update(
                ip=exclusion.ip_address,
                campaign_id=exclusion.campaign_id,
                customer_id=exclusion.google_customer_id,
                risk=exclusion.risk_score,
                confidence=exclusion.confidence,
                reason=exclusion.reason,
                resource_name=exclusion.google_resource_name,
            )
        if outcome is not None and not outcome.ok:
            details.update(error_category=outcome.error_category, error_code=outcome.error_code)
        if extra:
            details.update(extra)
        request_id = outcome.api_request_id if outcome is not None else None
        if request_id is None and exclusion is not None:
            request_id = exclusion.api_request_id
        audit_service.record(
            db,
            action=audit_action,
            result=result,
            organization_id=action.organization_id,
            resource_type="exclusion" if exclusion is not None else "platform_action",
            resource_id=exclusion.id if exclusion is not None else action.id,
            details=details,
            google_request_id=request_id,
            error=error,
        )

    @staticmethod
    def _flag_reauth(db: AsyncSession, connection: GoogleConnection, message: str) -> None:
        if not connection.needs_reauth:
            audit_service.record(
                db,
                action=AuditAction.GOOGLE_AUTH_EXPIRED,
                result=AuditResult.FAILED,
                organization_id=connection.organization_id,
                resource_type="google_connection",
                resource_id=connection.id,
                details={"customer_id": connection.customer_id, "email": connection.google_account_email},
                error=message,
            )
        connection.needs_reauth = True
        connection.auth_error = message[:1000]
        logger.error("Google connection %s needs re-authorization: %s", connection.id, message)

    # ---- lookups --------------------------------------------------------------

    async def _get_connection_for_exclusion(
        self,
        db: AsyncSession,
        exclusion: Exclusion,
    ) -> GoogleConnection | None:
        if exclusion.google_campaign_id is not None:
            result = await db.execute(build_connection_by_campaign_query(exclusion))
            connection = result.scalar_one_or_none()
            if connection is not None:
                return connection
        if not exclusion.google_customer_id:
            return None
        # Legacy rows without a campaign link: a connection of this org owning the customer.
        result = await db.execute(build_connection_by_customer_query(exclusion))
        return result.scalar_one_or_none()

    async def _get_access_token(self, connection: GoogleConnection) -> str:
        """Raise GoogleAuthError on failure; never return a missing token."""
        try:
            refresh_token = decrypt(connection.refresh_token_encrypted)
        except ValueError as exc:
            # Key rotated or data corrupt: only a fresh OAuth grant fixes this.
            raise GoogleAuthError(
                "Stored Google refresh token could not be decrypted; reconnect Google Ads.",
                permanent=True,
            ) from exc
        payload = await refresh_access_token(refresh_token)
        connection.last_refreshed_at = datetime.now(timezone.utc)
        return payload["access_token"]

    async def _get_exclusion(
        self,
        db: AsyncSession,
        exclusion_id,
        organization_id,
    ) -> Exclusion | None:
        if exclusion_id is None:
            return None
        # Scoped to the action's tenant so a bad reference can't act on another org's IP.
        result = await db.execute(
            select(Exclusion).where(
                Exclusion.id == exclusion_id,
                Exclusion.organization_id == organization_id,
            )
        )
        return result.scalar_one_or_none()

    async def _increment_blocked_count(
        self,
        db: AsyncSession,
        organization_id,
        ip_address: str,
    ) -> None:
        await db.execute(
            update(IPReputation)
            .where(
                IPReputation.organization_id == organization_id,
                IPReputation.ip == ip_address,
            )
            .values(blocked_count=IPReputation.blocked_count + 1)
        )

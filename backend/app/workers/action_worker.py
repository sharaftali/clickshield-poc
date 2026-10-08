from __future__ import annotations

import logging
import random
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
    Exclusion,
    ExclusionStatus,
    GoogleCampaign,
    GoogleConnection,
    IPReputation,
    Platform,
    PlatformAction,
)
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


def build_claim_query(now: datetime, organization_id=None):
    filters = [
        PlatformAction.status.in_([ActionStatus.PENDING, ActionStatus.RETRYING]),
        PlatformAction.scheduled_at.is_(None) | (PlatformAction.scheduled_at <= now),
    ]
    if organization_id is not None:
        filters.append(PlatformAction.organization_id == organization_id)
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
    (spec §43 "Never silently fail").
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
            action = await self._claim_next(db, organization_id)
            if action is None:
                break
            metrics["processed"] += 1
            outcome = await self._process_action(db, action)
            metrics[outcome] += 1
            await db.commit()

        return metrics

    async def _claim_next(self, db: AsyncSession, organization_id) -> PlatformAction | None:
        """Lock one due action, mark it PROCESSING and commit, so no other worker takes it."""
        result = await db.execute(build_claim_query(datetime.now(timezone.utc), organization_id))
        action = result.scalar_one_or_none()
        if action is None:
            return None
        action.status = ActionStatus.PROCESSING
        action.attempts += 1
        await db.commit()
        return action

    async def _process_action(self, db: AsyncSession, action: PlatformAction) -> str:
        """Run one action. Returns the metrics bucket it ended in."""
        if action.platform != Platform.GOOGLE:
            return self._fail(action, None, "Only Google Ads actions are currently supported by the protection worker.")

        exclusion = await self._get_exclusion(db, action.reference_id, action.organization_id)
        if exclusion is None:
            return self._fail(action, None, "Exclusion reference was not found for this organization.")

        if action.action_type not in (ActionType.ADD_IP_EXCLUSION, ActionType.REMOVE_IP_EXCLUSION):
            self._fail(action, exclusion, f"Unsupported action type: {action.action_type}")
            return "skipped"

        if settings.GOOGLE_ADS_DRY_RUN:
            return self._dry_run(action, exclusion)

        if not settings.GOOGLE_CLIENT_ID or not settings.GOOGLE_CLIENT_SECRET:
            return self._fail(
                action, exclusion,
                "Google Ads is not configured (GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET missing).",
            )

        # The connection that owns this exclusion's campaign — never "the newest one" (task 009).
        connection = await self._get_connection_for_exclusion(db, exclusion)
        if connection is None:
            return self._fail(
                action, exclusion,
                f"No Google Ads connection found for customer {exclusion.google_customer_id or '(unknown)'}.",
            )
        if not connection.is_active:
            return self._fail(action, exclusion, "The Google Ads connection for this campaign is disconnected.")
        if connection.needs_reauth:
            return self._fail(
                action, exclusion,
                f"Google Ads connection needs re-authorization: {connection.auth_error or 'reconnect Google Ads'}",
            )

        try:
            access_token = await self._get_access_token(connection)
        except GoogleAuthError as exc:
            if exc.permanent:
                self._flag_reauth(connection, str(exc))
                return self._fail(action, exclusion, str(exc))
            return self._retry_or_fail(action, exclusion, str(exc))

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
            await self._succeed(db, action, exclusion, outcome)
            return "successful"

        if outcome.api_request_id:
            exclusion.api_request_id = outcome.api_request_id
        if outcome.error_category == ErrorCategory.AUTH:
            self._flag_reauth(connection, _describe(outcome))
        if outcome.retryable:
            return self._retry_or_fail(action, exclusion, _describe(outcome))
        return self._fail(action, exclusion, _describe(outcome))

    # ---- outcomes -----------------------------------------------------------

    async def _succeed(
        self,
        db: AsyncSession,
        action: PlatformAction,
        exclusion: Exclusion,
        outcome: GoogleAdsApiResult,
    ) -> None:
        now = datetime.now(timezone.utc)
        action.status = ActionStatus.SUCCESS
        action.completed_at = now
        action.last_error = None
        exclusion.last_error = None
        exclusion.api_request_id = outcome.api_request_id or exclusion.api_request_id
        if action.action_type == ActionType.ADD_IP_EXCLUSION:
            if not outcome.resource_name:  # adapter guarantees this; never mark ACTIVE without it
                self._fail(action, exclusion, "Google Ads returned no resource name for the exclusion.")
                return
            exclusion.status = ExclusionStatus.ACTIVE
            exclusion.google_resource_name = outcome.resource_name
            exclusion.submitted_at = now
            await self._increment_blocked_count(db, exclusion.organization_id, str(exclusion.ip_address))
        else:
            exclusion.status = ExclusionStatus.REMOVED
            exclusion.removed_at = now

    def _dry_run(self, action: PlatformAction, exclusion: Exclusion) -> str:
        message = "Dry-run (GOOGLE_ADS_DRY_RUN=true): no Google Ads call was made."
        action.status = ActionStatus.SUCCESS
        action.completed_at = datetime.now(timezone.utc)
        action.last_error = message
        if action.action_type == ActionType.ADD_IP_EXCLUSION:
            exclusion.status = ExclusionStatus.SKIPPED
            exclusion.last_error = message
        logger.info("Dry-run protection action %s for exclusion %s", action.id, exclusion.id)
        return "skipped"

    def _fail(self, action: PlatformAction, exclusion: Exclusion | None, message: str) -> str:
        action.status = ActionStatus.FAILED
        action.last_error = message
        action.completed_at = datetime.now(timezone.utc)
        if exclusion is not None and action.action_type == ActionType.ADD_IP_EXCLUSION:
            exclusion.status = ExclusionStatus.FAILED
        if exclusion is not None:
            exclusion.last_error = message
        logger.error(
            "Protection action %s (%s) failed permanently: %s",
            action.id, action.action_type, message,
        )
        return "failed"

    def _retry_or_fail(self, action: PlatformAction, exclusion: Exclusion, message: str) -> str:
        if action.attempts >= action.max_attempts:
            return self._fail(action, exclusion, f"{message} (gave up after {action.attempts} attempts)")
        next_attempt = compute_next_attempt(action.attempts, datetime.now(timezone.utc))
        action.status = ActionStatus.RETRYING
        action.last_error = message
        action.scheduled_at = next_attempt
        # The exclusion stays PENDING while retries are outstanding (spec §43).
        exclusion.last_error = (
            f"{message} — attempt {action.attempts}/{action.max_attempts} failed, "
            f"next retry {next_attempt:%Y-%m-%d %H:%M:%S} UTC"
        )
        logger.warning(
            "Protection action %s attempt %d/%d failed, retry at %s: %s",
            action.id, action.attempts, action.max_attempts, next_attempt.isoformat(), message,
        )
        return "retrying"

    @staticmethod
    def _flag_reauth(connection: GoogleConnection, message: str) -> None:
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

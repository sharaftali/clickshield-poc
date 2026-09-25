from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.google_ads_adapter import GoogleAdsAdapter
from app.core.crypto import decrypt
from app.models import (
    ActionStatus,
    ActionType,
    Exclusion,
    ExclusionStatus,
    GoogleConnection,
    IPReputation,
    Platform,
    PlatformAction,
)
from app.services.google_oauth import refresh_access_token


class ActionWorker:
    """Processes queued Google Ads protection actions with retry + auditability."""

    async def process_pending(
        self,
        db: AsyncSession,
        *,
        organization_id: str | None = None,
        limit: int = 50,
    ) -> dict[str, int]:
        filters = [
            PlatformAction.status.in_([ActionStatus.PENDING, ActionStatus.RETRYING]),
            PlatformAction.scheduled_at.is_(None)
            | (PlatformAction.scheduled_at <= datetime.now(timezone.utc)),
        ]
        if organization_id is not None:
            filters.append(PlatformAction.organization_id == organization_id)

        result = await db.execute(
            select(PlatformAction)
            .where(*filters)
            .order_by(PlatformAction.scheduled_at.asc().nulls_first(), PlatformAction.created_at.asc())
            .limit(limit)
        )
        actions = result.scalars().all()

        metrics = {"processed": 0, "successful": 0, "failed": 0, "skipped": 0}

        for action in actions:
            metrics["processed"] += 1
            action.status = ActionStatus.PROCESSING
            action.attempts += 1
            await db.flush()

            if action.platform != Platform.GOOGLE:
                action.status = ActionStatus.FAILED
                action.last_error = "Only Google Ads actions are currently supported by the protection worker."
                metrics["failed"] += 1
                await db.commit()
                continue

            connection = await self._get_active_connection(db, action.organization_id)
            if connection is None:
                action.status = ActionStatus.FAILED
                action.last_error = "No active Google Ads connection exists for this organization."
                await self._mark_exclusion_failed(db, action, action.last_error)
                metrics["failed"] += 1
                await db.commit()
                continue

            exclusion = await self._get_exclusion(db, action.reference_id)
            if exclusion is None:
                action.status = ActionStatus.FAILED
                action.last_error = "Exclusion reference was not found."
                metrics["failed"] += 1
                await db.commit()
                continue

            access_token = await self._get_access_token(connection)
            adapter = GoogleAdsAdapter(
                customer_id=connection.customer_id,
                access_token=access_token,
                login_customer_id=connection.login_customer_id,
            )

            if action.action_type == ActionType.ADD_IP_EXCLUSION:
                result_payload = await adapter.create_ip_exclusion(
                    campaign_id=exclusion.campaign_id,
                    ip_address=str(exclusion.ip_address),
                    reason=exclusion.reason,
                )
            elif action.action_type == ActionType.REMOVE_IP_EXCLUSION:
                result_payload = await adapter.remove_ip_exclusion(
                    campaign_id=exclusion.campaign_id,
                    ip_address=str(exclusion.ip_address),
                    resource_name=exclusion.google_resource_name,
                )
            else:
                action.status = ActionStatus.FAILED
                action.last_error = f"Unsupported action type: {action.action_type}"
                metrics["skipped"] += 1
                await db.commit()
                continue

            if result_payload.ok:
                action.status = ActionStatus.SUCCESS
                action.completed_at = datetime.now(timezone.utc)
                action.last_error = None
                if action.action_type == ActionType.ADD_IP_EXCLUSION:
                    exclusion.status = ExclusionStatus.ACTIVE
                    exclusion.google_resource_name = result_payload.resource_name
                    exclusion.api_request_id = result_payload.api_request_id
                    exclusion.submitted_at = datetime.now(timezone.utc)
                    exclusion.reason = exclusion.reason or "High-risk fraudulent session flagged by Click Shield"
                    await self._increment_blocked_count(db, str(exclusion.ip_address))
                else:
                    exclusion.status = ExclusionStatus.REMOVED
                    exclusion.removed_at = datetime.now(timezone.utc)
                metrics["successful"] += 1
            else:
                if action.attempts >= action.max_attempts:
                    action.status = ActionStatus.FAILED
                    action.last_error = result_payload.message or "Action failed after all retry attempts."
                    if action.action_type == ActionType.ADD_IP_EXCLUSION:
                        exclusion.status = ExclusionStatus.FAILED
                    metrics["failed"] += 1
                else:
                    action.status = ActionStatus.RETRYING
                    action.last_error = result_payload.message or "Action failed; retry scheduled."
                    action.scheduled_at = datetime.now(timezone.utc)
                    if action.action_type == ActionType.ADD_IP_EXCLUSION:
                        exclusion.status = ExclusionStatus.FAILED
                    metrics["failed"] += 1

            await db.commit()

        return metrics

    async def _get_active_connection(
        self,
        db: AsyncSession,
        organization_id: str,
    ) -> GoogleConnection | None:
        result = await db.execute(
            select(GoogleConnection)
            .where(
                GoogleConnection.organization_id == organization_id,
                GoogleConnection.is_active.is_(True),
            )
            .order_by(GoogleConnection.created_at.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()

    async def _get_access_token(self, connection: GoogleConnection) -> str | None:
        try:
            refresh_token = decrypt(connection.refresh_token_encrypted)
            payload = await refresh_access_token(refresh_token)
            return payload.get("access_token")
        except Exception:
            return None

    async def _get_exclusion(
        self,
        db: AsyncSession,
        exclusion_id: str | None,
    ) -> Exclusion | None:
        if exclusion_id is None:
            return None
        result = await db.execute(select(Exclusion).where(Exclusion.id == exclusion_id))
        return result.scalar_one_or_none()

    async def _mark_exclusion_failed(
        self,
        db: AsyncSession,
        action: PlatformAction,
        error: str,
    ) -> None:
        exclusion = await self._get_exclusion(db, action.reference_id)
        if exclusion is not None:
            exclusion.status = ExclusionStatus.FAILED
            reason_text = (
                f"{exclusion.reason or 'Protection action failed'} | {error}"
                if exclusion.reason
                else error
            )
            exclusion.reason = reason_text
            exclusion.api_request_id = action.id.hex[:12]

    async def _increment_blocked_count(
        self,
        db: AsyncSession,
        ip_address: str,
    ) -> None:
        result = await db.execute(
            select(IPReputation).where(IPReputation.ip == ip_address)
        )
        reputation = result.scalar_one_or_none()
        if reputation is None:
            return
        reputation.blocked_count = int(reputation.blocked_count or 0) + 1

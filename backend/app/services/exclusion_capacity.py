"""
Per-campaign IP exclusion capacity (spec §39, §73; task 012).

Google allows a limited number of IP exclusions per campaign (500 today,
configurable). Slots are used by Click Shield exclusions that are PENDING,
SUBMITTED or ACTIVE, plus IPs the advertiser excluded by hand. When a campaign
is full a new candidate waits in the overflow queue (status SKIPPED,
overflow=true); a strictly stronger candidate may evict the weakest active
exclusion — the REMOVE runs first, then the freed slot is promoted, so Google
never holds more than the limit.

Every function that changes slot usage expects the caller to hold the campaign
row lock (lock_campaign), so concurrent enqueues can't take the same slot.
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import exists, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models import (
    ActionStatus,
    ActionType,
    AuditResult,
    Exclusion,
    ExclusionStatus,
    GoogleCampaign,
    GoogleConnection,
    Platform,
    PlatformAction,
)
from app.services import audit_service
from app.services.audit_service import AuditAction

logger = logging.getLogger(__name__)

SLOT_STATUSES = (ExclusionStatus.PENDING, ExclusionStatus.SUBMITTED, ExclusionStatus.ACTIVE)
OPEN_ACTION_STATUSES = (ActionStatus.PENDING, ActionStatus.PROCESSING, ActionStatus.RETRYING)
WARNING_RATIO = 0.9


@dataclass(frozen=True)
class Capacity:
    used_by_click_shield: int
    external: int
    limit: int

    @property
    def used(self) -> int:
        return self.used_by_click_shield + self.external

    @property
    def available(self) -> int:
        return max(0, self.limit - self.used)

    @property
    def ratio(self) -> float:
        return self.used / self.limit if self.limit else 1.0


def campaign_limit() -> int:
    return max(1, settings.GOOGLE_MAX_IP_EXCLUSIONS_PER_CAMPAIGN - settings.GOOGLE_EXCLUSION_RESERVED_SLOTS)


def priority(exclusion: Exclusion) -> tuple[int, int]:
    """Higher is more important to keep. Ties are broken by recency in queries."""
    return int(exclusion.confidence or 0), int(exclusion.risk_score or 0)


def new_action(exclusion: Exclusion, action_type: ActionType) -> PlatformAction:
    return PlatformAction(
        id=uuid.uuid4(),
        organization_id=exclusion.organization_id,
        platform=Platform.GOOGLE,
        action_type=action_type,
        reference_id=exclusion.id,
        status=ActionStatus.PENDING,
        scheduled_at=datetime.now(timezone.utc),
        attempts=0,
        max_attempts=settings.ACTION_QUEUE_MAX_ATTEMPTS,
    )


async def lock_campaign(
    db: AsyncSession, campaign_row_id: uuid.UUID, organization_id: uuid.UUID
) -> tuple[GoogleCampaign, GoogleConnection] | None:
    """Lock a campaign of this tenant for a capacity decision (spec §58: tenant-scoped)."""
    row = (
        await db.execute(
            select(GoogleCampaign, GoogleConnection)
            .join(GoogleConnection, GoogleConnection.id == GoogleCampaign.connection_id)
            .where(
                GoogleCampaign.id == campaign_row_id,
                GoogleConnection.organization_id == organization_id,
            )
            .with_for_update(of=GoogleCampaign)
        )
    ).first()
    return (row[0], row[1]) if row is not None else None


async def get_capacity(db: AsyncSession, campaign: GoogleCampaign) -> Capacity:
    used = await db.scalar(
        select(func.count())
        .select_from(Exclusion)
        .where(Exclusion.google_campaign_id == campaign.id, Exclusion.status.in_(SLOT_STATUSES))
    )
    return Capacity(
        used_by_click_shield=int(used or 0),
        external=int(campaign.external_exclusion_count or 0),
        limit=campaign_limit(),
    )


async def sync_exclusion_count(db: AsyncSession, campaign: GoogleCampaign) -> None:
    await db.flush()
    capacity = await get_capacity(db, campaign)
    campaign.exclusion_count = capacity.used_by_click_shield
    await capacity_alert(db, campaign, capacity)


async def capacity_alert(db: AsyncSession, campaign: GoogleCampaign, capacity: Capacity) -> None:
    """Spec §66 "Exclusion limit reached": warning from 90%, critical at 100%, resolved below 90%."""
    from app.services import alert_service

    key = alert_service.capacity_key(campaign.id)
    if capacity.limit <= 0 or capacity.used < WARNING_RATIO * capacity.limit:
        await alert_service.resolve(db, dedupe_key=key)
        return
    organization_id = await db.scalar(
        select(GoogleConnection.organization_id).where(GoogleConnection.id == campaign.connection_id)
    )
    full = capacity.used >= capacity.limit
    await alert_service.raise_alert(
        db, organization_id=organization_id, type=alert_service.AlertType.EXCLUSION_LIMIT_REACHED,
        severity="critical" if full else "warning", dedupe_key=key,
        title=f"Campaign {campaign.name} {'reached' if full else 'is near'} its IP exclusion limit",
        message=(f"{capacity.used} of {capacity.limit} IP exclusion slots are used on {campaign.name}. "
                 + ("New fraud IPs wait in the overflow queue." if full else "")).strip(),
        resource_type="campaign", resource_id=str(campaign.id),
        details={"used": capacity.used, "limit": capacity.limit},
    )


def _open_removal_exists(campaign: GoogleCampaign):
    return exists().where(
        PlatformAction.reference_id == Exclusion.id,
        PlatformAction.action_type == ActionType.REMOVE_IP_EXCLUSION,
        PlatformAction.status.in_(OPEN_ACTION_STATUSES),
        Exclusion.google_campaign_id == campaign.id,
    )


async def has_open_removal(db: AsyncSession, campaign: GoogleCampaign) -> bool:
    return bool(await db.scalar(select(_open_removal_exists(campaign))))


async def pick_eviction_candidate(db: AsyncSession, campaign: GoogleCampaign) -> Exclusion | None:
    """Weakest ACTIVE exclusion: lowest confidence, then risk, then oldest evidence (spec §39)."""
    being_removed = exists().where(
        PlatformAction.reference_id == Exclusion.id,
        PlatformAction.action_type == ActionType.REMOVE_IP_EXCLUSION,
        PlatformAction.status.in_(OPEN_ACTION_STATUSES),
    )
    return (
        await db.execute(
            select(Exclusion)
            .where(
                Exclusion.google_campaign_id == campaign.id,
                Exclusion.status == ExclusionStatus.ACTIVE,
                ~being_removed,
            )
            .order_by(
                Exclusion.confidence.asc(),
                Exclusion.risk_score.asc(),
                Exclusion.last_fraud_at.asc().nulls_first(),
                Exclusion.created_at.asc(),
            )
            .limit(1)
        )
    ).scalar_one_or_none()


async def _overflow_queue(db: AsyncSession, campaign: GoogleCampaign, limit: int) -> list[Exclusion]:
    return list(
        (
            await db.execute(
                select(Exclusion)
                .where(
                    Exclusion.google_campaign_id == campaign.id,
                    Exclusion.status == ExclusionStatus.SKIPPED,
                    Exclusion.overflow.is_(True),
                )
                .order_by(
                    Exclusion.confidence.desc(),
                    Exclusion.risk_score.desc(),
                    Exclusion.last_fraud_at.desc().nulls_last(),
                )
                .limit(limit)
            )
        ).scalars()
    )


async def rebalance(db: AsyncSession, campaign: GoogleCampaign) -> list[PlatformAction]:
    """Fill free slots from the overflow queue, or evict once for a stronger candidate.

    Caller holds the campaign lock and commits. Returns the actions created.
    """
    actions: list[PlatformAction] = []
    await db.flush()
    capacity = await get_capacity(db, campaign)

    if capacity.available > 0:
        for exclusion in await _overflow_queue(db, campaign, capacity.available):
            exclusion.status = ExclusionStatus.PENDING
            exclusion.overflow = False
            exclusion.last_error = None
            action = new_action(exclusion, ActionType.ADD_IP_EXCLUSION)
            db.add(action)
            actions.append(action)
            audit_service.record(
                db,
                action=AuditAction.EXCLUSION_PROMOTED,
                result=AuditResult.PENDING,
                organization_id=exclusion.organization_id,
                resource_type="exclusion",
                resource_id=exclusion.id,
                details={"ip": exclusion.ip_address, "campaign_id": exclusion.campaign_id,
                         "risk": exclusion.risk_score, "confidence": exclusion.confidence},
            )
    elif settings.EXCLUSION_EVICTION_ENABLED and not await has_open_removal(db, campaign):
        best = await _overflow_queue(db, campaign, 1)
        victim = await pick_eviction_candidate(db, campaign)
        if best and victim is not None and priority(best[0]) > priority(victim):
            action = new_action(victim, ActionType.REMOVE_IP_EXCLUSION)
            db.add(action)
            actions.append(action)
            victim.last_error = (
                f"Being replaced by a higher-priority exclusion ({best[0].ip_address}) "
                f"because the campaign IP exclusion limit is reached."
            )
            audit_service.record(
                db,
                action=AuditAction.EXCLUSION_EVICTED,
                result=AuditResult.PENDING,
                organization_id=victim.organization_id,
                resource_type="exclusion",
                resource_id=victim.id,
                details={
                    "ip": victim.ip_address, "campaign_id": victim.campaign_id,
                    "risk": victim.risk_score, "confidence": victim.confidence,
                    "replaced_by_ip": best[0].ip_address,
                    "replaced_by_confidence": best[0].confidence,
                },
            )

    await sync_exclusion_count(db, campaign)
    return actions


async def rebalance_all(db: AsyncSession) -> list[uuid.UUID]:
    """Sweep: rebalance every campaign that has an overflow queue. Commits per campaign."""
    rows = (
        await db.execute(
            select(Exclusion.google_campaign_id, Exclusion.organization_id)
            .where(Exclusion.status == ExclusionStatus.SKIPPED, Exclusion.overflow.is_(True))
            .distinct()
        )
    ).all()
    action_ids: list[uuid.UUID] = []
    for campaign_row_id, organization_id in rows:
        locked = await lock_campaign(db, campaign_row_id, organization_id)
        if locked is None:
            await db.rollback()
            continue
        actions = await rebalance(db, locked[0])
        await db.commit()
        action_ids += [action.id for action in actions]
    return action_ids


async def expire_stale_exclusions(db: AsyncSession) -> list[uuid.UUID]:
    """Remove exclusions without new fraud for EXCLUSION_EXPIRY_DAYS (0 = disabled)."""
    if settings.EXCLUSION_EXPIRY_DAYS <= 0:
        return []
    cutoff = datetime.now(timezone.utc) - timedelta(days=settings.EXCLUSION_EXPIRY_DAYS)
    being_removed = exists().where(
        PlatformAction.reference_id == Exclusion.id,
        PlatformAction.action_type == ActionType.REMOVE_IP_EXCLUSION,
        PlatformAction.status.in_(OPEN_ACTION_STATUSES),
    )
    stale = (
        await db.execute(
            select(Exclusion).where(
                Exclusion.status == ExclusionStatus.ACTIVE,
                func.coalesce(Exclusion.last_fraud_at, Exclusion.submitted_at, Exclusion.created_at) < cutoff,
                ~being_removed,
            )
        )
    ).scalars().all()
    action_ids: list[uuid.UUID] = []
    for exclusion in stale:
        action = new_action(exclusion, ActionType.REMOVE_IP_EXCLUSION)
        db.add(action)
        action_ids.append(action.id)
        audit_service.record(
            db,
            action=AuditAction.EXCLUSION_EXPIRED,
            result=AuditResult.PENDING,
            organization_id=exclusion.organization_id,
            resource_type="exclusion",
            resource_id=exclusion.id,
            details={"ip": exclusion.ip_address, "campaign_id": exclusion.campaign_id,
                     "last_fraud_at": exclusion.last_fraud_at, "expiry_days": settings.EXCLUSION_EXPIRY_DAYS},
        )
    await db.commit()
    return action_ids


def capacity_warning(
    db: AsyncSession,
    campaign: GoogleCampaign,
    organization_id: uuid.UUID,
    before: Capacity,
    after_used: int,
) -> None:
    """Log + audit once when a campaign crosses 90% of its limit (spec §66 "Exclusion limit reached")."""
    threshold = WARNING_RATIO * before.limit
    if before.used < threshold <= after_used:
        logger.warning(
            "Campaign %s is at %d/%d IP exclusions (%.0f%%)",
            campaign.campaign_id, after_used, before.limit, 100 * after_used / before.limit,
        )
        audit_service.record(
            db,
            action=AuditAction.EXCLUSION_CAPACITY_WARNING,
            result=AuditResult.SUCCESS,
            organization_id=organization_id,
            resource_type="campaign",
            resource_id=campaign.id,
            details={"campaign_id": campaign.campaign_id, "campaign_name": campaign.name,
                     "used": after_used, "limit": before.limit},
        )

"""
Turn a FRAUD verdict into a Google Ads exclusion request (spec §37–§42).

`enqueue_exclusion_for_session` runs inside the tracking request's transaction:
it only writes rows (Exclusion + PlatformAction); the Google API call happens
later in the worker. It is idempotent per (organization, campaign, IP) — a
repeat fraud session refreshes the evidence instead of creating a second
exclusion (spec §41) — and respects the campaign's IP exclusion capacity
(spec §39, see exclusion_capacity.py).
"""
from __future__ import annotations

import ipaddress
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models import (
    ActionType,
    AuditResult,
    CampaignType,
    Exclusion,
    ExclusionStatus,
    FraudEvent,
    PlatformAction,
    Session,
    Verdict,
)
from app.services import audit_service
from app.services.audit_service import AuditAction
from app.services.exclusion_capacity import (
    SLOT_STATUSES,
    capacity_warning,
    get_capacity,
    lock_campaign,
    new_action,
    rebalance,
    sync_exclusion_count,
)

logger = logging.getLogger(__name__)

UNSUPPORTED_CAMPAIGN_TYPES = {CampaignType.PERFORMANCE_MAX, CampaignType.VIDEO}
COOLDOWN_STATUSES = (ExclusionStatus.FAILED, ExclusionStatus.SKIPPED)
# RFC 1918, carrier-grade NAT, IPv6 unique-local
NON_ROUTABLE_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7",
))


@dataclass
class EnqueueResult:
    outcome: str
    exclusion: Exclusion | None = None
    actions: list[PlatformAction] = field(default_factory=list)

    @property
    def action_ids(self) -> list[uuid.UUID]:
        return [action.id for action in self.actions]


def is_routable_ip(value) -> bool:
    """Spec §38 "Is IP valid?": ad clicks come from the public internet. A private, loopback or
    link-local address means a proxy in front of the API isn't trusted (TRUSTED_PROXY_CIDRS) —
    excluding it would block nobody and waste one of the campaign's limited slots."""
    try:
        ip = ipaddress.ip_address(str(value))
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return False
    return not any(ip.version == net.version and ip in net for net in NON_ROUTABLE_NETWORKS)


def is_actionable_fraud(session: Session) -> bool:
    """Only FRAUD (= BLOCK) is excluded automatically; FLAG waits for human review (task 017).
    The organization's thresholds were already applied when the verdict was decided (task 016)."""
    return session.verdict == Verdict.FRAUD and bool(session.ip_address)


def _valid_customer_id(value: str | None) -> str | None:
    digits = (value or "").replace("-", "").strip()
    return digits if digits.isdigit() and len(digits) == 10 else None


async def _reasons(db: AsyncSession, session: Session) -> tuple[str, list[str]]:
    rows = (
        await db.execute(
            select(FraudEvent.reason_code, FraudEvent.reason_text)
            .where(FraudEvent.session_id == session.id, FraudEvent.triggered.is_(True))
            .order_by(FraudEvent.score_contribution.desc(), FraudEvent.rule_name)
        )
    ).all()
    text = "; ".join(row.reason_text or row.reason_code for row in rows)
    return text or "High-risk fraudulent session detected by fraud engine.", [row.reason_code for row in rows]


async def enqueue_exclusion_for_session(db: AsyncSession, session: Session) -> EnqueueResult:
    """Create or refresh the exclusion for a FRAUD session. The caller commits."""
    if not is_actionable_fraud(session):
        return EnqueueResult("not_actionable")
    if not is_routable_ip(session.ip_address):
        logger.warning(
            "Not excluding non-routable IP %s (session %s): check TRUSTED_PROXY_CIDRS",
            session.ip_address, session.id,
        )
        return EnqueueResult("ip_not_routable")
    if session.google_campaign_id is None:
        return EnqueueResult("no_campaign")

    # Campaign row lock: serializes capacity decisions and duplicate inserts per campaign.
    locked = await lock_campaign(db, session.google_campaign_id, session.organization_id)
    if locked is None:
        return EnqueueResult("campaign_unavailable")
    campaign, connection = locked
    if not campaign.protection_enabled:
        return EnqueueResult("protection_disabled")
    if campaign.campaign_type in UNSUPPORTED_CAMPAIGN_TYPES:
        return EnqueueResult("unsupported_campaign")
    customer_id = _valid_customer_id(connection.customer_id)
    if customer_id is None:
        logger.warning(
            "Not enqueuing exclusion for %s on campaign %s: connection %s has no valid customer ID",
            session.ip_address, campaign.campaign_id, connection.id,
        )
        return EnqueueResult("no_customer")

    now = datetime.now(timezone.utc)
    ip = str(session.ip_address)
    reason_text, reason_codes = await _reasons(db, session)

    exclusion = (
        await db.execute(
            select(Exclusion)
            .where(
                Exclusion.organization_id == session.organization_id,
                Exclusion.campaign_id == campaign.campaign_id,
                Exclusion.ip_address == ip,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()

    if exclusion is not None:
        last_changed = exclusion.updated_at
        # Same IP again: update local evidence, no duplicate Google action (spec §41).
        exclusion.risk_score = max(int(exclusion.risk_score or 0), int(session.risk_score or 0))
        exclusion.confidence = max(int(exclusion.confidence or 0), int(session.confidence_score or 0))
        exclusion.last_fraud_at = now
        exclusion.reason = reason_text
        exclusion.google_campaign_id = campaign.id

        if exclusion.status in SLOT_STATUSES:
            return EnqueueResult("already_protected", exclusion)
        if exclusion.status == ExclusionStatus.SKIPPED and exclusion.overflow:
            actions = await rebalance(db, campaign)  # stronger evidence may now win a slot
            return EnqueueResult("overflow", exclusion, actions)
        cooldown = timedelta(seconds=settings.EXCLUSION_RETRY_COOLDOWN_SECONDS)
        if exclusion.status in COOLDOWN_STATUSES and last_changed and last_changed > now - cooldown:
            return EnqueueResult("cooldown", exclusion)
        # REMOVED (or a FAILED/SKIPPED one past its cooldown): exclude again, same row.
    else:
        exclusion = Exclusion(
            id=uuid.uuid4(),
            organization_id=session.organization_id,
            google_customer_id=customer_id,
            campaign_id=campaign.campaign_id,
            google_campaign_id=campaign.id,
            ip_address=ip,
            reason=reason_text,
            risk_score=session.risk_score,
            confidence=session.confidence_score,
            status=ExclusionStatus.SKIPPED,  # placed below
            last_fraud_at=now,
        )
        db.add(exclusion)

    exclusion.google_customer_id = customer_id
    details = {
        "ip": ip,
        "campaign_id": campaign.campaign_id,
        "campaign_name": campaign.name,
        "customer_id": customer_id,
        "risk": session.risk_score,
        "confidence": session.confidence_score,
        "reason_codes": reason_codes,
        "session_id": session.id,
    }

    await db.flush()
    capacity = await get_capacity(db, campaign)
    if capacity.available > 0:
        exclusion.status = ExclusionStatus.PENDING
        exclusion.overflow = False
        exclusion.last_error = None
        action = new_action(exclusion, ActionType.ADD_IP_EXCLUSION)
        db.add(action)
        audit_service.record(
            db, action=AuditAction.EXCLUSION_QUEUED, result=AuditResult.PENDING,
            organization_id=session.organization_id, resource_type="exclusion",
            resource_id=exclusion.id, details=details,
        )
        capacity_warning(db, campaign, session.organization_id, capacity, capacity.used + 1)
        await sync_exclusion_count(db, campaign)
        return EnqueueResult("queued", exclusion, [action])

    # Campaign full: wait in the overflow queue; rebalance may evict a weaker exclusion.
    exclusion.status = ExclusionStatus.SKIPPED
    exclusion.overflow = True
    exclusion.last_error = (
        f"Campaign IP exclusion limit reached ({capacity.used}/{capacity.limit}); "
        "queued until a slot frees up."
    )
    logger.warning(
        "Campaign %s is full (%d/%d): %s queued in overflow",
        campaign.campaign_id, capacity.used, capacity.limit, ip,
    )
    audit_service.record(
        db, action=AuditAction.EXCLUSION_LIMIT_REACHED, result=AuditResult.PENDING,
        organization_id=session.organization_id, resource_type="exclusion",
        resource_id=exclusion.id, details={**details, "used": capacity.used, "limit": capacity.limit},
    )
    actions = await rebalance(db, campaign)
    return EnqueueResult("overflow", exclusion, actions)

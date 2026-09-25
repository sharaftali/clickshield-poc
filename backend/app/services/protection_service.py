from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    CampaignType,
    Exclusion,
    FraudEvent,
    GoogleCampaign,
    GoogleConnection,
    PlatformAction,
    Platform,
    Session,
    ActionType,
    ActionStatus,
    ExclusionStatus,
    Verdict,
)


async def enqueue_high_risk_exclusions(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID | str | None = None,
    min_risk_score: int = 80,
    min_confidence: int = 80,
) -> list[Exclusion]:
    """Create exclusion records for any fraudulent sessions that are eligible for action."""
    filters = [
        Session.verdict == Verdict.FRAUD,
        Session.risk_score >= min_risk_score,
        Session.confidence_score >= min_confidence,
        Session.ip_address.is_not(None),
        Session.google_campaign_id.is_not(None),
    ]
    if organization_id is not None:
        filters.append(Session.organization_id == organization_id)

    result = await db.execute(
        select(Session)
        .where(*filters)
        .order_by(Session.created_at.desc())
    )
    sessions = result.scalars().all()

    created: list[Exclusion] = []
    seen: set[tuple[uuid.UUID, str, str]] = set()

    for session in sessions:
        if not session.google_campaign_id or not session.ip_address:
            continue

        campaign_result = await db.execute(
            select(GoogleCampaign).where(GoogleCampaign.id == session.google_campaign_id)
        )
        campaign = campaign_result.scalar_one_or_none()
        if campaign is None:
            continue
        if not campaign.protection_enabled:
            continue
        if campaign.campaign_type in {CampaignType.PERFORMANCE_MAX, CampaignType.VIDEO}:
            continue

        customer_id = ""
        if campaign.connection_id:
            connection_result = await db.execute(
                select(GoogleConnection).where(GoogleConnection.id == campaign.connection_id)
            )
            connection = connection_result.scalar_one_or_none()
            if connection is not None:
                customer_id = connection.customer_id

        ip_key = (session.organization_id, campaign.campaign_id, str(session.ip_address))
        if ip_key in seen:
            continue
        seen.add(ip_key)

        existing = await db.execute(
            select(Exclusion).where(
                Exclusion.organization_id == session.organization_id,
                Exclusion.campaign_id == campaign.campaign_id,
                Exclusion.ip_address == str(session.ip_address),
            )
        )
        if existing.scalar_one_or_none() is not None:
            continue

        fraud_result = await db.execute(
            select(FraudEvent.reason_text, FraudEvent.reason_code)
            .where(FraudEvent.session_id == session.id)
            .order_by(FraudEvent.created_at.desc())
        )
        reasons = fraud_result.all()
        reason_text = "; ".join(
            item.reason_text or item.reason_code for item in reasons if item.reason_text or item.reason_code
        )
        if not reason_text:
            reason_text = "High-risk fraudulent session detected by fraud engine."

        exclusion = Exclusion(
            organization_id=session.organization_id,
            google_customer_id=customer_id,
            campaign_id=campaign.campaign_id,
            google_campaign_id=campaign.id,
            ip_address=str(session.ip_address),
            reason=reason_text,
            risk_score=session.risk_score,
            confidence=session.confidence_score,
            status=ExclusionStatus.PENDING,
        )
        db.add(exclusion)
        await db.flush()

        action = PlatformAction(
            organization_id=session.organization_id,
            platform=Platform.GOOGLE,
            action_type=ActionType.ADD_IP_EXCLUSION,
            reference_id=exclusion.id,
            status=ActionStatus.PENDING,
            scheduled_at=datetime.now(timezone.utc) + timedelta(seconds=5),
            attempts=0,
            max_attempts=5,
        )
        db.add(action)
        created.append(exclusion)

    await db.commit()
    return created

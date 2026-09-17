from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    Event,
    EventType,
    Session,
    Verdict,
    Visitor,
    Website,
)
from app.schemas.tracking import TrackingBatchIn, TrackingResponse
from app.services.fraud_engine import FraudEngine
from app.services.ip_intel import IPIntelService

logger = logging.getLogger(__name__)


class TrackingService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.ip_intel = IPIntelService()
        self.fraud_engine = FraudEngine()

    async def ingest_batch(
        self,
        payload: TrackingBatchIn,
        client_ip: str,
        request: Request,
    ) -> TrackingResponse:
        first = payload.events[0]

        website = await self._get_website(first.site_token)
        logger.info(
            "Ingesting %d events for site=%s visitor=%s session=%s ip=%s",
            len(payload.events),
            website.domain,
            first.visitor_token,
            first.session_token,
            client_ip,
        )

        visitor = await self._get_or_create_visitor(
            website=website,
            visitor_token=first.visitor_token,
            client_ip=client_ip,
        )

        session = await self._get_or_create_session(
            website=website,
            visitor=visitor,
            first_event=first,
            client_ip=client_ip,
            request=request,
        )

        for ev in payload.events:
            event = Event(
                session_id=session.id,
                organization_id=website.organization_id,
                event_type=EventType(ev.event_type),
                page_url=ev.page_url,
                timestamp=ev.timestamp,
                payload=ev.payload,
            )
            self.db.add(event)

        self._update_session_counters(session, payload)

        await self.fraud_engine.score(self.db, session)

        await self.db.commit()

        logger.info(
            "Session %s scored: risk=%d confidence=%d verdict=%s",
            session.session_token,
            session.risk_score,
            session.confidence_score,
            session.verdict.value,
        )

        return TrackingResponse(
            status="ok",
            session_id=session.id,
            risk_score=session.risk_score,
            confidence_score=session.confidence_score,
            verdict=session.verdict.value,
        )

    async def _get_website(self, site_token: str) -> Website:
        result = await self.db.execute(
            select(Website).where(Website.tracking_token == site_token)
        )
        website = result.scalar_one_or_none()
        if not website:
            raise ValueError("Invalid site token")
        if not website.is_verified:
            raise ValueError("Website not verified")
        return website

    async def _get_or_create_visitor(
        self,
        website: Website,
        visitor_token: str,
        client_ip: str,
    ) -> Visitor:
        result = await self.db.execute(
            select(Visitor)
            .where(
                Visitor.website_id == website.id,
                Visitor.visitor_token == visitor_token,
            )
            .order_by(Visitor.created_at.asc())
            .limit(1)
        )
        visitor = result.scalar_one_or_none()
        now = datetime.now(timezone.utc)

        if visitor:
            visitor.last_seen_at = now
            visitor.total_sessions += 1
            visitor.ip_address = client_ip
            return visitor

        visitor = Visitor(
            organization_id=website.organization_id,
            website_id=website.id,
            visitor_token=visitor_token,
            ip_address=client_ip,
            first_seen_at=now,
            last_seen_at=now,
            total_sessions=1,
        )
        self.db.add(visitor)

        try:
            await self.db.flush()
            return visitor
        except IntegrityError:
            await self.db.rollback()
            result = await self.db.execute(
                select(Visitor)
                .where(
                    Visitor.website_id == website.id,
                    Visitor.visitor_token == visitor_token,
                )
                .order_by(Visitor.created_at.asc())
                .limit(1)
            )
            existing = result.scalar_one_or_none()
            if not existing:
                raise
            existing.last_seen_at = now
            existing.total_sessions += 1
            existing.ip_address = client_ip
            return existing

    async def _get_or_create_session(
        self,
        website: Website,
        visitor: Visitor,
        first_event,
        client_ip: str,
        request: Request,
    ) -> Session:
        result = await self.db.execute(
            select(Session)
            .where(Session.session_token == first_event.session_token)
            .order_by(Session.created_at.asc())
            .limit(1)
        )
        session = result.scalar_one_or_none()
        if session:
            return session

        ip_data = await self.ip_intel.lookup(client_ip)

        session = Session(
            organization_id=website.organization_id,
            website_id=website.id,
            visitor_id=visitor.id,
            session_token=first_event.session_token,
            gclid=first_event.gclid,
            utm_source=first_event.utm_source,
            utm_medium=first_event.utm_medium,
            utm_campaign=first_event.utm_campaign,
            utm_term=first_event.utm_term,
            utm_content=first_event.utm_content,
            referrer=first_event.referrer,
            landing_page=first_event.page_url,
            ip_address=client_ip,
            country=ip_data.get("country"),
            region=ip_data.get("region"),
            city=ip_data.get("city"),
            asn=ip_data.get("asn"),
            isp=ip_data.get("isp"),
            is_vpn=ip_data.get("is_vpn", False),
            is_proxy=ip_data.get("is_proxy", False),
            is_tor=ip_data.get("is_tor", False),
            is_datacenter=ip_data.get("is_datacenter", False),
            user_agent=request.headers.get("user-agent"),
            system_verdict=Verdict.SAFE,
            verdict=Verdict.SAFE,
        )
        self.db.add(session)

        try:
            await self.db.flush()
            return session
        except IntegrityError:
            await self.db.rollback()
            result = await self.db.execute(
                select(Session)
                .where(Session.session_token == first_event.session_token)
                .order_by(Session.created_at.asc())
                .limit(1)
            )
            existing = result.scalar_one_or_none()
            if not existing:
                raise
            return existing

    def _update_session_counters(
        self, session: Session, payload: TrackingBatchIn
    ) -> None:
        for ev in payload.events:
            if ev.event_type == EventType.PAGE_VIEW.value:
                session.page_count = (session.page_count or 0) + 1
            elif ev.event_type == EventType.CLICK.value:
                session.click_count = (session.click_count or 0) + 1
            elif ev.event_type == EventType.SCROLL.value:
                if ev.payload and "depth" in ev.payload:
                    session.scroll_depth = max(
                        session.scroll_depth or 0.0,
                        float(ev.payload["depth"]),
                    )

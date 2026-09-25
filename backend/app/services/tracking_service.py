from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    CampaignStatus,
    Event,
    EventType,
    GoogleCampaign,
    GoogleConnection,
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
    MAX_BATCH_SIZE = 50
    MAX_EVENT_AGE_SECONDS = 3600

    def __init__(self, db: AsyncSession):
        self.db = db
        self.ip_intel = IPIntelService()
        self.fraud_engine = FraudEngine()

    @staticmethod
    def _normalize_campaign_value(value: str | None) -> str:
        return (value or "").strip().casefold()

    @staticmethod
    def _detect_device(user_agent: str, payload: dict | None) -> str:
        touch_points = int((payload or {}).get("touch_points") or 0)
        ua = user_agent.casefold()
        if "ipad" in ua or "tablet" in ua:
            return "tablet"
        if "mobile" in ua or "android" in ua or "iphone" in ua or touch_points > 1:
            return "mobile"
        return "desktop"

    @staticmethod
    def _detect_browser(user_agent: str) -> str | None:
        ua = user_agent.casefold()
        if "edg/" in ua:
            return "Edge"
        if "chrome/" in ua and "edg/" not in ua:
            return "Chrome"
        if "safari/" in ua and "chrome/" not in ua:
            return "Safari"
        if "firefox/" in ua:
            return "Firefox"
        if "opr/" in ua or "opera/" in ua:
            return "Opera"
        if "msie" in ua or "trident/" in ua:
            return "Internet Explorer"
        return None

    @staticmethod
    def _detect_os(user_agent: str) -> str | None:
        ua = user_agent.casefold()
        if "windows" in ua:
            return "Windows"
        if "mac os x" in ua or "macintosh" in ua:
            return "macOS"
        if "android" in ua:
            return "Android"
        if "iphone" in ua or "ipad" in ua or "ios" in ua:
            return "iOS"
        if "linux" in ua:
            return "Linux"
        return None

    def _build_extra_signals(self, first_event, is_google_ads_traffic: bool) -> dict:
        payload = dict(first_event.payload or {})
        payload["source_platform"] = "google_ads" if is_google_ads_traffic else "other"
        payload["campaign_id"] = first_event.campaign_id
        payload["gclid_present"] = bool(first_event.gclid)
        return payload

    def _is_google_ads_traffic(self, first_event) -> bool:
        if first_event.gclid:
            return True
        if first_event.campaign_id:
            return True
        return "google" in (first_event.utm_source or "").casefold()

    def _validate_payload(self, payload: TrackingBatchIn) -> None:
        if not payload.events:
            raise ValueError("At least one tracking event is required.")
        if len(payload.events) > self.MAX_BATCH_SIZE:
            raise ValueError(
                f"Tracking batches cannot exceed {self.MAX_BATCH_SIZE} events."
            )

        valid_event_types = {event_type.value for event_type in EventType}
        now = datetime.now(timezone.utc)

        for event in payload.events:
            if not event.site_token or not event.visitor_token or not event.session_token:
                raise ValueError("site_token, visitor_token and session_token are required.")
            if event.event_type not in valid_event_types:
                raise ValueError(f"Unsupported event type: {event.event_type}")

            event_time = event.timestamp
            if event_time.tzinfo is None:
                event_time = event_time.replace(tzinfo=timezone.utc)
            if (now - event_time).total_seconds() > self.MAX_EVENT_AGE_SECONDS:
                raise ValueError("Tracking event timestamp is too old.")
            if (event_time - now).total_seconds() > 300:
                raise ValueError("Tracking event timestamp cannot be in the future.")

    async def ingest_batch(
        self,
        payload: TrackingBatchIn,
        client_ip: str,
        request: Request,
    ) -> TrackingResponse:
        self._validate_payload(payload)
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

        visitor, visitor_is_new = await self._get_or_create_visitor(
            website=website,
            visitor_token=first.visitor_token,
            client_ip=client_ip,
        )

        session, session_is_new = await self._get_or_create_session(
            website=website,
            visitor=visitor,
            first_event=first,
            client_ip=client_ip,
            request=request,
        )

        if session_is_new:
            visitor.total_sessions = (visitor.total_sessions or 0) + 1

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

        previous_verdict = session.verdict
        await self.fraud_engine.score(
            self.db,
            session,
            is_new_session=session_is_new,
            previous_verdict=previous_verdict,
        )

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
    ) -> tuple[Visitor, bool]:
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
            visitor.ip_address = client_ip
            return visitor, False

        visitor = Visitor(
            organization_id=website.organization_id,
            website_id=website.id,
            visitor_token=visitor_token,
            ip_address=client_ip,
            first_seen_at=now,
            last_seen_at=now,
            total_sessions=0,
        )
        self.db.add(visitor)

        try:
            await self.db.flush()
            return visitor, True
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
            existing.ip_address = client_ip
            return existing, False

    async def _get_or_create_session(
        self,
        website: Website,
        visitor: Visitor,
        first_event,
        client_ip: str,
        request: Request,
    ) -> tuple[Session, bool]:
        result = await self.db.execute(
            select(Session)
            .where(Session.session_token == first_event.session_token)
            .order_by(Session.created_at.asc())
            .limit(1)
        )
        session = result.scalar_one_or_none()
        if session:
            if session.google_campaign_id is None:
                matched_campaign = await self._resolve_google_campaign(
                    organization_id=website.organization_id,
                    first_event=first_event,
                )
                if matched_campaign is not None:
                    session.google_campaign_id = matched_campaign.id
            return session, False

        ip_data = await self.ip_intel.lookup(client_ip)
        matched_campaign = await self._resolve_google_campaign(
            organization_id=website.organization_id,
            first_event=first_event,
        )
        user_agent = request.headers.get("user-agent") or ""
        is_google_ads_traffic = self._is_google_ads_traffic(first_event)
        language = first_event.language or request.headers.get("accept-language", "").split(",")[0].strip() or None

        session = Session(
            organization_id=website.organization_id,
            website_id=website.id,
            visitor_id=visitor.id,
            session_token=first_event.session_token,
            gclid=first_event.gclid,
            google_campaign_id=matched_campaign.id if matched_campaign is not None else None,
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
            device=self._detect_device(user_agent, first_event.payload),
            browser=self._detect_browser(user_agent),
            os=self._detect_os(user_agent),
            language=language,
            timezone=first_event.timezone,
            user_agent=user_agent or None,
            extra_signals=self._build_extra_signals(first_event, is_google_ads_traffic),
            system_verdict=Verdict.SAFE,
            verdict=Verdict.SAFE,
        )
        self.db.add(session)

        try:
            await self.db.flush()
            return session, True
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
            return existing, False

    async def _resolve_google_campaign(
        self,
        *,
        organization_id,
        first_event,
    ) -> GoogleCampaign | None:
        if not self._is_google_ads_traffic(first_event):
            return None

        result = await self.db.execute(
            select(GoogleCampaign)
            .join(GoogleConnection, GoogleConnection.id == GoogleCampaign.connection_id)
            .where(
                GoogleConnection.organization_id == organization_id,
                GoogleConnection.is_active.is_(True),
                GoogleCampaign.status != CampaignStatus.REMOVED,
            )
            .order_by(GoogleConnection.created_at.desc(), GoogleCampaign.name.asc())
        )
        campaigns = result.scalars().all()
        if not campaigns:
            return None

        explicit_campaign_id = self._normalize_campaign_value(first_event.campaign_id)
        if explicit_campaign_id:
            for campaign in campaigns:
                if self._normalize_campaign_value(campaign.campaign_id) == explicit_campaign_id:
                    return campaign

        utm_campaign = self._normalize_campaign_value(first_event.utm_campaign)
        if utm_campaign:
            for campaign in campaigns:
                if self._normalize_campaign_value(campaign.campaign_id) == utm_campaign:
                    return campaign
                if self._normalize_campaign_value(campaign.name) == utm_campaign:
                    return campaign

        return None

    def _update_session_counters(
        self, session: Session, payload: TrackingBatchIn
    ) -> None:
        event_timestamps: list[datetime] = []
        click_timestamps: list[datetime] = []

        for ev in payload.events:
            event_timestamp = ev.timestamp
            if event_timestamp.tzinfo is None:
                event_timestamp = event_timestamp.replace(tzinfo=timezone.utc)
            event_timestamps.append(event_timestamp)

            if ev.event_type == EventType.PAGE_VIEW.value:
                session.page_count = (session.page_count or 0) + 1
            elif ev.event_type == EventType.CLICK.value:
                session.click_count = (session.click_count or 0) + 1
                click_timestamps.append(event_timestamp)
            elif ev.event_type == EventType.SCROLL.value:
                if ev.payload and "depth" in ev.payload:
                    session.scroll_depth = max(
                        session.scroll_depth or 0.0,
                        float(ev.payload["depth"]),
                    )

        if event_timestamps:
            start = min(event_timestamps)
            end = max(event_timestamps)
            session.session_duration_seconds = max(
                session.session_duration_seconds or 0.0,
                (end - start).total_seconds(),
            )

        if click_timestamps:
            newest_click = max(click_timestamps)
            windows = {
                10: 10,
                30: 30,
                60: 60,
                300: 300,
                3600: 3600,
                86400: 86400,
            }
            for seconds in windows:
                bucket = sum(
                    1
                    for ts in click_timestamps
                    if (newest_click - ts).total_seconds() <= seconds
                )
                if seconds == 10:
                    session.clicks_10_seconds = bucket
                elif seconds == 30:
                    session.clicks_30_seconds = bucket
                elif seconds == 60:
                    session.clicks_60_seconds = bucket
                elif seconds == 300:
                    session.clicks_5_minutes = bucket
                elif seconds == 3600:
                    session.clicks_1_hour = bucket
                elif seconds == 86400:
                    session.clicks_24_hours = bucket

        session.interaction_count = (session.interaction_count or 0) + len(payload.events)

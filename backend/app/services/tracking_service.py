from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from fastapi import Request
from sqlalchemy import String, cast, distinct, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    AuditResult,
    CampaignStatus,
    Event,
    EventType,
    GoogleCampaign,
    GoogleConnection,
    Organization,
    Session,
    Verdict,
    Visitor,
    Website,
)
from app.core.config import settings
from app.core.queue import enqueue_actions
from app.core.rate_limit import recent_rate_limited
from app.core.redis import get_redis
from app.services import alert_service, audit_service
from app.services.audit_service import AuditAction
from app.services.website_service import host_allowed, host_of
from app.schemas.tracking import TrackingBatchIn, TrackingResponse
from app.services.features import apply_event_interval_features, apply_landing_features, device_key
from app.services.fraud_engine import FraudEngine
from app.services.ip_intel import IPIntelService
from app.services.protection_policy import get_policy
from app.services.protection_service import enqueue_exclusion_for_session

logger = logging.getLogger(__name__)

# Real interactions a bot rarely fakes; they exempt a session from the bounce /
# low-engagement rules (task 024).
HUMAN_ACTION_EVENT_TYPES = frozenset(
    t.value for t in (EventType.FORM_START, EventType.FORM_SUBMIT, EventType.PHONE_CLICK, EventType.CONVERSION)
)
LAST_EVENT_WRITE_INTERVAL = timedelta(seconds=60)


class TrackingRejected(ValueError):
    """A request the website doesn't allow (wrong origin, unverified)."""

    def __init__(self, message: str, status_code: int = 403) -> None:
        super().__init__(message)
        self.status_code = status_code


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
        if first_event.gclid or first_event.gbraid or first_event.wbraid:
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
        origin_host = self._origin_host(request, first)
        await self._check_origin(website, origin_host)
        if not website.is_verified:
            return await self._verify_by_first_event(website, origin_host, request)
        self._touch_website(website)
        # The organization's protection mode decides what a score means (task 016).
        policy = get_policy(await self.db.get(Organization, website.organization_id))
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
        await self._update_client_signals(session, origin_host, client_ip)
        await self._update_session_duration(session)
        await apply_event_interval_features(self.db, session)

        # Velocity, repeat counts and click timing are fixed at landing time;
        # later batches of the session don't recount them.
        if session_is_new and self._is_paid_landing(first, payload):
            session.ad_landing_at = datetime.now(timezone.utc)
            await self._apply_ad_click_velocity(session)
            await apply_landing_features(self.db, session)

        previous_verdict = session.verdict
        await self.fraud_engine.score(
            self.db,
            session,
            is_new_session=session_is_new,
            previous_verdict=previous_verdict,
            policy=policy,
        )

        # Automatic protection (spec §42): the session just became FRAUD → queue the
        # exclusion in this transaction; the worker calls Google after commit.
        protection_action_ids = []
        if (
            settings.AUTO_PROTECTION_ENABLED
            and policy.auto_exclude
            and session.verdict == Verdict.FRAUD
            and previous_verdict != Verdict.FRAUD
        ):
            protection = await enqueue_exclusion_for_session(self.db, session)
            protection_action_ids = protection.action_ids
            logger.info("Protection for session %s: %s", session.session_token, protection.outcome)

        await self.db.commit()
        await enqueue_actions(protection_action_ids)

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
            select(Website).where(Website.tracking_token == site_token, Website.is_active.is_(True))
        )
        website = result.scalar_one_or_none()
        if not website:
            raise ValueError("Invalid site token")
        return website

    @staticmethod
    def _origin_host(request: Request, first_event) -> str | None:
        # Browsers send Origin on cross-origin fetch / sendBeacon; Referer is the fallback.
        return host_of(request.headers.get("origin")) or host_of(request.headers.get("referer"))

    async def _check_origin(self, website: Website, origin_host: str | None) -> None:
        """Task 023: a token copied into another site's HTML must not work there."""
        if origin_host is None or host_allowed(website, origin_host):
            return
        if not (settings.TRACKING_ENFORCE_ORIGIN and website.enforce_origin):
            return
        await self._count_origin_mismatch(website, origin_host)
        raise TrackingRejected(f"Origin {origin_host} is not allowed for this website.")

    async def _count_origin_mismatch(self, website: Website, origin_host: str) -> None:
        now = datetime.now(timezone.utc)
        key = f"origin_mismatch:{website.id}:{now:%Y%m%d%H}"
        try:
            redis = get_redis()
            count = int(await redis.incr(key))
            await redis.expire(key, 7200)
        except Exception:
            return
        if count == settings.WEBSITE_ORIGIN_MISMATCH_ALERT_COUNT:
            await alert_service.raise_alert(
                self.db, organization_id=website.organization_id,
                type=alert_service.AlertType.WEBSITE_DISCONNECTED, severity="warning",
                dedupe_key=alert_service.website_disconnected_key(website.id),
                title=f"Tracking token of {website.domain} used from another site",
                message=(f"{count} tracking batches this hour came from {origin_host}, which is not one of "
                         f"{website.domain}'s domains. They were rejected. Add the domain to the website if it's "
                         "yours, or rotate the token."),
                resource_type="website", resource_id=str(website.id), details={"origin": origin_host},
            )
            await self.db.commit()

    async def _verify_by_first_event(self, website: Website, origin_host: str | None, request: Request) -> TrackingResponse:
        """Verification mode (task 023): the first event from the website's own origin verifies it.
        Nothing is stored or scored before that."""
        if not host_allowed(website, origin_host):
            raise TrackingRejected(
                "Website not verified: install the snippet on the website, or verify it from the dashboard."
            )
        now = datetime.now(timezone.utc)
        website.is_verified = True
        website.verified_at = now
        website.verification_method = "first_event"
        website.last_event_at = now
        audit_service.record(
            self.db, action=AuditAction.WEBSITE_VERIFIED, result=AuditResult.SUCCESS,
            organization_id=website.organization_id, resource_type="website", resource_id=website.id,
            request=request, details={"domain": website.domain, "method": "first_event", "origin": origin_host},
        )
        await self.db.commit()
        logger.info("Website %s verified by its first event from %s", website.domain, origin_host)
        return TrackingResponse(status="verified")

    @staticmethod
    def _touch_website(website: Website) -> None:
        # At most one write a minute: busy sites must not contend on their website row.
        now = datetime.now(timezone.utc)
        if website.last_event_at is None or website.last_event_at < now - LAST_EVENT_WRITE_INTERVAL:
            website.last_event_at = now

    async def _update_client_signals(self, session: Session, origin_host: str | None, client_ip: str) -> None:
        """Non-browser and rate-limited clients (tasks 023, 031) for AUTOMATION_SIGNAL."""
        signals = dict(session.extra_signals or {})
        if origin_host is None:
            signals["origin_missing"] = True
        limited = await recent_rate_limited(client_ip)
        if limited:
            signals["rate_limited"] = max(int(signals.get("rate_limited") or 0), limited)
        if signals != (session.extra_signals or {}):
            session.extra_signals = signals

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
        try:
            async with self.db.begin_nested():
                self.db.add(visitor)
                await self.db.flush()
            return visitor, True
        except IntegrityError:
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
        session = await self._find_session(website, first_event.session_token)
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
        browser = self._detect_browser(user_agent)
        operating_system = self._detect_os(user_agent)
        device = self._detect_device(user_agent, first_event.payload)
        client = first_event.payload or {}

        session = Session(
            organization_id=website.organization_id,
            website_id=website.id,
            visitor_id=visitor.id,
            session_token=first_event.session_token,
            gclid=first_event.gclid,
            gbraid=first_event.gbraid,
            wbraid=first_event.wbraid,
            ad_group_id=first_event.adgroup_id,
            keyword=first_event.keyword,
            match_type=first_event.matchtype,
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
            device=device,
            browser=browser,
            os=operating_system,
            language=language,
            timezone=first_event.timezone,
            user_agent=user_agent or None,
            device_key=device_key(
                website.organization_id,
                browser=browser,
                os=operating_system,
                device=device,
                screen_width=client.get("screen_width"),
                screen_height=client.get("screen_height"),
                timezone_name=first_event.timezone,
                language=language,
            ),
            extra_signals=self._build_extra_signals(first_event, is_google_ads_traffic),
            system_verdict=Verdict.SAFE,
            verdict=Verdict.SAFE,
        )
        try:
            # Savepoint: losing a race on uq_sessions_website_token must not roll
            # back the visitor created earlier in this transaction.
            async with self.db.begin_nested():
                self.db.add(session)
                await self.db.flush()
            return session, True
        except IntegrityError:
            existing = await self._find_session(website, first_event.session_token)
            if not existing:
                raise
            return existing, False

    async def _find_session(self, website: Website, session_token: str) -> Session | None:
        # Session tokens come from the browser: always scope them to the website (spec §58).
        result = await self.db.execute(
            select(Session).where(
                Session.website_id == website.id,
                Session.session_token == session_token,
            )
        )
        return result.scalar_one_or_none()

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

    def _is_paid_landing(self, first_event, payload: TrackingBatchIn) -> bool:
        return self._is_google_ads_traffic(first_event) or any(
            ev.event_type == EventType.AD_LANDING.value for ev in payload.events
        )

    async def _apply_ad_click_velocity(self, session: Session) -> None:
        """Count paid ad landings by the same IP and the same visitor across sessions (spec §16)."""
        await self.db.flush()  # autoflush is off; the current landing must be counted
        counts_by_key: dict[str, dict[str, int]] = {}
        if session.ip_address:
            counts_by_key["ip"] = await self._ad_click_counts(session, Session.ip_address, session.ip_address)
        if session.visitor_id:
            counts_by_key["visitor"] = await self._ad_click_counts(session, Session.visitor_id, session.visitor_id)

        for name, value in merge_velocity_counts(counts_by_key).items():
            setattr(session, name, value)
        session.extra_signals = {**(session.extra_signals or {}), "ad_click_velocity": counts_by_key}

    async def _ad_click_counts(self, session: Session, key_column, key_value) -> dict[str, int]:
        query = build_ad_click_velocity_query(
            organization_id=session.organization_id,
            key_column=key_column,
            key_value=key_value,
            landed_at=session.ad_landing_at,
        )
        row = (await self.db.execute(query)).one()
        return {name: int(row._mapping[name] or 0) for name, _ in VELOCITY_WINDOWS}

    async def _update_session_duration(self, session: Session) -> None:
        """Duration spans all of the session's events, not just the current batch."""
        await self.db.flush()
        first_at, last_at = (
            await self.db.execute(
                select(func.min(Event.timestamp), func.max(Event.timestamp)).where(
                    Event.session_id == session.id
                )
            )
        ).one()
        if first_at is not None and last_at is not None:
            session.session_duration_seconds = max(0.0, (last_at - first_at).total_seconds())

    def _update_session_counters(
        self, session: Session, payload: TrackingBatchIn
    ) -> None:
        human_actions = 0
        for ev in payload.events:
            if ev.event_type in INTERACTION_EVENT_TYPES:
                session.interaction_count = (session.interaction_count or 0) + 1
            if ev.event_type in HUMAN_ACTION_EVENT_TYPES:
                human_actions += 1

            if ev.event_type == EventType.PAGE_VIEW.value:
                session.page_count = (session.page_count or 0) + 1
            elif ev.event_type == EventType.CLICK.value:
                # On-page clicks only feed engagement, never ad-click velocity.
                session.click_count = (session.click_count or 0) + 1
            elif ev.event_type == EventType.SCROLL.value:
                if ev.payload and "depth" in ev.payload:
                    session.scroll_depth = max(
                        session.scroll_depth or 0.0,
                        float(ev.payload["depth"]),
                    )
        if human_actions:
            signals = dict(session.extra_signals or {})
            signals["human_actions"] = int(signals.get("human_actions") or 0) + human_actions
            session.extra_signals = signals


# (column name, window seconds) — spec §16
VELOCITY_WINDOWS: tuple[tuple[str, int], ...] = (
    ("clicks_10_seconds", 10),
    ("clicks_30_seconds", 30),
    ("clicks_60_seconds", 60),
    ("clicks_5_minutes", 300),
    ("clicks_1_hour", 3600),
    ("clicks_24_hours", 86400),
)

INTERACTION_EVENT_TYPES = frozenset(
    event_type.value
    for event_type in (
        EventType.CLICK,
        EventType.SCROLL,
        EventType.FORM_START,
        EventType.FORM_SUBMIT,
        EventType.PHONE_CLICK,
        EventType.OUTBOUND_CLICK,
        EventType.CONVERSION,
    )
)


def build_ad_click_velocity_query(*, organization_id, key_column, key_value, landed_at: datetime):
    """One row with a count per window of distinct paid ad clicks for one key.

    Repeat landings with the same gclid are reloads of one ad click, so each
    gclid counts once; landings without a gclid count per session.
    """
    click_key = func.coalesce(Session.gclid, cast(Session.id, String))
    longest = max(seconds for _, seconds in VELOCITY_WINDOWS)
    columns = [
        func.count(distinct(click_key))
        .filter(Session.ad_landing_at > landed_at - timedelta(seconds=seconds))
        .label(name)
        for name, seconds in VELOCITY_WINDOWS
    ]
    return select(*columns).where(
        Session.organization_id == organization_id,
        key_column == key_value,
        Session.ad_landing_at.is_not(None),
        Session.ad_landing_at > landed_at - timedelta(seconds=longest),
        Session.ad_landing_at <= landed_at,
    )


def merge_velocity_counts(counts_by_key: dict[str, dict[str, int]]) -> dict[str, int]:
    """Per window, the highest count across keys (IP, visitor). At least 1: the current landing."""
    return {
        name: max([1, *(counts.get(name, 0) for counts in counts_by_key.values())])
        for name, _ in VELOCITY_WINDOWS
    }

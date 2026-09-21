# Task 02 — Tracking Script and Visitor/Session Ingestion

## Goal
Capture ad-click traffic from the website tracking script and persist raw session data in a structured way for fraud analysis.

## Current status in repo
Implemented:
- FastAPI endpoint at `/api/v1/track` accepts batched tracking payloads.
- Visitor and session creation logic is present.
- Event ingestion captures page views, clicks, scrolls, and related metadata.
- IP address is extracted from `X-Forwarded-For` or request client IP.

Still missing:
- Real JavaScript tracking snippet for end-user websites.
- Browser-side event collection for click, scroll, and metadata enrichment.
- Robust replay protection and anti-spam rate limiting.
- Session update logic for duration, velocity metrics, and richer behavioral counters.
- Testing against live website traffic.

## Deliverables
- Browser tracking script hosted or served from the Click Shield domain.
- Event payload schema for click, page view, scroll, conversion, and custom metadata.
- API ingestion pipeline that stores events and aggregates session metrics.
- Rate limiting and validation for abuse prevention.

## Acceptance criteria
- A page view or ad click from a website sends data to the backend successfully.
- Session record is created with attribution fields (GCLID, UTM, referrer, landing page).
- Visitor identity and session counters are updated correctly.
- Raw event audit trail is preserved for later fraud investigation.

## Dependencies
- Task 01

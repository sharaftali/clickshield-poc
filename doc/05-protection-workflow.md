# Task 05 — Protection Workflow and Automated Exclusion Actions

## Goal
Convert fraud verdicts into actual protective actions on Google Ads, using an idempotent action queue and exclusion management framework.

## Current status in repo
Partially modeled:
- Exclusion and platform action models exist.
- The database supports pending/submitted/removed exclusion states.
- Multi-platform action queue design is in place.

Not implemented:
- Worker to process pending actions.
- Google Ads API calls to add or remove IP exclusions.
- Campaign limits and exclusion capacity tracking.
- Deduplication and retry logic in production flow.
- Action audit trail and failure reporting.

## Deliverables
- Exclusion generation for IPs classified as high-risk.
- Queue-based action worker with retries.
- Google Ads API integration for adding/removing exclusions.
- Manual override and re-evaluation workflow for false positives.

## Acceptance criteria
- High-confidence fraudulent sessions are accepted into the exclusion pipeline.
- Same IP is not submitted twice for the same campaign.
- Exclusion status changes are auditable.
- Failed API requests are retried with backoff and clear logging.

## Dependencies
- Task 03
- Task 04

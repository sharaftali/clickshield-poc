# Task 04 — Google Ads OAuth and Account Connection

## Goal
Integrate Google Ads securely so the platform can read connected accounts and apply protection actions for suspicious traffic.

## Current status in repo
Partially modeled:
- `GoogleConnection` and `GoogleCampaign` models exist.
- OAuth settings and encrypted token storage are defined in config and model layer.
- Data model includes customer ID, login customer ID, and campaign metadata.

Not implemented:
- OAuth authorization flow endpoint and callback handling.
- Token refresh and encryption/decryption logic.
- Google Ads API client to list campaigns and customers.
- Account selection and campaign mapping UI/API.
- Connection health checks and token expiry management.

## Deliverables
- Secure Google OAuth login flow.
- Encrypted Google refresh token persistence.
- Campaign discovery by customer/account.
- Permission checks and account-level controls.
- Connection status and error reporting.

## Acceptance criteria
- A user can authorize Click Shield to access a Google Ads manager or customer account.
- Refresh tokens are stored encrypted at rest.
- Campaigns are discovered and persisted to the database.
- A connection can be reactivated after token expiry.

## Dependencies
- Task 01
- Task 03

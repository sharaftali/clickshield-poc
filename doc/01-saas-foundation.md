# Task 01 — SaaS Foundation and Multi-Tenant Scaffolding

## Goal
Set up the product base required to support multiple organizations, websites, users, and future ad-platform integrations without hard-coding a single client.

## Current status in repo
Partial/implemented:
- Multi-tenant database models exist for organizations, users, websites, and connections.
- Core config supports PostgreSQL, Redis, security, and Google OAuth settings.
- Seed logic creates a default org, admin user, and test website.

Not implemented yet:
- Auth API and user session flows for real login/logout.
- Organization management UI or admin APIs.
- Tenant isolation rules across all endpoints beyond model design.
- Production-ready deployment config for SaaS hosting.

## Deliverables
- Tenant/user models with secure password handling.
- Auth endpoints for login and refresh tokens.
- Organization and website CRUD APIs.
- Role-based access and tenant-scoped queries.
- Environment + deployment configuration for production.

## Acceptance criteria
- A new organization can be created and isolated from other organizations.
- A website is linked to one organization and owns a unique tracking token.
- Admin user can authenticate via secure token-based flow.
- Startup seeding works idempotently.

## Dependencies
- None

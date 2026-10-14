"""
Development seed (task 032) — runs only when ENVIRONMENT=development / test.

Creates a default organization, an owner and a verified localhost website so a
fresh checkout works. Production never seeds: create the first owner with
`python -m app.cli create-admin`.
"""
from __future__ import annotations

import logging
import secrets

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import hash_password
from app.models import Organization, ProtectionMode, User, UserRole, Website

logger = logging.getLogger(__name__)


async def seed_defaults(db: AsyncSession) -> None:
    if not settings.is_development:
        logger.info("ENVIRONMENT=%s: development seed skipped", settings.ENVIRONMENT)
        return

    org = (
        await db.execute(select(Organization).where(Organization.slug == settings.DEFAULT_ORGANIZATION_SLUG))
    ).scalar_one_or_none()
    if not org:
        org = Organization(
            name=settings.DEFAULT_ORGANIZATION_NAME,
            slug=settings.DEFAULT_ORGANIZATION_SLUG,
            protection_mode=ProtectionMode.BALANCED,
        )
        db.add(org)
        await db.flush()
        logger.info("Created organization: %s", org.name)

    user = (await db.execute(select(User).where(User.email == settings.DEFAULT_ADMIN_EMAIL))).scalar_one_or_none()
    if not user:
        password = settings.DEFAULT_ADMIN_PASSWORD
        if not password:
            password = secrets.token_urlsafe(12)
            logger.warning(
                "DEVELOPMENT: created %s with generated password %s (set DEFAULT_ADMIN_PASSWORD to choose one)",
                settings.DEFAULT_ADMIN_EMAIL, password,
            )
        db.add(User(
            organization_id=org.id,
            email=settings.DEFAULT_ADMIN_EMAIL,
            hashed_password=hash_password(password),
            full_name=settings.DEFAULT_ADMIN_FULL_NAME,
            role=UserRole.OWNER,
        ))
        logger.info("Created development owner: %s", settings.DEFAULT_ADMIN_EMAIL)

    website = (await db.execute(select(Website).where(Website.organization_id == org.id))).scalars().first()
    if not website:
        website = Website(
            organization_id=org.id,
            domain="localhost",
            display_name="Local Test Site",
            tracking_token=secrets.token_urlsafe(24),
            is_verified=True,
        )
        db.add(website)
        logger.info("Created development website: localhost")
    logger.info("Development tracking token: %s", website.tracking_token)

    await db.commit()

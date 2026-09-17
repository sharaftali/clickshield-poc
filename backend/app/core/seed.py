"""
Idempotent seeding — safe to run on every startup.
Creates a default org, admin user, and test website if they don't exist.
"""
from __future__ import annotations

import logging
import secrets

import bcrypt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models import (
    Organization,
    ProtectionMode,
    User,
    UserRole,
    Website,
)

logger = logging.getLogger(__name__)


def hash_password(plain_password: str) -> str:
    """Hash a password using bcrypt. Truncates to 72 bytes per bcrypt spec."""
    password_bytes = plain_password.encode("utf-8")[:72]
    hashed = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    return hashed.decode("utf-8")


async def seed_defaults(db: AsyncSession) -> None:
    # ---- Organization ----
    result = await db.execute(
        select(Organization).where(
            Organization.slug == settings.DEFAULT_ORGANIZATION_SLUG
        )
    )
    org = result.scalar_one_or_none()
    if not org:
        org = Organization(
            name=settings.DEFAULT_ORGANIZATION_NAME,
            slug=settings.DEFAULT_ORGANIZATION_SLUG,
            protection_mode=ProtectionMode.BALANCED,
        )
        db.add(org)
        await db.flush()
        logger.info("Created organization: %s", org.name)
    else:
        logger.debug("Organization already exists: %s", org.slug)

    # ---- Admin user ----
    result = await db.execute(
        select(User).where(User.email == settings.DEFAULT_ADMIN_EMAIL)
    )
    user = result.scalar_one_or_none()
    if not user:
        user = User(
            organization_id=org.id,
            email=settings.DEFAULT_ADMIN_EMAIL,
            hashed_password=hash_password(settings.DEFAULT_ADMIN_PASSWORD),
            full_name=settings.DEFAULT_ADMIN_FULL_NAME,
            role=UserRole.OWNER,
        )
        db.add(user)
        logger.info("Created admin user: %s", user.email)
    else:
        logger.debug("Admin user already exists: %s", user.email)

    # ---- Test website ----
    result = await db.execute(
        select(Website).where(Website.organization_id == org.id)
    )
    website = result.scalar_one_or_none()
    if not website:
        token = secrets.token_urlsafe(24)
        website = Website(
            organization_id=org.id,
            domain="localhost",
            display_name="Local Test Site",
            tracking_token=token,
            is_verified=True,
        )
        db.add(website)
        logger.info("Created website: %s", website.domain)
    logger.info("Tracking token: %s", website.tracking_token)

    await db.commit()

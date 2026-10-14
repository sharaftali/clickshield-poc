from __future__ import annotations

from fastapi import HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AuditResult, ProtectionMode
from app.models.organization import Organization, User
from app.schemas.organization import OrganizationResponse, OrganizationUpdateRequest, ProtectionPolicyOut
from app.services import audit_service
from app.services.audit_service import AuditAction
from app.services.protection_policy import get_policy, mode_defaults, validate_custom_settings


def organization_response(organization: Organization) -> OrganizationResponse:
    return OrganizationResponse(
        id=organization.id,
        name=organization.name,
        slug=organization.slug,
        protection_mode=organization.protection_mode,
        is_active=organization.is_active,
        protection_settings=organization.protection_settings,
        timezone=organization.timezone,
        raw_events_retention_days=organization.raw_events_retention_days,
        sessions_retention_days=organization.sessions_retention_days,
        fraud_session_retention_days=organization.fraud_session_retention_days,
        policy=ProtectionPolicyOut(**get_policy(organization).as_dict()),
        mode_defaults={
            mode.value: ProtectionPolicyOut(mode=mode, **mode_defaults(mode))
            for mode in ProtectionMode
            if mode != ProtectionMode.CUSTOM
        },
    )


class OrganizationService:
    @staticmethod
    async def _load(db: AsyncSession, user: User, *, for_update: bool = False) -> Organization:
        query = select(Organization).where(Organization.id == user.organization_id)
        if for_update:
            query = query.with_for_update()
        organization = (await db.execute(query)).scalar_one_or_none()
        if organization is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Organization not found.",
            )
        return organization

    @staticmethod
    async def get_my_organization(db: AsyncSession, user: User) -> OrganizationResponse:
        return organization_response(await OrganizationService._load(db, user))

    @staticmethod
    async def update_my_organization(
        db: AsyncSession, user: User, payload: OrganizationUpdateRequest, request: Request
    ) -> OrganizationResponse:
        """Change the protection mode / Custom thresholds (task 016). Affects new scoring
        only: existing verdicts and exclusions are not touched."""
        organization = await OrganizationService._load(db, user, for_update=True)
        before = get_policy(organization).as_dict()
        previous_mode = organization.protection_mode

        if payload.protection_mode is not None:
            organization.protection_mode = payload.protection_mode
        if payload.protection_settings is not None:
            organization.protection_settings = validate_custom_settings(
                payload.protection_settings.model_dump(exclude_none=True)
            )
        if organization.protection_mode == ProtectionMode.CUSTOM and not organization.protection_settings:
            organization.protection_settings = validate_custom_settings({})

        settings_changes = {}
        fields = payload.model_fields_set
        for name in ("timezone", "raw_events_retention_days", "sessions_retention_days", "fraud_session_retention_days"):
            if name in fields and (name != "timezone" or payload.timezone is not None):
                value = getattr(payload, name)
                if getattr(organization, name) != value:
                    settings_changes[name] = {"from": getattr(organization, name), "to": value}
                    setattr(organization, name, value)
        if settings_changes:
            audit_service.record(
                db, action=AuditAction.ORGANIZATION_SETTINGS_CHANGED, result=AuditResult.SUCCESS,
                organization_id=organization.id, user_id=user.id, resource_type="organization",
                resource_id=organization.id, request=request, details={"changes": settings_changes},
            )

        after = get_policy(organization).as_dict()
        if before != after or previous_mode != organization.protection_mode:
            audit_service.record(
                db, action=AuditAction.PROTECTION_MODE_CHANGED, result=AuditResult.SUCCESS,
                organization_id=organization.id, user_id=user.id,
                resource_type="organization", resource_id=organization.id, request=request,
                details={"before": before, "after": after},
            )
        await db.commit()
        await db.refresh(organization)
        return organization_response(organization)

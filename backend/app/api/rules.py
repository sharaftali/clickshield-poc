"""
Fraud rules for the caller's organization (spec §21–22, §54 Custom mode, §64; task 015).

GET lists the effective rules. PATCH stores an organization override (weight,
enabled, params); DELETE removes it. Global rule values change only through
migrations until platform administration exists (task 027). Every change is
audited and takes effect for this organization at once (other API processes
within RULES_CACHE_TTL_SECONDS).
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.dependencies.auth import AdminUser, CurrentUser
from app.models import AuditResult, Rule, RuleOverride
from app.schemas.rules import RuleDefaults, RuleOut, RuleOverrideIn, RuleOverrideOut
from app.services import audit_service
from app.services.audit_service import AuditAction
from app.services.rules import EVALUATORS, validate_params
from app.services.rules.repository import apply_override, invalidate, rule_to_config

router = APIRouter(prefix="/api/v1/rules", tags=["rules"])


def _rule_out(rule: Rule, override: RuleOverride | None) -> RuleOut:
    base = rule_to_config(rule)
    effective = apply_override(base, override)
    return RuleOut(
        code=rule.code, name=rule.name, description=rule.description or "", category=rule.category,
        enabled=effective.enabled, weight=effective.weight, confidence=effective.confidence,
        params=effective.params, version=rule.version,
        defaults=RuleDefaults(enabled=base.enabled, weight=base.weight, params=base.params),
        override=None if override is None else RuleOverrideOut(
            enabled=override.enabled, weight=override.weight, params=override.params, version=override.version,
        ),
    )


async def _load(db: AsyncSession, organization_id, code: str) -> tuple[Rule, RuleOverride | None]:
    rule = await db.get(Rule, code)
    if rule is None or rule.code not in EVALUATORS:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Unknown rule {code!r}.")
    override = await db.get(RuleOverride, (organization_id, code), with_for_update=True)
    return rule, override


@router.get("", response_model=list[RuleOut])
async def list_rules(current_user: CurrentUser, db: AsyncSession = Depends(get_db)) -> list[RuleOut]:
    rules = (await db.execute(select(Rule).order_by(Rule.category, Rule.code))).scalars().all()
    overrides = {
        row.rule_code: row
        for row in (
            await db.execute(select(RuleOverride).where(RuleOverride.organization_id == current_user.organization_id))
        ).scalars()
    }
    return [_rule_out(rule, overrides.get(rule.code)) for rule in rules if rule.code in EVALUATORS]


@router.patch("/{code}", response_model=RuleOut)
async def update_rule(
    code: str,
    payload: RuleOverrideIn,
    request: Request,
    current_user: AdminUser,
    db: AsyncSession = Depends(get_db),
) -> RuleOut:
    rule, override = await _load(db, current_user.organization_id, code)
    before = _rule_out(rule, override)

    changes = payload.model_dump(exclude_unset=True)
    if "params" in changes and changes["params"] is not None:
        try:
            validate_params(code, {**(rule.params or {}), **(override.params if override and override.params else {}), **changes["params"]})
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
        unknown = set(changes["params"]) - set(rule.params or {})
        if unknown:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                                detail=f"Unknown parameters for {code}: {', '.join(sorted(unknown))}")
        changes["params"] = {**((override.params or {}) if override else {}), **changes["params"]}

    if override is None:
        override = RuleOverride(organization_id=current_user.organization_id, rule_code=code, version=0)
        db.add(override)
    for key, value in changes.items():
        setattr(override, key, value)
    override.version = (override.version or 0) + 1
    override.updated_by = current_user.id

    after = _rule_out(rule, override)
    audit_service.record(
        db, action=AuditAction.RULE_CHANGED, result=AuditResult.SUCCESS,
        organization_id=current_user.organization_id, user_id=current_user.id,
        resource_type="rule", resource_id=code, request=request,
        details={"scope": "organization", "changes": changes, "before": _summary(before), "after": _summary(after)},
    )
    await db.commit()
    invalidate(current_user.organization_id)
    return after


@router.delete("/{code}/override", response_model=RuleOut)
async def reset_rule(
    code: str,
    request: Request,
    current_user: AdminUser,
    db: AsyncSession = Depends(get_db),
) -> RuleOut:
    rule, override = await _load(db, current_user.organization_id, code)
    if override is None:
        return _rule_out(rule, None)
    before = _rule_out(rule, override)
    await db.delete(override)
    after = _rule_out(rule, None)
    audit_service.record(
        db, action=AuditAction.RULE_CHANGED, result=AuditResult.SUCCESS,
        organization_id=current_user.organization_id, user_id=current_user.id,
        resource_type="rule", resource_id=code, request=request,
        details={"scope": "organization", "reset": True, "before": _summary(before), "after": _summary(after)},
    )
    await db.commit()
    invalidate(current_user.organization_id)
    return after


def _summary(rule: RuleOut) -> dict:
    return {"enabled": rule.enabled, "weight": rule.weight, "params": rule.params}

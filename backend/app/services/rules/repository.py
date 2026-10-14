"""
Effective rule configuration per organization (task 015).

global row (`rules`) → organization override (`rule_overrides`) → effective config.
Results are cached in process for RULES_CACHE_TTL_SECONDS so scoring doesn't read
the rules on every tracking batch; a change made through the API invalidates this
process's cache at once, other processes pick it up within the TTL.
"""
from __future__ import annotations

import logging
import time
import uuid
from dataclasses import replace

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models import Rule, RuleOverride
from app.services.rules.catalog import CATALOG, Category
from app.services.rules.evaluators import EVALUATORS, RuleConfig, validate_params

logger = logging.getLogger(__name__)

_GLOBAL_KEY = "global"
_cache: dict[str, tuple[float, object]] = {}


def invalidate(organization_id: uuid.UUID | None = None) -> None:
    """Drop cached rules: one organization's overrides, or everything."""
    if organization_id is None:
        _cache.clear()
    else:
        _cache.pop(str(organization_id), None)


def _cached(key: str):
    entry = _cache.get(key)
    if entry and entry[0] > time.monotonic():
        return entry[1]
    return None


def _store(key: str, value) -> None:
    _cache[key] = (time.monotonic() + settings.RULES_CACHE_TTL_SECONDS, value)


def catalog_configs() -> list[RuleConfig]:
    return [
        RuleConfig(
            code=rule.code, name=rule.name, description=rule.description, category=rule.category,
            enabled=rule.enabled, weight=rule.weight, confidence=rule.confidence,
            params=dict(rule.params), version=0,
        )
        for rule in CATALOG
    ]


def rule_to_config(row: Rule) -> RuleConfig:
    return RuleConfig(
        code=row.code, name=row.name, description=row.description or "", category=Category(row.category),
        enabled=row.enabled, weight=row.weight, confidence=row.confidence,
        params=dict(row.params or {}), version=row.version,
    )


def apply_override(rule: RuleConfig, override: RuleOverride | None) -> RuleConfig:
    if override is None:
        return rule
    params = rule.params
    if override.params:
        try:
            params = validate_params(rule.code, {**rule.params, **override.params})
        except ValueError as exc:
            logger.error("Ignoring invalid override params for %s: %s", rule.code, exc)
    return replace(
        rule,
        enabled=rule.enabled if override.enabled is None else override.enabled,
        weight=rule.weight if override.weight is None else override.weight,
        params=params,
        override_version=override.version,
    )


async def load_global_rules(db: AsyncSession) -> list[RuleConfig]:
    if settings.RULES_SOURCE == "code":
        return catalog_configs()
    cached = _cached(_GLOBAL_KEY)
    if cached is not None:
        return cached
    rows = (await db.execute(select(Rule).order_by(Rule.category, Rule.code))).scalars().all()
    rules = []
    for row in rows:
        if row.code not in EVALUATORS:
            logger.warning("Rule %s has no evaluator in this version; skipped", row.code)
            continue
        rules.append(rule_to_config(row))
    if not rules:
        logger.error("The rules table is empty (migrations not run?); using the built-in catalog")
        rules = catalog_configs()
    _store(_GLOBAL_KEY, rules)
    return rules


async def load_overrides(db: AsyncSession, organization_id: uuid.UUID) -> dict[str, RuleOverride]:
    key = str(organization_id)
    cached = _cached(key)
    if cached is not None:
        return cached
    rows = (
        await db.execute(select(RuleOverride).where(RuleOverride.organization_id == organization_id))
    ).scalars().all()
    overrides = {row.rule_code: row for row in rows}
    for row in rows:
        db.expunge(row)  # cached across sessions: detach
    _store(key, overrides)
    return overrides


async def load_rules(db: AsyncSession, organization_id: uuid.UUID) -> list[RuleConfig]:
    """Effective rules for an organization (cached)."""
    rules = await load_global_rules(db)
    if settings.RULES_SOURCE == "code":
        return rules
    overrides = await load_overrides(db, organization_id)
    return [apply_override(rule, overrides.get(rule.code)) for rule in rules]

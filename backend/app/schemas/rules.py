from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class RuleDefaults(BaseModel):
    enabled: bool
    weight: int
    params: dict[str, Any]


class RuleOverrideOut(BaseModel):
    enabled: bool | None = None
    weight: int | None = None
    params: dict[str, Any] | None = None
    version: int


class RuleOut(BaseModel):
    """A rule as it applies to the caller's organization (global value + override)."""
    code: str
    name: str
    description: str
    category: str
    enabled: bool
    weight: int
    confidence: int
    params: dict[str, Any]
    version: int
    defaults: RuleDefaults
    override: RuleOverrideOut | None = None


class RuleOverrideIn(BaseModel):
    """Fields left out keep their current override; null clears that field of the override."""
    enabled: bool | None = None
    weight: int | None = Field(default=None, ge=0, le=100)
    # Only the parameters to change; validated against the rule's parameter schema.
    params: dict[str, Any] | None = None

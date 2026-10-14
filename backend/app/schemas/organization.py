from __future__ import annotations

import uuid

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.models.enums import ProtectionMode


class OrganizationCreateRequest(BaseModel):
    model_config = ConfigDict(strict=False)

    name: str = Field(..., min_length=2, max_length=120)
    slug: str | None = Field(default=None, min_length=2, max_length=80)
    protection_mode: ProtectionMode = ProtectionMode.BALANCED

    @field_validator("name", "slug")
    @classmethod
    def strip_values(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("This field cannot be blank.")
        return cleaned


class ProtectionPolicyOut(BaseModel):
    mode: ProtectionMode
    flag_risk: int
    fraud_risk: int
    fraud_confidence: int
    min_diversity: int
    auto_exclude: bool


class ProtectionSettingsIn(BaseModel):
    """Custom-mode thresholds (task 016). Missing values fall back to Balanced."""
    model_config = ConfigDict(extra="forbid")

    flag_risk: int | None = Field(default=None, ge=0, le=100)
    fraud_risk: int | None = Field(default=None, ge=0, le=100)
    fraud_confidence: int | None = Field(default=None, ge=0, le=100)
    min_diversity: int | None = Field(default=None, ge=0, le=7)
    auto_exclude: bool | None = None


class OrganizationUpdateRequest(BaseModel):
    protection_mode: ProtectionMode | None = None
    protection_settings: ProtectionSettingsIn | None = None

    @model_validator(mode="after")
    def check_custom(self) -> "OrganizationUpdateRequest":
        from app.services.protection_policy import validate_custom_settings

        if self.protection_settings is not None:
            # Floors (min diversity ≥ 2, …) are enforced here so a bad value is a 422.
            validate_custom_settings(self.protection_settings.model_dump(exclude_none=True))
        return self


class OrganizationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    slug: str
    protection_mode: ProtectionMode
    is_active: bool
    protection_settings: dict[str, Any] | None = None
    # What the current mode resolves to, and every mode's defaults (for the settings page).
    policy: ProtectionPolicyOut | None = None
    mode_defaults: dict[str, ProtectionPolicyOut] = {}

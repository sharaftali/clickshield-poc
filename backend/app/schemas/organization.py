from __future__ import annotations

import uuid

from pydantic import BaseModel, ConfigDict, Field, field_validator

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


class OrganizationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    slug: str
    protection_mode: ProtectionMode
    is_active: bool

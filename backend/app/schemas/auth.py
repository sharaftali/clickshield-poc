from __future__ import annotations

import uuid
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.models.enums import ProtectionMode, UserRole


class TokenPayload(BaseModel):
    sub: str
    token_type: Literal["access", "refresh"]
    iat: int
    exp: int


class OrganizationSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    slug: str
    protection_mode: ProtectionMode
    is_active: bool


class UserPublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    email: EmailStr
    full_name: str | None = None
    role: UserRole
    is_active: bool


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in_minutes: int = Field(default=60, ge=1)


class RegisterRequest(BaseModel):
    full_name: Annotated[str, Field(min_length=2, max_length=120)]
    email: EmailStr
    password: Annotated[str, Field(min_length=8, max_length=128)]
    organization_name: Annotated[str, Field(min_length=2, max_length=120)]
    organization_slug: Annotated[str | None, Field(default=None, min_length=2, max_length=80)] = None
    protection_mode: ProtectionMode = ProtectionMode.BALANCED

    @field_validator("full_name", "organization_name")
    @classmethod
    def trim_and_validate_names(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("This field cannot be blank.")
        return cleaned

    @field_validator("organization_slug")
    @classmethod
    def normalize_slug(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip().lower()
        if not cleaned:
            raise ValueError("Organization slug cannot be blank.")
        return cleaned

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: EmailStr) -> str:
        return str(value).strip().lower()

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        if len(value) < 8:
            raise ValueError("Password must be at least 8 characters long.")
        if not any(ch.isdigit() for ch in value):
            raise ValueError("Password must contain at least one number.")
        if not any(ch.isalpha() for ch in value):
            raise ValueError("Password must contain at least one letter.")
        return value


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: EmailStr) -> str:
        return str(value).strip().lower()


class RefreshTokenRequest(BaseModel):
    refresh_token: str = Field(..., min_length=10)


class AuthResponse(BaseModel):
    user: UserPublic
    organization: OrganizationSummary
    tokens: TokenPair


class AuthenticatedUserResponse(BaseModel):
    user: UserPublic
    organization: OrganizationSummary

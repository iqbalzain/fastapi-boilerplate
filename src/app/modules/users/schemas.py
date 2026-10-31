"""Transport schemas. Inputs forbid unknown fields; outputs never expose secrets."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


class StrictInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class UserCreate(StrictInput):
    email: EmailStr = Field(max_length=320)
    password: str = Field(min_length=12, max_length=128)
    full_name: str | None = Field(default=None, max_length=200)

    @field_validator("email")
    @classmethod
    def _normalise_email(cls, value: str) -> str:
        return value.lower()


class UserUpdate(StrictInput):
    full_name: str | None = Field(default=None, max_length=200)


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: EmailStr
    full_name: str | None
    is_active: bool
    is_superuser: bool
    created_at: datetime


class Page[T](BaseModel):
    items: list[T]
    total: int
    limit: int
    offset: int

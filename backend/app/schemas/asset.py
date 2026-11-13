"""Pydantic schemas for target Assets and Domain Ownership Verifications."""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import TargetType, VerificationMethod, VerificationStatus


class AssetCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=150)
    target: str = Field(..., min_length=3, max_length=255)
    environment: str = Field(default="production", min_length=2, max_length=50)
    owner_email: str | None = Field(default=None, max_length=255)
    notes: str | None = Field(default=None, max_length=2000)


class DomainVerificationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    asset_id: uuid.UUID
    method: VerificationMethod
    challenge_token: str
    expected_location: str
    status: VerificationStatus
    last_checked_at: datetime | None
    verified_at: datetime | None
    failure_reason: str | None
    expires_at: datetime
    created_at: datetime
    instructions: str | None = None


class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    target_type: TargetType
    normalized_target: str
    hostname: str
    scheme: str | None
    port: int | None
    resolved_ip: str | None
    environment: str
    owner_email: str | None
    notes: str | None
    is_verified: bool
    verified_at: datetime | None
    verification_method: VerificationMethod | None
    created_at: datetime
    updated_at: datetime


class AssetDetailOut(AssetOut):
    verifications: list[DomainVerificationOut] = Field(default_factory=list)


class VerificationChallengeCreate(BaseModel):
    method: VerificationMethod


class VerificationCheckOut(BaseModel):
    verified: bool
    message: str
    verification: DomainVerificationOut

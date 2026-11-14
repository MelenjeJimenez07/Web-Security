"""Pydantic schemas for structured security Findings mapped to OWASP Top 10:2025."""

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from app.models.enums import FindingStatus, SeverityLevel


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    audit_run_id: uuid.UUID
    module_execution_id: uuid.UUID | None
    module_key: str
    owasp_category_code: str
    secondary_owasp_codes: list[str]
    title: str
    technical_description: str
    severity: SeverityLevel
    cvss_score: float | None
    cvss_vector: str | None = None
    cwe_id: str | None
    cve_ids: list[str]
    affected_component: str | None
    evidence: dict[str, Any]
    remediation_steps: str
    remediation_snippets: dict[str, str]
    references: list[str]
    fingerprint_hash: str
    status: FindingStatus
    created_at: datetime
    owasp_category_name: str | None = None
    owasp_category_name_es: str | None = None


class FindingStatusUpdate(BaseModel):
    status: FindingStatus

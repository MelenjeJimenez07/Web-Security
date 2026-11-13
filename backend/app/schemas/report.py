"""Pydantic schemas for PDF and JSON audit report exports."""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import ReportFormat, ReportType


class ReportGenerateRequest(BaseModel):
    format: ReportFormat = ReportFormat.PDF
    report_type: ReportType = ReportType.FULL
    generated_by: str = Field(default="security-auditor", min_length=2, max_length=150)


class AuditReportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    audit_run_id: uuid.UUID
    format: ReportFormat
    report_type: ReportType
    file_name: str
    file_size_bytes: int
    sha256_checksum: str
    generated_by: str | None
    created_at: datetime
    download_url: str = ""

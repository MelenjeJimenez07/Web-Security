"""Pydantic schemas for Audit Runs, Modules, Dashboard KPIs, and Security Logs."""

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import AuditStatus, ModuleStatus, ScanProfile
from app.schemas.asset import AssetOut


class ScannerInfoOut(BaseModel):
    module_key: str
    module_name: str
    description: str
    is_active: bool
    default_owasp_categories: list[str]


class AuditLaunchRequest(BaseModel):
    asset_id: uuid.UUID
    scan_profile: ScanProfile = ScanProfile.QUICK
    selected_modules: list[str] | None = None
    authorization_confirmed: bool
    authorization_statement: str = Field(
        default=(
            "Confirmo que poseo autorización expresa y por escrito del propietario del activo "
            "para ejecutar estas pruebas de seguridad."
        ),
        min_length=15,
        max_length=1000,
    )
    requested_by: str = Field(default="security-auditor", min_length=2, max_length=150)


class AuditModuleExecutionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    audit_run_id: uuid.UUID
    module_key: str
    module_name: str
    status: ModuleStatus
    findings_count: int
    duration_ms: int | None
    raw_output: dict[str, Any]
    error_detail: str | None
    started_at: datetime | None
    completed_at: datetime | None


class AuditRunSummaryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    asset_id: uuid.UUID
    asset_name: str | None = None
    asset_target: str | None = None
    celery_task_id: str | None
    status: AuditStatus
    scan_profile: ScanProfile
    selected_modules: list[str]
    authorization_confirmed: bool
    requested_by: str
    ownership_verified_at_launch: bool
    progress_percent: int
    current_stage: str | None
    security_grade: str | None
    security_score: float | None
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    summary_metadata: dict[str, Any]
    started_at: datetime | None
    completed_at: datetime | None
    error_message: str | None
    created_at: datetime


class OwaspDistributionItem(BaseModel):
    code: str
    rank: int
    name: str
    name_es: str
    count: int
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class AuditRunDetailOut(AuditRunSummaryOut):
    authorization_statement: str
    asset: AssetOut
    module_executions: list[AuditModuleExecutionOut] = Field(default_factory=list)
    owasp_distribution: list[OwaspDistributionItem] = Field(default_factory=list)


class SecurityEventLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    audit_run_id: uuid.UUID | None
    asset_id: uuid.UUID | None
    event_type: str
    severity: str
    actor: str | None
    source_ip: str | None
    message: str
    details: dict[str, Any]
    created_at: datetime


class DashboardStatsOut(BaseModel):
    total_assets: int
    verified_assets: int
    total_audits: int
    active_audits: int
    total_findings: int
    severity_distribution: dict[str, int]
    owasp_distribution: list[OwaspDistributionItem]
    recent_audits: list[AuditRunSummaryOut]

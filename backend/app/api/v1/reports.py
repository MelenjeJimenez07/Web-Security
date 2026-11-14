"""Report export and secure download endpoints (PDF and JSON)."""

import uuid

from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.exceptions import ConflictError, ResourceNotFoundError
from app.core.logging import record_security_event_async
from app.db.session import get_async_db
from app.models.audit import AuditRun
from app.models.enums import AuditStatus, ReportFormat
from app.models.owasp import OwaspCategory
from app.models.report import AuditReport
from app.reports.exporter import generate_audit_report_file, resolve_safe_report_path
from app.schemas.report import AuditReportOut, ReportGenerateRequest

router = APIRouter(tags=["reports"])

_EXPORTABLE_STATUSES = {
    AuditStatus.COMPLETED,
    AuditStatus.PARTIAL_FAILURE,
    AuditStatus.FAILED,
}


def _to_report_out(report: AuditReport) -> AuditReportOut:
    out = AuditReportOut.model_validate(report)
    out.download_url = f"/api/v1/reports/{report.id}/download"
    return out


@router.get("/audits/{audit_id}/reports", response_model=list[AuditReportOut])
async def list_audit_reports(
    audit_id: uuid.UUID,
    db: AsyncSession = Depends(get_async_db),
) -> list[AuditReportOut]:
    """List exported reports generated for an audit run."""
    run = await db.get(AuditRun, audit_id)
    if run is None:
        raise ResourceNotFoundError(f"Auditoría '{audit_id}' no encontrada.")

    reports = (
        await db.scalars(
            select(AuditReport)
            .where(AuditReport.audit_run_id == audit_id)
            .order_by(AuditReport.created_at.desc())
        )
    ).all()
    return [_to_report_out(r) for r in reports]


@router.post(
    "/audits/{audit_id}/reports",
    response_model=AuditReportOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_audit_report(
    audit_id: uuid.UUID,
    payload: ReportGenerateRequest,
    request: Request,
    db: AsyncSession = Depends(get_async_db),
) -> AuditReportOut:
    """Generate and persist an executive, technical, or full PDF/JSON report."""
    run = await db.scalar(
        select(AuditRun)
        .options(
            selectinload(AuditRun.asset),
            selectinload(AuditRun.findings),
            selectinload(AuditRun.module_executions),
        )
        .where(AuditRun.id == audit_id)
    )
    if run is None:
        raise ResourceNotFoundError(f"Auditoría '{audit_id}' no encontrada.")

    if run.status not in _EXPORTABLE_STATUSES:
        raise ConflictError(
            "La auditoría aún está en curso. Espera a que finalice antes de exportar el informe."
        )

    categories = list(
        (await db.scalars(select(OwaspCategory).order_by(OwaspCategory.rank.asc()))).all()
    )

    exported = generate_audit_report_file(
        run,
        categories,
        report_format=payload.format,
        report_type=payload.report_type,
        generated_by=payload.generated_by,
    )

    report = AuditReport(
        audit_run_id=run.id,
        format=payload.format,
        report_type=payload.report_type,
        file_name=exported.file_name,
        file_path=str(exported.file_path),
        file_size_bytes=exported.file_size_bytes,
        sha256_checksum=exported.sha256_checksum,
        generated_by=payload.generated_by.strip(),
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)

    src_ip = request.client.host if request.client else None
    await record_security_event_async(
        db,
        event_type="REPORT_EXPORTED",
        severity="info",
        actor=payload.generated_by,
        source_ip=src_ip,
        asset_id=run.asset_id,
        audit_run_id=run.id,
        message=(
            f"Reporte {payload.format.value.upper()} ({payload.report_type.value}) generado "
            f"para {run.asset.normalized_target}."
        ),
        details={
            "report_id": str(report.id),
            "file_name": report.file_name,
            "sha256_checksum": report.sha256_checksum,
        },
    )

    return _to_report_out(report)


@router.get("/reports/{report_id}/download")
async def download_report(
    report_id: uuid.UUID,
    db: AsyncSession = Depends(get_async_db),
) -> FileResponse:
    """Safely download a previously generated PDF or JSON report."""
    report = await db.get(AuditReport, report_id)
    if report is None:
        raise ResourceNotFoundError(f"Reporte '{report_id}' no encontrado.")

    safe_path = resolve_safe_report_path(report.file_path)
    if not safe_path.is_file():
        raise ResourceNotFoundError("El archivo de reporte ya no existe en almacenamiento.")

    media_types = {
        ReportFormat.PDF: "application/pdf",
        ReportFormat.JSON: "application/json",
        ReportFormat.DOCX: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    }
    media_type = media_types.get(report.format, "application/octet-stream")
    return FileResponse(
        path=safe_path,
        filename=report.file_name,
        media_type=media_type,
        headers={
            "X-Content-Type-Options": "nosniff",
            "X-Report-SHA256": report.sha256_checksum,
        },
    )

"""Audit orchestration, findings triage, dashboard metrics, and SSE streaming routes."""

import asyncio
import json
import uuid
from collections.abc import AsyncGenerator

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, Query, Request, status
from fastapi.responses import StreamingResponse
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import get_settings
from app.core.exceptions import (
    AuthorizationRequiredError,
    ConflictError,
    DomainNotVerifiedError,
    ResourceNotFoundError,
    ScannerExecutionError,
    SSRFBlockedError,
)
from app.reports.exporter import resolve_safe_report_path
from app.core.logging import record_security_event_async
from app.core.security import validate_target_ssrf
from app.db.session import AsyncSessionLocal, get_async_db
from app.models.asset import Asset
from app.models.audit import AuditModuleExecution, AuditRun
from app.models.audit_log import SecurityEventLog
from app.models.enums import AuditStatus, FindingStatus, ModuleStatus, SeverityLevel
from app.models.finding import Finding
from app.models.owasp import OwaspCategory
from app.scanners.registry import (
    get_scanner,
    has_active_modules,
    list_scanners_metadata,
    validate_module_keys,
)
from app.schemas.asset import AssetOut
from app.schemas.audit import (
    AuditLaunchRequest,
    AuditModuleExecutionOut,
    AuditRunDetailOut,
    AuditRunSummaryOut,
    DashboardStatsOut,
    OwaspDistributionItem,
    ScannerInfoOut,
)
from app.schemas.finding import FindingOut, FindingStatusUpdate
from app.worker.events import audit_channel_name, fetch_buffered_events
from app.worker.tasks import run_audit_task

router = APIRouter(tags=["audits"])
settings = get_settings()

_TERMINAL_AUDIT_STATUSES = {
    AuditStatus.COMPLETED,
    AuditStatus.PARTIAL_FAILURE,
    AuditStatus.FAILED,
    AuditStatus.CANCELLED,
}


def _client_ip(request: Request) -> str | None:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


def _to_audit_summary(run: AuditRun) -> AuditRunSummaryOut:
    summary = AuditRunSummaryOut.model_validate(run)
    if run.asset:
        summary.asset_name = run.asset.name
        summary.asset_target = run.asset.normalized_target
    return summary


async def _build_owasp_distribution(
    db: AsyncSession,
    *,
    audit_run_id: uuid.UUID | None = None,
) -> list[OwaspDistributionItem]:
    categories = (
        await db.scalars(select(OwaspCategory).order_by(OwaspCategory.rank.asc()))
    ).all()

    stmt = select(
        Finding.owasp_category_code,
        func.count(Finding.id).label("total"),
        func.sum(case((Finding.severity == SeverityLevel.CRITICAL, 1), else_=0)).label("critical"),
        func.sum(case((Finding.severity == SeverityLevel.HIGH, 1), else_=0)).label("high"),
        func.sum(case((Finding.severity == SeverityLevel.MEDIUM, 1), else_=0)).label("medium"),
        func.sum(case((Finding.severity == SeverityLevel.LOW, 1), else_=0)).label("low"),
        func.sum(case((Finding.severity == SeverityLevel.INFO, 1), else_=0)).label("info"),
    )
    if audit_run_id is not None:
        stmt = stmt.where(Finding.audit_run_id == audit_run_id)
    stmt = stmt.group_by(Finding.owasp_category_code)

    rows = (await db.execute(stmt)).all()
    counts_by_code = {row.owasp_category_code: row for row in rows}

    distribution: list[OwaspDistributionItem] = []
    for cat in categories:
        row = counts_by_code.get(cat.code)
        distribution.append(
            OwaspDistributionItem(
                code=cat.code,
                rank=cat.rank,
                name=cat.name,
                name_es=cat.name_es,
                count=int(row.total) if row else 0,
                critical=int(row.critical or 0) if row else 0,
                high=int(row.high or 0) if row else 0,
                medium=int(row.medium or 0) if row else 0,
                low=int(row.low or 0) if row else 0,
                info=int(row.info or 0) if row else 0,
            )
        )
    return distribution


@router.get("/scanners", response_model=list[ScannerInfoOut])
async def list_available_scanners() -> list[dict[str, object]]:
    """Return registered OWASP Top 10:2025 audit modules."""
    return list_scanners_metadata()


@router.get("/dashboard/stats", response_model=DashboardStatsOut)
async def get_dashboard_stats(db: AsyncSession = Depends(get_async_db)) -> DashboardStatsOut:
    """Return aggregated KPIs, severity breakdown, and OWASP Top 10:2025 distribution."""
    total_assets = int(await db.scalar(select(func.count(Asset.id))) or 0)
    verified_assets = int(
        await db.scalar(select(func.count(Asset.id)).where(Asset.is_verified.is_(True))) or 0
    )
    total_audits = int(await db.scalar(select(func.count(AuditRun.id))) or 0)
    active_audits = int(
        await db.scalar(
            select(func.count(AuditRun.id)).where(
                AuditRun.status.in_([AuditStatus.PENDING, AuditStatus.QUEUED, AuditStatus.RUNNING])
            )
        )
        or 0
    )
    total_findings = int(await db.scalar(select(func.count(Finding.id))) or 0)

    sev_rows = (
        await db.execute(
            select(Finding.severity, func.count(Finding.id)).group_by(Finding.severity)
        )
    ).all()
    severity_distribution = {sev.value: 0 for sev in SeverityLevel}
    for sev, count in sev_rows:
        severity_distribution[sev.value] = int(count)

    owasp_distribution = await _build_owasp_distribution(db)

    recent_runs = (
        await db.scalars(
            select(AuditRun)
            .options(selectinload(AuditRun.asset))
            .order_by(AuditRun.created_at.desc())
            .limit(8)
        )
    ).all()

    return DashboardStatsOut(
        total_assets=total_assets,
        verified_assets=verified_assets,
        total_audits=total_audits,
        active_audits=active_audits,
        total_findings=total_findings,
        severity_distribution=severity_distribution,
        owasp_distribution=owasp_distribution,
        recent_audits=[_to_audit_summary(r) for r in recent_runs],
    )


@router.get("/audits", response_model=list[AuditRunSummaryOut])
async def list_audits(
    asset_id: uuid.UUID | None = Query(default=None),
    status_filter: AuditStatus | None = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=200),
    db: AsyncSession = Depends(get_async_db),
) -> list[AuditRunSummaryOut]:
    """List audit runs ordered by creation date descending."""
    stmt = select(AuditRun).options(selectinload(AuditRun.asset)).order_by(AuditRun.created_at.desc())
    if asset_id is not None:
        stmt = stmt.where(AuditRun.asset_id == asset_id)
    if status_filter is not None:
        stmt = stmt.where(AuditRun.status == status_filter)
    stmt = stmt.limit(limit)

    runs = (await db.scalars(stmt)).all()
    return [_to_audit_summary(r) for r in runs]


@router.post("/audits", response_model=AuditRunDetailOut, status_code=status.HTTP_201_CREATED)
async def launch_audit(
    payload: AuditLaunchRequest,
    request: Request,
    db: AsyncSession = Depends(get_async_db),
) -> AuditRunDetailOut:
    """Validate authorization, domain ownership, anti-SSRF, and enqueue a Celery audit."""
    src_ip = _client_ip(request)
    if not payload.authorization_confirmed:
        await record_security_event_async(
            db,
            event_type="AUTH_CONFIRMATION_MISSING",
            severity="warning",
            actor=payload.requested_by,
            source_ip=src_ip,
            asset_id=payload.asset_id,
            message="Intento de lanzamiento sin confirmación explícita de autorización.",
        )
        raise AuthorizationRequiredError(
            "Debes confirmar explícitamente que cuentas con autorización expresa para auditar este activo."
        )

    asset = await db.get(Asset, payload.asset_id)
    if asset is None:
        raise ResourceNotFoundError(f"Activo '{payload.asset_id}' no encontrado.")

    selected_modules = validate_module_keys(payload.selected_modules)

    if (
        settings.REQUIRE_DOMAIN_VERIFICATION
        and has_active_modules(selected_modules)
        and not asset.is_verified
    ):
        await record_security_event_async(
            db,
            event_type="SCAN_BLOCKED_UNVERIFIED",
            severity="warning",
            actor=payload.requested_by,
            source_ip=src_ip,
            asset_id=asset.id,
            message=(
                f"Escaneo activo bloqueado sobre '{asset.normalized_target}': propiedad del dominio no verificada."
            ),
            details={"selected_modules": selected_modules},
        )
        raise DomainNotVerifiedError(
            "Los módulos activos requieren verificar previamente la propiedad del dominio mediante "
            "registro DNS TXT o archivo '.well-known/security-audit.txt'.",
            details={"asset_id": str(asset.id), "hostname": asset.hostname},
        )

    try:
        validated = validate_target_ssrf(asset.normalized_target)
        asset.resolved_ip = validated.resolved_ip
    except SSRFBlockedError as exc:
        await record_security_event_async(
            db,
            event_type="SSRF_BLOCKED",
            severity="critical",
            actor=payload.requested_by,
            source_ip=src_ip,
            asset_id=asset.id,
            message=f"SSRF bloqueado al lanzar auditoría sobre {asset.normalized_target}.",
            details=exc.details,
        )
        raise

    audit_run = AuditRun(
        asset_id=asset.id,
        status=AuditStatus.QUEUED,
        scan_profile=payload.scan_profile,
        selected_modules=selected_modules,
        authorization_confirmed=True,
        authorization_statement=payload.authorization_statement.strip(),
        requested_by=payload.requested_by.strip(),
        requester_ip=src_ip,
        ownership_verified_at_launch=asset.is_verified,
        progress_percent=0,
        current_stage="En cola para ejecución en worker",
    )
    db.add(audit_run)
    await db.flush()

    for mkey in selected_modules:
        scanner = get_scanner(mkey)
        db.add(
            AuditModuleExecution(
                audit_run_id=audit_run.id,
                module_key=mkey,
                module_name=scanner.module_name,
                status=ModuleStatus.PENDING,
            )
        )

    await db.commit()
    await db.refresh(audit_run)

    try:
        task = run_audit_task.delay(str(audit_run.id))
        audit_run.celery_task_id = task.id
        await db.commit()
    except Exception as exc:
        audit_run.status = AuditStatus.FAILED
        audit_run.error_message = "No fue posible encolar la tarea en Celery/Redis."
        await db.commit()
        raise ScannerExecutionError(f"Error al encolar tarea de auditoría: {exc}") from exc

    await record_security_event_async(
        db,
        event_type="SCAN_REQUESTED",
        severity="info",
        actor=payload.requested_by,
        source_ip=src_ip,
        asset_id=asset.id,
        audit_run_id=audit_run.id,
        message=f"Auditoría encolada contra {asset.normalized_target} ({payload.scan_profile.value}).",
        details={"modules": selected_modules, "celery_task_id": task.id},
    )

    return await get_audit_detail(audit_run.id, db)


@router.get("/audits/{audit_id}", response_model=AuditRunDetailOut)
async def get_audit_detail(
    audit_id: uuid.UUID,
    db: AsyncSession = Depends(get_async_db),
) -> AuditRunDetailOut:
    """Return full detail for an audit run including module executions and OWASP breakdown."""
    run = await db.scalar(
        select(AuditRun)
        .options(selectinload(AuditRun.asset), selectinload(AuditRun.module_executions))
        .where(AuditRun.id == audit_id)
    )
    if run is None:
        raise ResourceNotFoundError(f"Auditoría '{audit_id}' no encontrada.")

    owasp_dist = await _build_owasp_distribution(db, audit_run_id=run.id)
    summary = _to_audit_summary(run)
    return AuditRunDetailOut(
        **summary.model_dump(),
        authorization_statement=run.authorization_statement,
        asset=AssetOut.model_validate(run.asset),
        module_executions=[
            AuditModuleExecutionOut.model_validate(me) for me in run.module_executions
        ],
        owasp_distribution=owasp_dist,
    )


def _remove_audit_report_files(file_paths: list[str]) -> None:
    """Safely delete exported report files that reside within REPORTS_DIR."""
    for file_path in file_paths:
        try:
            safe_path = resolve_safe_report_path(file_path)
        except ResourceNotFoundError:
            continue
        try:
            safe_path.unlink(missing_ok=True)
        except OSError:
            continue


@router.delete("/audits/{audit_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_audit(
    audit_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_async_db),
) -> None:
    """Delete a finished/failed/cancelled audit run and clean up its report artifacts."""
    run = await db.scalar(
        select(AuditRun)
        .options(
            selectinload(AuditRun.asset),
            selectinload(AuditRun.reports),
        )
        .where(AuditRun.id == audit_id)
    )
    if run is None:
        raise ResourceNotFoundError(f"Auditoría '{audit_id}' no encontrada.")

    if run.status not in _TERMINAL_AUDIT_STATUSES:
        raise ConflictError(
            "No se puede eliminar una auditoría en ejecución. Espera a que finalice."
        )

    asset_id = run.asset_id
    asset_target = run.asset.normalized_target if run.asset else str(asset_id)
    _remove_audit_report_files([report.file_path for report in run.reports])

    await db.delete(run)
    await db.commit()

    src_ip = request.client.host if request.client else None
    await record_security_event_async(
        db,
        event_type="AUDIT_DELETED",
        severity="warning",
        actor="dashboard-user",
        source_ip=src_ip,
        asset_id=asset_id,
        audit_run_id=None,
        message=f"Auditoría '{audit_id}' eliminada para el activo {asset_target}.",
        details={
            "deleted_audit_run_id": str(audit_id),
            "target": asset_target,
        },
    )


@router.get("/audits/{audit_id}/findings", response_model=list[FindingOut])
async def list_audit_findings(
    audit_id: uuid.UUID,
    severity: SeverityLevel | None = Query(default=None),
    owasp_category_code: str | None = Query(default=None),
    module_key: str | None = Query(default=None),
    status_filter: FindingStatus | None = Query(default=None, alias="status"),
    db: AsyncSession = Depends(get_async_db),
) -> list[FindingOut]:
    """Return structured findings for an audit run with optional OWASP/severity filtering."""
    run = await db.get(AuditRun, audit_id)
    if run is None:
        raise ResourceNotFoundError(f"Auditoría '{audit_id}' no encontrada.")

    stmt = (
        select(Finding)
        .options(selectinload(Finding.owasp_category))
        .where(Finding.audit_run_id == audit_id)
    )
    if severity is not None:
        stmt = stmt.where(Finding.severity == severity)
    if owasp_category_code is not None:
        stmt = stmt.where(Finding.owasp_category_code == owasp_category_code.upper())
    if module_key is not None:
        stmt = stmt.where(Finding.module_key == module_key)
    if status_filter is not None:
        stmt = stmt.where(Finding.status == status_filter)

    severity_order = case(
        (Finding.severity == SeverityLevel.CRITICAL, 1),
        (Finding.severity == SeverityLevel.HIGH, 2),
        (Finding.severity == SeverityLevel.MEDIUM, 3),
        (Finding.severity == SeverityLevel.LOW, 4),
        else_=5,
    )
    stmt = stmt.order_by(severity_order.asc(), Finding.created_at.asc())

    findings = (await db.scalars(stmt)).all()
    output: list[FindingOut] = []
    for item in findings:
        out = FindingOut.model_validate(item)
        if item.owasp_category:
            out.owasp_category_name = item.owasp_category.name
            out.owasp_category_name_es = item.owasp_category.name_es
        output.append(out)
    return output


@router.patch("/findings/{finding_id}", response_model=FindingOut)
async def update_finding_status(
    finding_id: uuid.UUID,
    payload: FindingStatusUpdate,
    request: Request,
    db: AsyncSession = Depends(get_async_db),
) -> FindingOut:
    """Update triage status of a finding (open, acknowledged, mitigated, false_positive)."""
    finding = await db.scalar(
        select(Finding)
        .options(selectinload(Finding.owasp_category))
        .where(Finding.id == finding_id)
    )
    if finding is None:
        raise ResourceNotFoundError(f"Hallazgo '{finding_id}' no encontrado.")

    previous_status = finding.status.value
    finding.status = payload.status
    await db.commit()
    await db.refresh(finding)

    await record_security_event_async(
        db,
        event_type="FINDING_STATUS_UPDATED",
        severity="info",
        source_ip=_client_ip(request),
        audit_run_id=finding.audit_run_id,
        message=f"Hallazgo '{finding.title}' actualizado de '{previous_status}' a '{payload.status.value}'.",
        details={"finding_id": str(finding.id), "from": previous_status, "to": payload.status.value},
    )

    out = FindingOut.model_validate(finding)
    if finding.owasp_category:
        out.owasp_category_name = finding.owasp_category.name
        out.owasp_category_name_es = finding.owasp_category.name_es
    return out


@router.get("/audits/{audit_id}/logs")
async def get_audit_logs(
    audit_id: uuid.UUID,
    db: AsyncSession = Depends(get_async_db),
) -> dict[str, object]:
    """Return buffered real-time console logs plus persistent security audit events."""
    run = await db.get(AuditRun, audit_id)
    if run is None:
        raise ResourceNotFoundError(f"Auditoría '{audit_id}' no encontrada.")

    buffered = await fetch_buffered_events(audit_id)
    events = (
        await db.scalars(
            select(SecurityEventLog)
            .where(SecurityEventLog.audit_run_id == audit_id)
            .order_by(SecurityEventLog.created_at.asc())
        )
    ).all()

    return {
        "audit_run_id": str(audit_id),
        "status": run.status.value,
        "stream_logs": buffered,
        "security_events": [
            {
                "id": str(e.id),
                "event_type": e.event_type,
                "severity": e.severity,
                "message": e.message,
                "created_at": e.created_at.isoformat(),
            }
            for e in events
        ],
    }


@router.get("/audits/{audit_id}/events")
async def stream_audit_events_sse(
    audit_id: uuid.UUID,
    request: Request,
) -> StreamingResponse:
    """Server-Sent Events (SSE) endpoint streaming real-time progress and logs."""
    async with AsyncSessionLocal() as check_db:
        run = await check_db.get(AuditRun, audit_id)
        if run is None:
            raise ResourceNotFoundError(f"Auditoría '{audit_id}' no encontrada.")

    async def event_generator() -> AsyncGenerator[str, None]:
        client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
        pubsub = client.pubsub()
        channel = audit_channel_name(audit_id)
        await pubsub.subscribe(channel)
        seen_keys: set[tuple[str | None, str | None, str | None]] = set()
        try:
            buffered = await fetch_buffered_events(audit_id)
            for item in buffered:
                key = (item.get("timestamp"), item.get("event_type"), item.get("message"))
                seen_keys.add(key)
                yield f"data: {json.dumps(item)}\n\n"

            async with AsyncSessionLocal() as poll_db:
                latest_run = await poll_db.get(AuditRun, audit_id)
                if latest_run and latest_run.status in _TERMINAL_AUDIT_STATUSES:
                    return

            idle_ticks = 0
            while True:
                if await request.is_disconnected():
                    break
                msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                if msg and msg.get("type") == "message":
                    idle_ticks = 0
                    raw_data = msg["data"]
                    try:
                        parsed = json.loads(raw_data)
                        key = (
                            parsed.get("timestamp"),
                            parsed.get("event_type"),
                            parsed.get("message"),
                        )
                        if key in seen_keys:
                            continue
                        seen_keys.add(key)
                        yield f"data: {raw_data}\n\n"
                        if parsed.get("event_type") in ("AUDIT_COMPLETED", "AUDIT_FAILED"):
                            break
                    except json.JSONDecodeError:
                        yield f"data: {raw_data}\n\n"
                else:
                    idle_ticks += 1
                    if idle_ticks >= 5:
                        idle_ticks = 0
                        async with AsyncSessionLocal() as poll_db:
                            latest_run = await poll_db.get(AuditRun, audit_id)
                            if latest_run and latest_run.status in _TERMINAL_AUDIT_STATUSES:
                                break
                    yield ": keepalive\n\n"
                    await asyncio.sleep(0.2)
        finally:
            await pubsub.unsubscribe(channel)
            await pubsub.close()
            await client.aclose()

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )

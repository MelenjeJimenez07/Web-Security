"""Celery background tasks executing modular OWASP Top 10:2025 security audits."""

import time
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select

from app.core.config import get_settings
from app.core.exceptions import SSRFBlockedError
from app.core.logging import configure_logging, record_security_event_sync
from app.core.security import validate_target_ssrf
from app.db.session import SyncSessionLocal
from app.models.audit import AuditModuleExecution, AuditRun
from app.models.enums import AuditStatus, ModuleStatus, SeverityLevel
from app.models.finding import Finding
from app.scanners.base import ScanContext, score_to_grade
from app.scanners.registry import get_scanner, has_active_modules
from app.worker.celery_app import celery_app
from app.worker.events import AuditStreamPublisher

configure_logging()
settings = get_settings()

_SEVERITY_PENALTIES: dict[SeverityLevel, float] = {
    SeverityLevel.CRITICAL: 24.0,
    SeverityLevel.HIGH: 12.0,
    SeverityLevel.MEDIUM: 5.0,
    SeverityLevel.LOW: 1.5,
    SeverityLevel.INFO: 0.0,
}


def _compute_overall_posture(
    findings: list[Finding],
    summary_metadata: dict[str, Any],
) -> tuple[float, str]:
    """Calculate overall 0-100 posture score and A+..F letter grade."""
    penalty = sum(_SEVERITY_PENALTIES.get(f.severity, 0.0) for f in findings)
    finding_based_score = max(0.0, 100.0 - min(penalty, 100.0))

    http_score = summary_metadata.get("http_score")
    if isinstance(http_score, (int, float)):
        blended = round((finding_based_score * 0.65) + (float(http_score) * 0.35), 1)
    else:
        blended = round(finding_based_score, 1)

    return blended, score_to_grade(blended)


@celery_app.task(name="websec.run_audit", bind=True)
def run_audit_task(self: Any, audit_run_id_str: str) -> dict[str, Any]:
    """Execute all selected audit modules for an AuditRun with real-time Redis streaming."""
    publisher = AuditStreamPublisher()
    audit_run_id = uuid.UUID(audit_run_id_str)

    try:
        with SyncSessionLocal() as db:
            audit_run = db.scalar(
                select(AuditRun).where(AuditRun.id == audit_run_id)
            )
            if audit_run is None:
                return {"status": "not_found", "audit_run_id": audit_run_id_str}

            asset = audit_run.asset
            if not audit_run.authorization_confirmed:
                audit_run.status = AuditStatus.FAILED
                audit_run.error_message = "Auditoría rechazada: falta confirmación de autorización."
                db.commit()
                publisher.publish(
                    audit_run_id,
                    event_type="AUDIT_FAILED",
                    level="error",
                    progress_percent=100,
                    message=audit_run.error_message,
                )
                return {"status": "failed", "reason": "authorization_missing"}

            selected_modules = list(audit_run.selected_modules or [])
            if (
                settings.REQUIRE_DOMAIN_VERIFICATION
                and has_active_modules(selected_modules)
                and not asset.is_verified
            ):
                audit_run.status = AuditStatus.FAILED
                audit_run.error_message = (
                    "Auditoría bloqueada: el activo requiere verificación previa de propiedad "
                    "(DNS TXT o .well-known/security-audit.txt) para módulos activos."
                )
                db.commit()
                record_security_event_sync(
                    db,
                    event_type="SCAN_BLOCKED_UNVERIFIED",
                    severity="warning",
                    actor=audit_run.requested_by,
                    asset_id=asset.id,
                    audit_run_id=audit_run.id,
                    message=audit_run.error_message,
                )
                publisher.publish(
                    audit_run_id,
                    event_type="AUDIT_FAILED",
                    level="error",
                    progress_percent=100,
                    message=audit_run.error_message,
                )
                return {"status": "failed", "reason": "domain_not_verified"}

            audit_run.status = AuditStatus.RUNNING
            audit_run.started_at = datetime.now(UTC)
            audit_run.progress_percent = 5
            audit_run.current_stage = "Validación anti-SSRF en tiempo de ejecución"
            db.commit()

            publisher.publish(
                audit_run_id,
                event_type="AUDIT_STARTED",
                level="info",
                progress_percent=5,
                message=f"Iniciando auditoría sobre {asset.normalized_target}...",
                data={"modules": selected_modules, "scan_profile": audit_run.scan_profile.value},
            )

            # Re-validate target in worker right before scanning to defeat DNS rebinding (TOCTOU)
            try:
                validated = validate_target_ssrf(asset.normalized_target)
                asset.resolved_ip = validated.resolved_ip
                db.commit()
            except SSRFBlockedError as exc:
                audit_run.status = AuditStatus.FAILED
                audit_run.completed_at = datetime.now(UTC)
                audit_run.progress_percent = 100
                audit_run.error_message = exc.message
                db.commit()
                record_security_event_sync(
                    db,
                    event_type="SSRF_BLOCKED",
                    severity="critical",
                    actor=audit_run.requested_by,
                    asset_id=asset.id,
                    audit_run_id=audit_run.id,
                    message=f"SSRF bloqueado en ejecución de worker: {exc.message}",
                    details=exc.details,
                )
                publisher.publish(
                    audit_run_id,
                    event_type="AUDIT_FAILED",
                    level="error",
                    progress_percent=100,
                    message=exc.message,
                )
                return {"status": "failed", "reason": "ssrf_blocked"}
            except Exception as exc:
                audit_run.status = AuditStatus.FAILED
                audit_run.completed_at = datetime.now(UTC)
                audit_run.progress_percent = 100
                audit_run.error_message = f"Error validando objetivo en ejecución: {exc}"
                db.commit()
                publisher.publish(
                    audit_run_id,
                    event_type="AUDIT_FAILED",
                    level="error",
                    progress_percent=100,
                    message=audit_run.error_message,
                )
                return {"status": "failed", "reason": "target_validation_error"}

            record_security_event_sync(
                db,
                event_type="SCAN_STARTED",
                severity="info",
                actor=audit_run.requested_by,
                asset_id=asset.id,
                audit_run_id=audit_run.id,
                message=f"Auditoría iniciada contra {asset.normalized_target} ({validated.resolved_ip}).",
                details={"modules": selected_modules, "profile": audit_run.scan_profile.value},
            )

            module_execs = {
                me.module_key: me
                for me in db.scalars(
                    select(AuditModuleExecution).where(
                        AuditModuleExecution.audit_run_id == audit_run.id
                    )
                ).all()
            }

            total_modules = max(len(selected_modules), 1)
            completed_count = 0
            failed_count = 0
            summary_metadata: dict[str, Any] = {
                "resolved_ip": validated.resolved_ip,
                "resolved_ips": list(validated.resolved_ips),
            }
            all_persisted_findings: list[Finding] = []

            for idx, module_key in enumerate(selected_modules, start=1):
                scanner = get_scanner(module_key)
                mod_exec = module_execs.get(module_key)
                if mod_exec is None:
                    mod_exec = AuditModuleExecution(
                        audit_run_id=audit_run.id,
                        module_key=module_key,
                        module_name=scanner.module_name,
                        status=ModuleStatus.PENDING,
                    )
                    db.add(mod_exec)
                    db.flush()

                base_progress = 10 + int(((idx - 1) / total_modules) * 85)
                mod_exec.status = ModuleStatus.RUNNING
                mod_exec.started_at = datetime.now(UTC)
                audit_run.current_stage = scanner.module_name
                audit_run.progress_percent = base_progress
                db.commit()

                publisher.publish(
                    audit_run_id,
                    event_type="MODULE_STARTED",
                    level="info",
                    module_key=module_key,
                    progress_percent=base_progress,
                    message=f"[{idx}/{total_modules}] Ejecutando {scanner.module_name}...",
                )

                def _emit_module_log(
                    level: str,
                    msg: str,
                    data: dict[str, Any] | None = None,
                    *,
                    _mkey: str = module_key,
                    _prog: int = base_progress,
                ) -> None:
                    publisher.publish(
                        audit_run_id,
                        event_type="LOG",
                        level=level,
                        module_key=_mkey,
                        progress_percent=_prog,
                        message=msg,
                        data=data,
                    )

                ctx = ScanContext(
                    audit_run_id=audit_run.id,
                    asset_id=asset.id,
                    target_type=validated.target_type,
                    normalized_target=validated.normalized_target,
                    hostname=validated.hostname,
                    scheme=validated.scheme,
                    port=validated.port,
                    resolved_ip=validated.resolved_ip,
                    resolved_ips=validated.resolved_ips,
                    scan_profile=audit_run.scan_profile,
                    emit_log=_emit_module_log,
                )

                t0 = time.monotonic()
                try:
                    result = scanner.run(ctx)
                    duration_ms = int((time.monotonic() - t0) * 1000)

                    if result.skipped_reason:
                        mod_exec.status = ModuleStatus.SKIPPED
                        mod_exec.error_detail = result.skipped_reason
                    else:
                        mod_exec.status = ModuleStatus.COMPLETED
                        completed_count += 1

                    mod_exec.duration_ms = duration_ms
                    mod_exec.raw_output = result.raw_output
                    mod_exec.findings_count = len(result.findings)
                    mod_exec.completed_at = datetime.now(UTC)
                    summary_metadata.update(result.summary_metrics)

                    for draft in result.findings:
                        finding = Finding(
                            audit_run_id=audit_run.id,
                            module_execution_id=mod_exec.id,
                            module_key=module_key,
                            owasp_category_code=draft.owasp_category_code,
                            secondary_owasp_codes=draft.secondary_owasp_codes,
                            title=draft.title[:255],
                            technical_description=draft.technical_description,
                            severity=draft.severity,
                            cvss_score=draft.cvss_score,
                            cwe_id=draft.cwe_id,
                            cve_ids=draft.cve_ids,
                            affected_component=(
                                draft.affected_component[:255]
                                if draft.affected_component
                                else None
                            ),
                            evidence=draft.evidence,
                            remediation_steps=draft.remediation_steps,
                            remediation_snippets=draft.remediation_snippets,
                            references=draft.references,
                            fingerprint_hash=draft.compute_fingerprint(
                                normalized_target=validated.normalized_target,
                                module_key=module_key,
                            ),
                        )
                        db.add(finding)
                        all_persisted_findings.append(finding)

                    db.commit()

                    done_progress = 10 + int((idx / total_modules) * 85)
                    audit_run.progress_percent = done_progress
                    db.commit()

                    publisher.publish(
                        audit_run_id,
                        event_type="MODULE_COMPLETED",
                        level="info",
                        module_key=module_key,
                        progress_percent=done_progress,
                        message=(
                            f"Módulo {scanner.module_name} finalizado en {duration_ms} ms "
                            f"({len(result.findings)} hallazgo(s))."
                        ),
                        data={
                            "status": mod_exec.status.value,
                            "findings_count": len(result.findings),
                            "duration_ms": duration_ms,
                            "summary_metrics": result.summary_metrics,
                        },
                    )
                except SSRFBlockedError as exc:
                    failed_count += 1
                    mod_exec.status = ModuleStatus.FAILED
                    mod_exec.duration_ms = int((time.monotonic() - t0) * 1000)
                    mod_exec.error_detail = exc.message
                    mod_exec.completed_at = datetime.now(UTC)
                    db.commit()
                    record_security_event_sync(
                        db,
                        event_type="SSRF_BLOCKED",
                        severity="critical",
                        actor=audit_run.requested_by,
                        asset_id=asset.id,
                        audit_run_id=audit_run.id,
                        message=f"SSRF bloqueado dentro de {module_key}: {exc.message}",
                        details=exc.details,
                    )
                    publisher.publish(
                        audit_run_id,
                        event_type="MODULE_FAILED",
                        level="error",
                        module_key=module_key,
                        progress_percent=base_progress,
                        message=f"Módulo {module_key} bloqueado por política anti-SSRF: {exc.message}",
                    )
                except Exception as exc:
                    failed_count += 1
                    mod_exec.status = ModuleStatus.FAILED
                    mod_exec.duration_ms = int((time.monotonic() - t0) * 1000)
                    mod_exec.error_detail = str(exc)[:1000]
                    mod_exec.completed_at = datetime.now(UTC)
                    db.commit()
                    record_security_event_sync(
                        db,
                        event_type="MODULE_EXECUTION_ERROR",
                        severity="error",
                        actor=audit_run.requested_by,
                        asset_id=asset.id,
                        audit_run_id=audit_run.id,
                        message=f"Error controlado en módulo {module_key}.",
                        details={"module_key": module_key, "error": str(exc)[:400]},
                    )
                    publisher.publish(
                        audit_run_id,
                        event_type="MODULE_FAILED",
                        level="error",
                        module_key=module_key,
                        progress_percent=base_progress,
                        message=f"Error controlado en módulo {scanner.module_name}: {exc}",
                    )

            # Finalize audit run summary metrics & posture score
            counts = {sev: 0 for sev in SeverityLevel}
            for f in all_persisted_findings:
                counts[f.severity] += 1

            score, grade = _compute_overall_posture(all_persisted_findings, summary_metadata)
            audit_run.total_findings = len(all_persisted_findings)
            audit_run.critical_count = counts[SeverityLevel.CRITICAL]
            audit_run.high_count = counts[SeverityLevel.HIGH]
            audit_run.medium_count = counts[SeverityLevel.MEDIUM]
            audit_run.low_count = counts[SeverityLevel.LOW]
            audit_run.info_count = counts[SeverityLevel.INFO]
            audit_run.security_score = score
            audit_run.security_grade = grade
            audit_run.summary_metadata = summary_metadata
            audit_run.progress_percent = 100
            audit_run.current_stage = "Finalizado"
            audit_run.completed_at = datetime.now(UTC)

            if failed_count == 0:
                audit_run.status = AuditStatus.COMPLETED
            elif completed_count > 0:
                audit_run.status = AuditStatus.PARTIAL_FAILURE
            else:
                audit_run.status = AuditStatus.FAILED
                audit_run.error_message = "Todos los módulos seleccionados fallaron durante la ejecución."

            db.commit()

            record_security_event_sync(
                db,
                event_type="SCAN_COMPLETED",
                severity="info",
                actor=audit_run.requested_by,
                asset_id=asset.id,
                audit_run_id=audit_run.id,
                message=(
                    f"Auditoría finalizada con estado '{audit_run.status.value}' "
                    f"(Calificación {grade}, {audit_run.total_findings} hallazgos)."
                ),
                details={
                    "status": audit_run.status.value,
                    "grade": grade,
                    "score": score,
                    "total_findings": audit_run.total_findings,
                },
            )

            publisher.publish(
                audit_run_id,
                event_type="AUDIT_COMPLETED",
                level="info" if audit_run.status == AuditStatus.COMPLETED else "warning",
                progress_percent=100,
                message=(
                    f"Auditoría finalizada ({audit_run.status.value}) — "
                    f"Calificación: {grade} ({score}/100) | Hallazgos: {audit_run.total_findings}"
                ),
                data={
                    "status": audit_run.status.value,
                    "security_grade": grade,
                    "security_score": score,
                    "total_findings": audit_run.total_findings,
                },
            )

            return {
                "status": audit_run.status.value,
                "audit_run_id": audit_run_id_str,
                "total_findings": audit_run.total_findings,
                "security_grade": grade,
            }
    finally:
        publisher.close()

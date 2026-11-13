"""Unified report context builder shared by JSON and PDF compliance exporters."""

from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

from app.models.audit import AuditRun
from app.models.enums import ReportType, SeverityLevel
from app.models.finding import Finding
from app.models.owasp import OwaspCategory

_SEVERITY_ORDER: tuple[SeverityLevel, ...] = (
    SeverityLevel.CRITICAL,
    SeverityLevel.HIGH,
    SeverityLevel.MEDIUM,
    SeverityLevel.LOW,
    SeverityLevel.INFO,
)

_SEVERITY_LABELS: dict[SeverityLevel, str] = {
    SeverityLevel.CRITICAL: "Crítico",
    SeverityLevel.HIGH: "Alto",
    SeverityLevel.MEDIUM: "Medio",
    SeverityLevel.LOW: "Bajo",
    SeverityLevel.INFO: "Informativo",
}


def _serialize_finding(finding: Finding, owasp_map: dict[str, OwaspCategory]) -> dict[str, Any]:
    cat = owasp_map.get(finding.owasp_category_code)
    return {
        "id": str(finding.id),
        "module_key": finding.module_key,
        "owasp_category_code": finding.owasp_category_code,
        "owasp_category_name": cat.name if cat else finding.owasp_category_code,
        "owasp_category_name_es": cat.name_es if cat else finding.owasp_category_code,
        "secondary_owasp_codes": list(finding.secondary_owasp_codes or []),
        "title": finding.title,
        "technical_description": finding.technical_description,
        "severity": finding.severity.value,
        "severity_label": _SEVERITY_LABELS.get(finding.severity, finding.severity.value),
        "cvss_score": finding.cvss_score,
        "cwe_id": finding.cwe_id,
        "cve_ids": list(finding.cve_ids or []),
        "affected_component": finding.affected_component,
        "evidence": finding.evidence or {},
        "remediation_steps": finding.remediation_steps,
        "remediation_snippets": dict(finding.remediation_snippets or {}),
        "references": list(finding.references or []),
        "status": finding.status.value,
        "fingerprint_hash": finding.fingerprint_hash,
    }


def _build_executive_summary(audit_run: AuditRun) -> str:
    grade = audit_run.security_grade or "N/A"
    score = audit_run.security_score if audit_run.security_score is not None else 0.0
    if audit_run.critical_count > 0:
        risk_posture = (
            f"La postura actual presenta riesgo CRÍTICO ({audit_run.critical_count} hallazgo(s) "
            f"crítico(s) y {audit_run.high_count} alto(s)) que requiere mitigación inmediata."
        )
    elif audit_run.high_count > 0:
        risk_posture = (
            f"Se identificaron {audit_run.high_count} hallazgo(s) de severidad ALTA que deben "
            "priorizarse en el corto plazo para fortalecer la superficie expuesta."
        )
    elif audit_run.medium_count > 0:
        risk_posture = (
            f"No se detectaron hallazgos críticos ni altos, pero existen {audit_run.medium_count} "
            "oportunidad(es) de endurecimiento de severidad media."
        )
    else:
        risk_posture = (
            "La superficie evaluada mantiene una postura defensiva sólida sin hallazgos críticos, "
            "altos ni medios."
        )

    return (
        f"Evaluación ejecutada sobre {audit_run.asset.normalized_target} bajo el perfil "
        f"'{audit_run.scan_profile.value}' con calificación global {grade} ({score}/100) y "
        f"{audit_run.total_findings} hallazgo(s) mapeados al estándar OWASP Top 10:2025. "
        f"{risk_posture}"
    )


def build_report_context(
    audit_run: AuditRun,
    owasp_categories: list[OwaspCategory],
    *,
    report_type: ReportType,
    generated_by: str | None = None,
) -> dict[str, Any]:
    """Assemble structured compliance matrix, grouped findings, and remediation guide."""
    owasp_ordered = sorted(owasp_categories, key=lambda c: c.rank)
    owasp_map = {cat.code: cat for cat in owasp_ordered}

    serialized_findings = [_serialize_finding(f, owasp_map) for f in audit_run.findings]
    severity_rank = {sev.value: idx for idx, sev in enumerate(_SEVERITY_ORDER)}
    serialized_findings.sort(key=lambda item: severity_rank.get(item["severity"], 99))

    # Group findings by severity
    by_severity: dict[str, list[dict[str, Any]]] = {sev.value: [] for sev in _SEVERITY_ORDER}
    for item in serialized_findings:
        by_severity.setdefault(item["severity"], []).append(item)

    findings_by_severity_groups = [
        {
            "severity": sev.value,
            "label": _SEVERITY_LABELS[sev],
            "count": len(by_severity[sev.value]),
            "findings": by_severity[sev.value],
        }
        for sev in _SEVERITY_ORDER
    ]

    # Group findings by OWASP Top 10:2025 category & build compliance matrix
    by_owasp_raw: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in serialized_findings:
        by_owasp_raw[item["owasp_category_code"]].append(item)

    compliance_matrix: list[dict[str, Any]] = []
    findings_by_owasp_groups: list[dict[str, Any]] = []

    for cat in owasp_ordered:
        cat_findings = by_owasp_raw.get(cat.code, [])
        sev_counts = {sev.value: 0 for sev in _SEVERITY_ORDER}
        for cf in cat_findings:
            sev_counts[cf["severity"]] += 1

        if sev_counts["critical"] > 0 or sev_counts["high"] > 0:
            compliance_status = "No Cumple / Riesgo Alto"
            compliance_badge = "critical"
        elif sev_counts["medium"] > 0 or sev_counts["low"] > 0:
            compliance_status = "Parcial / Requiere Endurecimiento"
            compliance_badge = "warning"
        else:
            compliance_status = "Sin Hallazgos Relevantes"
            compliance_badge = "pass"

        compliance_matrix.append(
            {
                "rank": cat.rank,
                "code": cat.code,
                "name": cat.name,
                "name_es": cat.name_es,
                "is_new_in_2025": cat.is_new_in_2025,
                "total_findings": len(cat_findings),
                "severity_counts": sev_counts,
                "compliance_status": compliance_status,
                "compliance_badge": compliance_badge,
                "remediation_guidance": cat.remediation_guidance,
            }
        )

        if cat_findings:
            findings_by_owasp_groups.append(
                {
                    "code": cat.code,
                    "rank": cat.rank,
                    "name": cat.name,
                    "name_es": cat.name_es,
                    "remediation_guidance": cat.remediation_guidance,
                    "count": len(cat_findings),
                    "findings": cat_findings,
                }
            )

    # Prioritized remediation roadmap (step-by-step action items)
    remediation_roadmap = [
        {
            "priority": item["severity_label"],
            "severity": item["severity"],
            "owasp_code": item["owasp_category_code"],
            "title": item["title"],
            "affected_component": item["affected_component"],
            "remediation_steps": item["remediation_steps"],
            "remediation_snippets": item["remediation_snippets"],
        }
        for item in serialized_findings
        if item["severity"] in ("critical", "high", "medium")
    ]

    module_summaries = [
        {
            "module_key": me.module_key,
            "module_name": me.module_name,
            "status": me.status.value,
            "findings_count": me.findings_count,
            "duration_ms": me.duration_ms,
            "error_detail": me.error_detail,
        }
        for me in audit_run.module_executions
    ]

    return {
        "report_metadata": {
            "standard": "OWASP Top 10:2025",
            "report_type": report_type.value,
            "generated_at": datetime.now(UTC).isoformat(),
            "generated_by": generated_by or audit_run.requested_by,
        },
        "audit": {
            "id": str(audit_run.id),
            "status": audit_run.status.value,
            "scan_profile": audit_run.scan_profile.value,
            "selected_modules": list(audit_run.selected_modules or []),
            "security_grade": audit_run.security_grade or "N/A",
            "security_score": audit_run.security_score,
            "total_findings": audit_run.total_findings,
            "severity_counts": {
                "critical": audit_run.critical_count,
                "high": audit_run.high_count,
                "medium": audit_run.medium_count,
                "low": audit_run.low_count,
                "info": audit_run.info_count,
            },
            "requested_by": audit_run.requested_by,
            "authorization_confirmed": audit_run.authorization_confirmed,
            "authorization_statement": audit_run.authorization_statement,
            "ownership_verified_at_launch": audit_run.ownership_verified_at_launch,
            "started_at": audit_run.started_at.isoformat() if audit_run.started_at else None,
            "completed_at": audit_run.completed_at.isoformat() if audit_run.completed_at else None,
        },
        "asset": {
            "id": str(audit_run.asset.id),
            "name": audit_run.asset.name,
            "normalized_target": audit_run.asset.normalized_target,
            "hostname": audit_run.asset.hostname,
            "resolved_ip": audit_run.asset.resolved_ip,
            "environment": audit_run.asset.environment,
            "is_verified": audit_run.asset.is_verified,
            "verification_method": (
                audit_run.asset.verification_method.value
                if audit_run.asset.verification_method
                else None
            ),
        },
        "executive_summary": _build_executive_summary(audit_run),
        "compliance_matrix": compliance_matrix,
        "findings_by_severity": findings_by_severity_groups,
        "findings_by_owasp": findings_by_owasp_groups,
        "remediation_roadmap": remediation_roadmap,
        "module_executions": module_summaries,
    }

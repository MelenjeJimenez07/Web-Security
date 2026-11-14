"""PDF and JSON audit report rendering and integrity-checked storage."""

import hashlib
import json
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.core.config import get_settings
from app.core.exceptions import ResourceNotFoundError, ScannerExecutionError
from app.models.audit import AuditRun
from app.models.enums import ReportFormat, ReportType
from app.models.owasp import OwaspCategory
from app.reports.builder import build_report_context

settings = get_settings()

_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"


@dataclass(frozen=True, slots=True)
class ExportedReportFile:
    file_name: str
    file_path: Path
    file_size_bytes: int
    sha256_checksum: str


def _get_jinja_env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=select_autoescape(enabled_extensions=("html", "xml"), default_for_string=True),
    )


def render_report_html(context: dict[str, Any]) -> str:
    """Render sanitized HTML for PDF conversion (XSS-safe autoescaping enabled)."""
    env = _get_jinja_env()
    template = env.get_template("audit_report.html")
    return template.render(**context)


def resolve_safe_report_path(stored_path: str | Path) -> Path:
    """Verify report file path stays strictly inside configured REPORTS_DIR."""
    base_dir = settings.REPORTS_DIR.resolve()
    target_path = Path(stored_path).resolve()
    if not target_path.is_relative_to(base_dir):
        raise ResourceNotFoundError("Ruta de reporte inválida o fuera del directorio autorizado.")
    return target_path


def _build_docx_table(
    doc: Any,
    headers: list[str],
    rows: list[list[str]],
) -> None:
    """Create a styled table without duplicating row-population logic."""
    table = doc.add_table(rows=1 + len(rows), cols=len(headers))
    table.style = "Table Grid"
    header_cells = table.rows[0].cells
    for idx, title in enumerate(headers):
        header_cells[idx].text = title
        for paragraph in header_cells[idx].paragraphs:
            for run in paragraph.runs:
                run.bold = True

    for row_idx, row_values in enumerate(rows, start=1):
        row_cells = table.rows[row_idx].cells
        for col_idx, val in enumerate(row_values):
            row_cells[col_idx].text = str(val)


def _write_docx_report(output_path: Path, context: dict[str, Any]) -> None:
    """Render an editable Word (.docx) technical/academic report using python-docx."""
    try:
        from docx import Document
        from docx.shared import Cm, Pt
    except Exception as exc:
        raise ScannerExecutionError(
            f"El motor DOCX (python-docx) no está disponible en este entorno: {exc}"
        ) from exc

    doc = Document()
    for section in doc.sections:
        section.top_margin = Cm(2.54)
        section.bottom_margin = Cm(2.54)
        section.left_margin = Cm(2.54)
        section.right_margin = Cm(2.54)

    normal_style = doc.styles["Normal"]
    normal_style.font.name = "Calibri"
    normal_style.font.size = Pt(11)
    normal_style.paragraph_format.line_spacing = 1.5

    asset = context["asset"]
    audit = context["audit"]
    meta = context["report_metadata"]

    # Portada editable
    cover_title = doc.add_heading("INFORME TÉCNICO DE AUDITORÍA DE SEGURIDAD WEB", level=0)
    cover_title.alignment = 1
    subtitle = doc.add_paragraph(
        f"Evaluación Defensiva de Seguridad sobre {asset['name']} ({asset['normalized_target']}) — {meta['standard']}"
    )
    subtitle.alignment = 1
    doc.add_paragraph(
        "Integrantes: [ Integrante 1 ] · [ Integrante 2 ] · [ Integrante 3 ]"
    ).alignment = 1
    doc.add_paragraph(
        f"Responsable del escaneo: {meta['generated_by']} | Fecha UTC: {meta['generated_at']}"
    ).alignment = 1
    doc.add_page_break()

    # 1 & 2. Título, Justificación y Alcance
    doc.add_heading("1. Título del Informe", level=1)
    doc.add_paragraph(
        f"Evaluación defensiva y diagnóstico de superficie expuesta sobre {asset['name']} "
        f"({asset['normalized_target']}) bajo el estándar {meta['standard']}."
    )

    doc.add_heading("2. Justificación y Alcance", level=1)
    doc.add_paragraph(
        "[Completar por el equipo: describa brevemente qué hace la aplicación web evaluada, "
        "qué tipo de datos procesa y por qué es relevante evaluar su seguridad.]"
    )
    _build_docx_table(
        doc,
        ["Parámetro de Alcance", "Valor Registrado"],
        [
            ["Objetivo normalizado", str(asset["normalized_target"])],
            ["IP resuelta", str(asset.get("resolved_ip") or "N/A")],
            ["Entorno", str(asset["environment"])],
            ["Perfil Nmap", str(audit["scan_profile"])],
            ["Autorización confirmada", "Sí" if audit["authorization_confirmed"] else "No"],
            ["Declaración de alcance", str(audit.get("authorization_statement") or "—")],
        ],
    )

    # 3. Fases de la Auditoría
    doc.add_heading("3. Fases de la Auditoría", level=1)
    doc.add_heading("3.1 Reconocimiento (Recolección de Información y Configuración)", level=2)
    doc.add_paragraph(
        f"Calificación global de postura HTTP/TLS: {audit['security_grade']} "
        f"({audit['security_score'] if audit['security_score'] is not None else 'N/A'}/100)."
    )
    mod_rows = [
        [
            f"{m['module_name']} ({m['module_key']})",
            str(m["status"]),
            str(m["findings_count"]),
            str(m["duration_ms"] if m["duration_ms"] is not None else "—"),
        ]
        for m in context.get("module_executions", [])
    ]
    if mod_rows:
        _build_docx_table(doc, ["Módulo", "Estado", "Hallazgos", "Duración (ms)"], mod_rows)

    discovery = context.get("discovery_summary") or {}
    if discovery:
        robots = discovery.get("robots_txt") or {}
        sitemap = discovery.get("sitemap_xml") or {}
        doc.add_paragraph(
            f"Archivos estándar de descubrimiento — robots.txt: "
            f"{'Presente' if robots.get('present') else 'No detectado'} "
            f"(rutas sensibles en Disallow: {len(robots.get('sensitive_disallows') or [])}); "
            f"sitemap.xml: {'Presente' if sitemap.get('present') else 'No detectado'} "
            f"(URLs listadas: {sitemap.get('url_count', 0)})."
        )

    # 3.2 Tabla de Vulnerabilidades / Hallazgos (CVE, CVSS y OWASP)
    doc.add_heading("3.2 Análisis de Vulnerabilidades (OWASP Top 10:2025, CVE y CVSS)", level=2)
    vuln_rows: list[list[str]] = []
    idx_counter = 1
    for group in context.get("findings_by_owasp", []):
        for f in group.get("findings", []):
            cve_or_cwe = ", ".join(f["cve_ids"]) if f.get("cve_ids") else (f.get("cwe_id") or "—")
            if f.get("cvss_score") is not None and f.get("cvss_vector"):
                cvss_text = f"{f['cvss_score']} ({f['cvss_vector']})"
            elif f.get("cvss_score") is not None:
                cvss_text = str(f["cvss_score"])
            else:
                cvss_text = "Evaluación cualitativa"
            vuln_rows.append(
                [
                    f"H{idx_counter}",
                    str(f["title"]),
                    f"{f['owasp_category_code']} — {f['owasp_category_name_es']}",
                    cve_or_cwe,
                    cvss_text,
                    str(f["severity_label"]),
                ]
            )
            idx_counter += 1

    if vuln_rows:
        _build_docx_table(
            doc,
            ["#", "Hallazgo", "OWASP Top 10:2025", "CVE / CWE", "CVSS (Score / Vector)", "Severidad"],
            vuln_rows,
        )
    else:
        doc.add_paragraph("No se registraron hallazgos técnicos en esta ejecución.")

    # 3.3 Sección explícitamente reservada para validación manual ética del equipo
    doc.add_heading("3.3 Validación y Verificación Manual Autorizada (Alcance del Equipo)", level=2)
    doc.add_paragraph(
        "Nota de seguridad: WebSec Audit Dashboard ejecuta únicamente reconocimiento controlado, "
        "auditoría pasiva/de configuración y correlación de CVEs; no realiza explotación automatizada. "
        "[Completar manualmente por el estudiante con capturas y evidencias de verificación autorizada si aplica.]"
    )

    # 3.4 Matriz de Riesgo 5x5 y Mitigación
    doc.add_heading("3.4 Análisis de Riesgos y Mitigación", level=2)
    risk_matrix = context.get("risk_matrix")
    if risk_matrix:
        matrix_headers = ["Probabilidad \\ Impacto"] + [
            f"{imp['label']} ({imp['level']})" for imp in risk_matrix["impact_levels"]
        ]
        matrix_rows = [
            [f"{row['label']} ({row['likelihood']})"]
            + [f"{cell['count']} ({cell['zone_label']})" for cell in row["cells"]]
            for row in risk_matrix["rows"]
        ]
        _build_docx_table(doc, matrix_headers, matrix_rows)

    roadmap_rows = [
        [
            str(step["priority"]),
            str(step["owasp_code"]),
            str(step["title"]),
            str(step["remediation_steps"]),
        ]
        for step in context.get("remediation_roadmap", [])
    ]
    if roadmap_rows:
        doc.add_paragraph("Plan de Mitigación Priorizada:")
        _build_docx_table(doc, ["Prioridad", "OWASP", "Hallazgo", "Acción Recomendada"], roadmap_rows)

    # 4. Resultados
    doc.add_heading("4. Resultados", level=1)
    doc.add_paragraph(context["executive_summary"])
    sev_rows = [
        [str(g["label"]), str(g["count"])] for g in context.get("findings_by_severity", [])
    ]
    _build_docx_table(doc, ["Severidad", "Cantidad"], sev_rows)

    comp_rows = [
        [
            str(r["code"]),
            str(r["name_es"]),
            str(r["total_findings"]),
            str(r["compliance_status"]),
        ]
        for r in context.get("compliance_matrix", [])
    ]
    doc.add_paragraph("Matriz de Cumplimiento OWASP Top 10:2025:")
    _build_docx_table(doc, ["Código", "Categoría", "Hallazgos", "Estado"], comp_rows)

    # 5. Conclusiones
    doc.add_heading("5. Conclusiones", level=1)
    doc.add_paragraph(
        "[Completar por el equipo: reflexiones propias sobre hallazgos prioritarios, "
        "importancia del enfoque DevSecOps y lecciones aprendidas.]"
    )

    # 6. Bibliografía APA 7.ª ed.
    doc.add_heading("6. Bibliografía (Normas APA 7.ª edición)", level=1)
    references_apa = [
        "Congreso de Colombia. (2009). Ley 1273 de 2009, de protección de la información y de los datos. Diario Oficial.",
        "FIRST. (2019). Common Vulnerability Scoring System v3.1: Specification Document. https://www.first.org/cvss/",
        "National Institute of Standards and Technology. (s. f.). National Vulnerability Database (NVD). https://nvd.nist.gov/",
        "OWASP Foundation. (2025). OWASP Top 10:2025. https://owasp.org/Top10/2025/",
    ]
    for ref in references_apa:
        p = doc.add_paragraph(ref)
        p.paragraph_format.left_indent = Cm(1.27)
        p.paragraph_format.first_line_indent = Cm(-1.27)

    doc.save(str(output_path))


def generate_audit_report_file(
    audit_run: AuditRun,
    owasp_categories: list[OwaspCategory],
    *,
    report_format: ReportFormat,
    report_type: ReportType,
    generated_by: str | None = None,
    output_dir: Path | None = None,
) -> ExportedReportFile:
    """Render PDF, JSON, or DOCX report to disk and return file metadata + SHA-256 digest."""
    target_dir = (output_dir or settings.REPORTS_DIR).resolve()
    target_dir.mkdir(parents=True, exist_ok=True)

    context = build_report_context(
        audit_run,
        owasp_categories,
        report_type=report_type,
        generated_by=generated_by,
    )

    short_uid = uuid.uuid4().hex[:8]
    file_name = (
        f"websec-audit-{str(audit_run.id)[:8]}-{report_type.value}-{short_uid}.{report_format.value}"
    )
    output_path = (target_dir / file_name).resolve()
    if not output_path.is_relative_to(target_dir):
        raise ScannerExecutionError("Ruta de salida de reporte inválida.")

    if report_format == ReportFormat.JSON:
        raw_bytes = json.dumps(context, indent=2, ensure_ascii=False, default=str).encode("utf-8")
        output_path.write_bytes(raw_bytes)
    elif report_format == ReportFormat.DOCX:
        _write_docx_report(output_path, context)
        raw_bytes = output_path.read_bytes()
    else:
        html_content = render_report_html(context)
        try:
            import weasyprint  # Lazy import so tests/environments without Pango can still import cleanly
        except Exception as exc:
            raise ScannerExecutionError(
                f"El motor PDF WeasyPrint no está disponible en este entorno: {exc}"
            ) from exc

        weasyprint.HTML(string=html_content).write_pdf(target=str(output_path))
        raw_bytes = output_path.read_bytes()

    checksum = hashlib.sha256(raw_bytes).hexdigest()
    return ExportedReportFile(
        file_name=file_name,
        file_path=output_path,
        file_size_bytes=len(raw_bytes),
        sha256_checksum=checksum,
    )

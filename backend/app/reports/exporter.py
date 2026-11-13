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


def generate_audit_report_file(
    audit_run: AuditRun,
    owasp_categories: list[OwaspCategory],
    *,
    report_format: ReportFormat,
    report_type: ReportType,
    generated_by: str | None = None,
    output_dir: Path | None = None,
) -> ExportedReportFile:
    """Render PDF or JSON report to disk and return file metadata + SHA-256 digest."""
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

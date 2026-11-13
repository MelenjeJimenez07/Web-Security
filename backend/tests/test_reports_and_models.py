"""Unit tests for OWASP Top 10:2025 models, DB constraints, and PDF/JSON reporting."""

import hashlib
import json
import sys
import types
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.exceptions import ResourceNotFoundError
from app.db.seed import seed_owasp_categories
from app.models.asset import Asset
from app.models.audit import AuditModuleExecution, AuditRun
from app.models.enums import (
    AuditStatus,
    ModuleStatus,
    ReportFormat,
    ReportType,
    ScanProfile,
    SeverityLevel,
    TargetType,
)
from app.models.finding import Finding
from app.models.owasp import OwaspCategory
from app.reports.builder import build_report_context
from app.reports.exporter import (
    generate_audit_report_file,
    render_report_html,
    resolve_safe_report_path,
)


def _create_sample_audit(db_session: Session) -> AuditRun:
    asset = Asset(
        name="Portal Demo <script>alert(1)</script>",
        target_type=TargetType.URL,
        normalized_target="https://example.com",
        hostname="example.com",
        scheme="https",
        port=443,
        resolved_ip="93.184.216.34",
        is_verified=True,
    )
    db_session.add(asset)
    db_session.flush()

    run = AuditRun(
        asset_id=asset.id,
        status=AuditStatus.COMPLETED,
        scan_profile=ScanProfile.QUICK,
        selected_modules=["http_headers", "ssl_tls"],
        authorization_confirmed=True,
        authorization_statement="Autorización verificada para entorno de pruebas.",
        requested_by="sec-architect",
        ownership_verified_at_launch=True,
        progress_percent=100,
        security_grade="B",
        security_score=74.5,
        total_findings=2,
        critical_count=0,
        high_count=1,
        medium_count=1,
        low_count=0,
        info_count=0,
    )
    db_session.add(run)
    db_session.flush()

    mod = AuditModuleExecution(
        audit_run_id=run.id,
        module_key="http_headers",
        module_name="Auditoría de Cabeceras HTTP",
        status=ModuleStatus.COMPLETED,
        findings_count=2,
        duration_ms=210,
    )
    db_session.add(mod)
    db_session.flush()

    db_session.add_all(
        [
            Finding(
                audit_run_id=run.id,
                module_execution_id=mod.id,
                module_key="http_headers",
                owasp_category_code="A05:2025",
                secondary_owasp_codes=["A02:2025"],
                title="Cabecera Content-Security-Policy (CSP) ausente",
                technical_description="Sin CSP frente a XSS.",
                severity=SeverityLevel.HIGH,
                cwe_id="CWE-693",
                affected_component="https://example.com",
                remediation_steps="Configurar CSP estricta.",
                remediation_snippets={"nginx": "add_header Content-Security-Policy \"default-src 'self';\";"},
                fingerprint_hash="a" * 64,
            ),
            Finding(
                audit_run_id=run.id,
                module_execution_id=mod.id,
                module_key="http_headers",
                owasp_category_code="A02:2025",
                secondary_owasp_codes=[],
                title="Cabecera Strict-Transport-Security (HSTS) ausente",
                technical_description="Falta HSTS.",
                severity=SeverityLevel.MEDIUM,
                cwe_id="CWE-319",
                affected_component="https://example.com",
                remediation_steps="Habilitar HSTS max-age=31536000.",
                fingerprint_hash="b" * 64,
            ),
        ]
    )
    db_session.commit()
    db_session.refresh(run)
    return run


def test_owasp_catalog_seeded_and_idempotent(db_session: Session) -> None:
    categories = db_session.scalars(select(OwaspCategory).order_by(OwaspCategory.rank.asc())).all()
    assert len(categories) == 10
    assert [c.code for c in categories] == [f"A{i:02d}:2025" for i in range(1, 11)]
    assert seed_owasp_categories(db_session) == 0


def test_audit_run_rejects_unconfirmed_authorization(db_session: Session) -> None:
    asset = Asset(
        name="Blocked Asset",
        target_type=TargetType.DOMAIN,
        normalized_target="blocked.example.com",
        hostname="blocked.example.com",
    )
    db_session.add(asset)
    db_session.flush()

    bad_run = AuditRun(
        asset_id=asset.id,
        status=AuditStatus.PENDING,
        scan_profile=ScanProfile.QUICK,
        selected_modules=["dns_passive"],
        authorization_confirmed=False,
        authorization_statement="Sin autorización",
        requested_by="tester",
    )
    db_session.add(bad_run)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_report_builder_html_autoescape_and_json_export(
    db_session: Session, tmp_path: Path
) -> None:
    run = _create_sample_audit(db_session)
    categories = list(
        db_session.scalars(select(OwaspCategory).order_by(OwaspCategory.rank.asc())).all()
    )

    context = build_report_context(run, categories, report_type=ReportType.FULL)
    assert len(context["compliance_matrix"]) == 10
    assert context["audit"]["security_grade"] == "B"
    assert len(context["remediation_roadmap"]) == 2

    # Ensure HTML template escapes malicious asset name (<script>)
    rendered_html = render_report_html(context)
    assert "<script>alert(1)</script>" not in rendered_html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in rendered_html

    # Test JSON report export & SHA-256 verification
    json_report = generate_audit_report_file(
        run,
        categories,
        report_format=ReportFormat.JSON,
        report_type=ReportType.FULL,
        output_dir=tmp_path,
    )
    assert json_report.file_path.exists()
    raw_bytes = json_report.file_path.read_bytes()
    assert json_report.sha256_checksum == hashlib.sha256(raw_bytes).hexdigest()
    parsed = json.loads(raw_bytes.decode("utf-8"))
    assert parsed["compliance_matrix"][0]["code"] == "A01:2025"


def test_pdf_export_and_path_traversal_guard(
    db_session: Session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = _create_sample_audit(db_session)
    categories = list(
        db_session.scalars(select(OwaspCategory).order_by(OwaspCategory.rank.asc())).all()
    )

    class FakeWeasyHtml:
        def __init__(self, string: str) -> None:
            self._html = string

        def write_pdf(self, target: str) -> None:
            assert "OWASP Top 10:2025" in self._html
            Path(target).write_bytes(b"%PDF-1.4\n%MockedWeasyPrintPDF\n")

    fake_weasyprint = types.ModuleType("weasyprint")
    fake_weasyprint.HTML = FakeWeasyHtml  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "weasyprint", fake_weasyprint)

    pdf_report = generate_audit_report_file(
        run,
        categories,
        report_format=ReportFormat.PDF,
        report_type=ReportType.EXECUTIVE,
        output_dir=tmp_path,
    )
    assert pdf_report.file_path.suffix == ".pdf"
    assert pdf_report.file_path.read_bytes().startswith(b"%PDF-1.4")

    # Path traversal check
    with pytest.raises(ResourceNotFoundError):
        resolve_safe_report_path("/etc/passwd")

"""API tests for deleting individual audit runs via DELETE /api/v1/audits/{audit_id}."""

import uuid
from collections.abc import AsyncGenerator
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

import app.reports.exporter as exporter_module
from app.db.session import get_async_db
from app.main import app
from app.models.asset import Asset
from app.models.audit import AuditModuleExecution, AuditRun
from app.models.audit_log import SecurityEventLog
from app.models.enums import (
    AuditStatus,
    ModuleStatus,
    ReportFormat,
    ReportType,
    ScanProfile,
    TargetType,
)
from app.models.report import AuditReport


class _SyncSessionAsyncAdapter:
    """Minimal async-compatible facade running on the same event-loop thread."""

    def __init__(self, sync_session: Session) -> None:
        self._sync = sync_session

    def add(self, instance: object) -> None:
        self._sync.add(instance)

    async def scalar(self, statement: object) -> object:
        return self._sync.scalar(statement)

    async def get(self, entity: object, ident: object) -> object:
        return self._sync.get(entity, ident)

    async def delete(self, instance: object) -> None:
        self._sync.delete(instance)

    async def commit(self) -> None:
        self._sync.commit()

    async def refresh(self, instance: object) -> None:
        self._sync.refresh(instance)


@pytest.fixture
async def async_api_client(db_session: Session) -> AsyncGenerator[httpx.AsyncClient, None]:
    """Yield an ASGI-backed AsyncClient sharing the in-thread SQLite test session."""

    async def _override_async_db() -> AsyncGenerator[_SyncSessionAsyncAdapter, None]:
        yield _SyncSessionAsyncAdapter(db_session)

    app.dependency_overrides[get_async_db] = _override_async_db
    transport = httpx.ASGITransport(app=app)
    try:
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            yield client
    finally:
        app.dependency_overrides.clear()


def _seed_asset_and_run(
    db_session: Session,
    *,
    status: AuditStatus = AuditStatus.COMPLETED,
) -> tuple[Asset, AuditRun]:
    asset = Asset(
        name="AuraWear Lab",
        target_type=TargetType.URL,
        normalized_target=f"http://aurawear-{uuid.uuid4().hex[:8]}.example.com",
        hostname="aurawear.example.com",
        scheme="http",
        port=80,
        resolved_ip="93.184.216.34",
        is_verified=True,
    )
    db_session.add(asset)
    db_session.flush()

    run = AuditRun(
        asset_id=asset.id,
        status=status,
        scan_profile=ScanProfile.QUICK,
        selected_modules=["http_headers"],
        authorization_confirmed=True,
        authorization_statement="Autorizado para pruebas de laboratorio.",
        requested_by="presenter",
        ownership_verified_at_launch=True,
        progress_percent=100 if status == AuditStatus.COMPLETED else 35,
    )
    db_session.add(run)
    db_session.commit()
    return asset, run


async def test_delete_completed_audit_cleans_children_reports_and_logs_event(
    async_api_client: httpx.AsyncClient,
    db_session: Session,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    asset, run = _seed_asset_and_run(db_session, status=AuditStatus.COMPLETED)

    monkeypatch.setattr(exporter_module.settings, "REPORTS_DIR", tmp_path)
    report_file = tmp_path / "audit_sample.json"
    report_file.write_text('{"status": "ok"}', encoding="utf-8")

    mod = AuditModuleExecution(
        audit_run_id=run.id,
        module_key="http_headers",
        module_name="Cabeceras HTTP",
        status=ModuleStatus.COMPLETED,
        findings_count=0,
    )
    report = AuditReport(
        audit_run_id=run.id,
        format=ReportFormat.JSON,
        report_type=ReportType.FULL,
        file_name=report_file.name,
        file_path=str(report_file),
        file_size_bytes=report_file.stat().st_size,
        sha256_checksum="a" * 64,
        generated_by="presenter",
    )
    prior_event = SecurityEventLog(
        event_type="AUDIT_STARTED",
        severity="info",
        actor="presenter",
        asset_id=asset.id,
        audit_run_id=run.id,
        message="Inicio de auditoría de prueba.",
        details={},
    )
    db_session.add_all([mod, report, prior_event])
    db_session.commit()

    response = await async_api_client.delete(f"/api/v1/audits/{run.id}")

    assert response.status_code == 204
    assert not report_file.exists()

    db_session.expire_all()
    assert db_session.get(AuditRun, run.id) is None
    assert db_session.get(AuditModuleExecution, mod.id) is None
    assert db_session.get(AuditReport, report.id) is None
    assert db_session.get(Asset, asset.id) is not None

    preserved_prior = db_session.get(SecurityEventLog, prior_event.id)
    assert preserved_prior is not None
    assert preserved_prior.audit_run_id is None

    deleted_event = db_session.scalar(
        select(SecurityEventLog).where(SecurityEventLog.event_type == "AUDIT_DELETED")
    )
    assert deleted_event is not None
    assert deleted_event.asset_id == asset.id
    assert deleted_event.details["deleted_audit_run_id"] == str(run.id)


async def test_delete_running_audit_returns_conflict(
    async_api_client: httpx.AsyncClient,
    db_session: Session,
) -> None:
    _asset, run = _seed_asset_and_run(db_session, status=AuditStatus.RUNNING)

    response = await async_api_client.delete(f"/api/v1/audits/{run.id}")

    assert response.status_code == 409
    assert db_session.get(AuditRun, run.id) is not None


async def test_delete_missing_audit_returns_not_found(
    async_api_client: httpx.AsyncClient,
) -> None:
    response = await async_api_client.delete(f"/api/v1/audits/{uuid.uuid4()}")
    assert response.status_code == 404

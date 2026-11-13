"""Shared pytest fixtures for database, OWASP catalog seeding, and scanner contexts."""

import uuid
from collections.abc import Generator
from typing import Any

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from app.db.base import Base
from app.db.seed import seed_owasp_categories
from app.models.enums import ScanProfile, TargetType
from app.scanners.base import ScanContext


@pytest.fixture
def db_session() -> Generator[Session, None, None]:
    """Yield an isolated in-memory SQLite session with all tables and OWASP 2025 catalog."""
    engine = create_engine("sqlite:///:memory:", future=True)

    @event.listens_for(engine, "connect")
    def _enable_sqlite_fks(dbapi_conn: Any, _conn_record: Any) -> None:
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(engine)
    TestingSession = sessionmaker(bind=engine, class_=Session, expire_on_commit=False)

    with TestingSession() as session:
        seed_owasp_categories(session)
        yield session


def make_scan_context(
    *,
    target_type: TargetType = TargetType.URL,
    normalized_target: str = "https://example.com",
    hostname: str = "example.com",
    scheme: str | None = "https",
    port: int | None = 443,
    resolved_ip: str = "93.184.216.34",
    scan_profile: ScanProfile = ScanProfile.QUICK,
    logs: list[tuple[str, str]] | None = None,
) -> ScanContext:
    """Create a ScanContext fixture for unit-testing audit scanner plugins."""
    captured = logs if logs is not None else []
    return ScanContext(
        audit_run_id=uuid.uuid4(),
        asset_id=uuid.uuid4(),
        target_type=target_type,
        normalized_target=normalized_target,
        hostname=hostname,
        scheme=scheme,
        port=port,
        resolved_ip=resolved_ip,
        resolved_ips=(resolved_ip,),
        scan_profile=scan_profile,
        emit_log=lambda level, msg, _data=None: captured.append((level, msg)),
    )

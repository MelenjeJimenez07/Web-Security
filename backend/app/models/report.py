"""Generated PDF and JSON audit report metadata model."""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, UUIDPrimaryKeyMixin, pg_enum
from app.models.enums import ReportFormat, ReportType

if TYPE_CHECKING:
    from app.models.audit import AuditRun


class AuditReport(UUIDPrimaryKeyMixin, Base):
    """Metadata and integrity hash for exported PDF/JSON compliance reports."""

    __tablename__ = "audit_reports"

    audit_run_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("audit_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    format: Mapped[ReportFormat] = mapped_column(
        pg_enum(ReportFormat, "report_format"),
        nullable=False,
    )
    report_type: Mapped[ReportType] = mapped_column(
        pg_enum(ReportType, "report_type"),
        default=ReportType.FULL,
        nullable=False,
    )
    file_name: Mapped[str] = mapped_column(String(255), nullable=False)
    file_path: Mapped[str] = mapped_column(String(512), nullable=False)
    file_size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    sha256_checksum: Mapped[str] = mapped_column(String(64), nullable=False)
    generated_by: Mapped[str | None] = mapped_column(String(150), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    audit_run: Mapped["AuditRun"] = relationship(back_populates="reports")

    def __repr__(self) -> str:
        return f"<AuditReport(file={self.file_name!r}, format={self.format.value})>"

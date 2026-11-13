"""AuditRun and AuditModuleExecution models tracking asynchronous security scans."""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, JSONVariant, TimestampMixin, UUIDPrimaryKeyMixin, pg_enum
from app.models.enums import AuditStatus, ModuleStatus, ScanProfile

if TYPE_CHECKING:
    from app.models.asset import Asset
    from app.models.audit_log import SecurityEventLog
    from app.models.finding import Finding
    from app.models.report import AuditReport


class AuditRun(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Represents a single orchestrated security audit execution against an Asset."""

    __tablename__ = "audit_runs"
    __table_args__ = (
        CheckConstraint("authorization_confirmed = true", name="authorization_confirmed_true"),
        CheckConstraint(
            "progress_percent >= 0 AND progress_percent <= 100",
            name="progress_percent_bounds",
        ),
    )

    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    celery_task_id: Mapped[str | None] = mapped_column(String(255), index=True, nullable=True)
    status: Mapped[AuditStatus] = mapped_column(
        pg_enum(AuditStatus, "audit_status"),
        default=AuditStatus.PENDING,
        nullable=False,
        index=True,
    )
    scan_profile: Mapped[ScanProfile] = mapped_column(
        pg_enum(ScanProfile, "scan_profile"),
        default=ScanProfile.QUICK,
        nullable=False,
    )
    selected_modules: Mapped[list[str]] = mapped_column(
        JSONVariant,
        default=list,
        nullable=False,
    )

    # Authorization & ethical audit governance
    authorization_confirmed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    authorization_statement: Mapped[str] = mapped_column(Text, nullable=False)
    requested_by: Mapped[str] = mapped_column(String(150), nullable=False)
    requester_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    ownership_verified_at_launch: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )

    # Real-time telemetry & scoring
    progress_percent: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    current_stage: Mapped[str | None] = mapped_column(String(120), nullable=True)
    security_grade: Mapped[str | None] = mapped_column(String(4), nullable=True)
    security_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Aggregated finding counts
    total_findings: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    critical_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    high_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    medium_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    low_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    info_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    summary_metadata: Mapped[dict[str, Any]] = mapped_column(
        JSONVariant,
        default=dict,
        nullable=False,
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    asset: Mapped["Asset"] = relationship(back_populates="audit_runs")
    module_executions: Mapped[list["AuditModuleExecution"]] = relationship(
        back_populates="audit_run",
        cascade="all, delete-orphan",
        order_by="AuditModuleExecution.created_at.asc()",
    )
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="audit_run",
        cascade="all, delete-orphan",
        order_by="Finding.created_at.asc()",
    )
    reports: Mapped[list["AuditReport"]] = relationship(
        back_populates="audit_run",
        cascade="all, delete-orphan",
        order_by="AuditReport.created_at.desc()",
    )
    security_logs: Mapped[list["SecurityEventLog"]] = relationship(
        back_populates="audit_run",
        passive_deletes=True,
    )

    def __repr__(self) -> str:
        return f"<AuditRun(id={self.id}, asset_id={self.asset_id}, status={self.status.value})>"


class AuditModuleExecution(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Per-plugin execution state and raw structured output within an AuditRun."""

    __tablename__ = "audit_module_executions"
    __table_args__ = (
        UniqueConstraint("audit_run_id", "module_key", name="uq_audit_module_run_key"),
    )

    audit_run_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("audit_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    module_key: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    module_name: Mapped[str] = mapped_column(String(150), nullable=False)
    status: Mapped[ModuleStatus] = mapped_column(
        pg_enum(ModuleStatus, "module_status"),
        default=ModuleStatus.PENDING,
        nullable=False,
    )
    findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    raw_output: Mapped[dict[str, Any]] = mapped_column(
        JSONVariant,
        default=dict,
        nullable=False,
    )
    error_detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    audit_run: Mapped["AuditRun"] = relationship(back_populates="module_executions")
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="module_execution",
        passive_deletes=True,
    )

    def __repr__(self) -> str:
        return (
            f"<AuditModuleExecution(run={self.audit_run_id}, module={self.module_key!r}, "
            f"status={self.status.value})>"
        )

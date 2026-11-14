"""Structured security Finding model mapped against OWASP Top 10:2025."""

import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, JSONVariant, TimestampMixin, UUIDPrimaryKeyMixin, pg_enum
from app.models.enums import FindingStatus, SeverityLevel

if TYPE_CHECKING:
    from app.models.audit import AuditModuleExecution, AuditRun
    from app.models.owasp import OwaspCategory


class Finding(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Structured vulnerability or misconfiguration finding linked to OWASP Top 10:2025."""

    __tablename__ = "findings"

    audit_run_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("audit_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    module_execution_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("audit_module_executions.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    module_key: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    owasp_category_code: Mapped[str] = mapped_column(
        ForeignKey("owasp_categories.code", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    secondary_owasp_codes: Mapped[list[str]] = mapped_column(
        JSONVariant,
        default=list,
        nullable=False,
    )

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    technical_description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[SeverityLevel] = mapped_column(
        pg_enum(SeverityLevel, "severity_level"),
        nullable=False,
        index=True,
    )
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(128), nullable=True)
    cwe_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    cve_ids: Mapped[list[str]] = mapped_column(JSONVariant, default=list, nullable=False)
    affected_component: Mapped[str | None] = mapped_column(String(255), nullable=True)

    evidence: Mapped[dict[str, Any]] = mapped_column(JSONVariant, default=dict, nullable=False)
    remediation_steps: Mapped[str] = mapped_column(Text, nullable=False)
    remediation_snippets: Mapped[dict[str, str]] = mapped_column(
        JSONVariant,
        default=dict,
        nullable=False,
    )
    references: Mapped[list[str]] = mapped_column(JSONVariant, default=list, nullable=False)

    fingerprint_hash: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    status: Mapped[FindingStatus] = mapped_column(
        pg_enum(FindingStatus, "finding_status"),
        default=FindingStatus.OPEN,
        nullable=False,
        index=True,
    )

    audit_run: Mapped["AuditRun"] = relationship(back_populates="findings")
    module_execution: Mapped["AuditModuleExecution | None"] = relationship(
        back_populates="findings"
    )
    owasp_category: Mapped["OwaspCategory"] = relationship(back_populates="findings")

    def __repr__(self) -> str:
        return (
            f"<Finding(id={self.id}, owasp={self.owasp_category_code!r}, "
            f"severity={self.severity.value}, title={self.title!r})>"
        )

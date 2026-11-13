"""Structured security audit log model (OWASP A09:2025 compliance)."""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import DateTime, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, JSONVariant, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.asset import Asset
    from app.models.audit import AuditRun


class SecurityEventLog(UUIDPrimaryKeyMixin, Base):
    """Append-only structured security event record for auditability and alerting."""

    __tablename__ = "security_event_logs"

    audit_run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("audit_runs.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    event_type: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), default="info", nullable=False)
    actor: Mapped[str | None] = mapped_column(String(150), nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(JSONVariant, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
    )

    audit_run: Mapped["AuditRun | None"] = relationship(back_populates="security_logs")
    asset: Mapped["Asset | None"] = relationship(back_populates="security_logs")

    def __repr__(self) -> str:
        return f"<SecurityEventLog(event={self.event_type!r}, severity={self.severity!r})>"

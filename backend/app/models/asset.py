"""Auditable target Asset and Domain Ownership Verification models."""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin, pg_enum
from app.models.enums import TargetType, VerificationMethod, VerificationStatus

if TYPE_CHECKING:
    from app.models.audit import AuditRun
    from app.models.audit_log import SecurityEventLog


class Asset(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Target host, domain, or web origin registered for security auditing."""

    __tablename__ = "assets"

    name: Mapped[str] = mapped_column(String(150), nullable=False)
    target_type: Mapped[TargetType] = mapped_column(
        pg_enum(TargetType, "target_type"),
        nullable=False,
    )
    normalized_target: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        index=True,
        nullable=False,
    )
    hostname: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    scheme: Mapped[str | None] = mapped_column(String(16), nullable=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    resolved_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    environment: Mapped[str] = mapped_column(String(50), default="production", nullable=False)
    owner_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Ownership verification state
    is_verified: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        index=True,
    )
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    verification_method: Mapped[VerificationMethod | None] = mapped_column(
        pg_enum(VerificationMethod, "verification_method"),
        nullable=True,
    )

    verifications: Mapped[list["DomainVerification"]] = relationship(
        back_populates="asset",
        cascade="all, delete-orphan",
        order_by="DomainVerification.created_at.desc()",
    )
    audit_runs: Mapped[list["AuditRun"]] = relationship(
        back_populates="asset",
        cascade="all, delete-orphan",
        order_by="AuditRun.created_at.desc()",
    )
    security_logs: Mapped[list["SecurityEventLog"]] = relationship(
        back_populates="asset",
        passive_deletes=True,
    )

    def __repr__(self) -> str:
        return f"<Asset(id={self.id}, target={self.normalized_target!r}, verified={self.is_verified})>"


class DomainVerification(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Challenge-response proof of domain ownership via DNS TXT or .well-known file."""

    __tablename__ = "domain_verifications"

    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    method: Mapped[VerificationMethod] = mapped_column(
        pg_enum(VerificationMethod, "verification_method"),
        nullable=False,
    )
    challenge_token: Mapped[str] = mapped_column(
        String(128),
        unique=True,
        index=True,
        nullable=False,
    )
    expected_location: Mapped[str] = mapped_column(String(512), nullable=False)
    status: Mapped[VerificationStatus] = mapped_column(
        pg_enum(VerificationStatus, "verification_status"),
        default=VerificationStatus.PENDING,
        nullable=False,
        index=True,
    )
    last_checked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    asset: Mapped["Asset"] = relationship(back_populates="verifications")

    def __repr__(self) -> str:
        return (
            f"<DomainVerification(asset_id={self.asset_id}, method={self.method.value}, "
            f"status={self.status.value})>"
        )

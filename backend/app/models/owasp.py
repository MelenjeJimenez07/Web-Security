"""OWASP Top 10:2025 reference catalog model."""

from typing import TYPE_CHECKING

from sqlalchemy import Boolean, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, JSONVariant, TimestampMixin

if TYPE_CHECKING:
    from app.models.finding import Finding


class OwaspCategory(TimestampMixin, Base):
    """Catalog of official OWASP Top 10:2025 risk categories."""

    __tablename__ = "owasp_categories"

    code: Mapped[str] = mapped_column(String(16), primary_key=True)
    rank: Mapped[int] = mapped_column(Integer, unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    name_es: Mapped[str] = mapped_column(String(150), nullable=False)
    short_summary: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    remediation_guidance: Mapped[str] = mapped_column(Text, nullable=False)
    cwe_examples: Mapped[list[str]] = mapped_column(JSONVariant, default=list, nullable=False)
    is_new_in_2025: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    reference_url: Mapped[str] = mapped_column(String(512), nullable=False)

    findings: Mapped[list["Finding"]] = relationship(
        back_populates="owasp_category",
        passive_deletes=True,
    )

    def __repr__(self) -> str:
        return f"<OwaspCategory(code={self.code!r}, name={self.name!r})>"

"""SQLAlchemy 2.0 DeclarativeBase, deterministic naming conventions, and reusable mixins."""

import enum
import uuid
from datetime import datetime

from sqlalchemy import JSON, DateTime, Enum, MetaData, Uuid, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# Deterministic constraint naming convention for clean Alembic migrations
NAMING_CONVENTION: dict[str, str] = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

# Use native JSONB in PostgreSQL and fallback to generic JSON for local SQLite unit tests
JSONVariant = JSON().with_variant(JSONB(), "postgresql")


def pg_enum(enum_cls: type[enum.Enum], name: str) -> Enum:
    """Create a SQLAlchemy Enum persisting enum values rather than member names."""
    return Enum(
        enum_cls,
        name=name,
        values_callable=lambda obj: [member.value for member in obj],
        native_enum=True,
        create_constraint=True,
    )


class Base(DeclarativeBase):
    """Root declarative base for all ORM models."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class UUIDPrimaryKeyMixin:
    """Adds a UUID primary key column."""

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )


class TimestampMixin:
    """Adds UTC timezone-aware created_at and updated_at columns."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

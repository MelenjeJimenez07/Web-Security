"""Structured JSON logging and persistent security event auditing (OWASP A09:2025)."""

import logging
import sys
import uuid
from typing import Any

import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.audit_log import SecurityEventLog

settings = get_settings()


def configure_logging() -> None:
    """Configure structlog and standard library logging to emit structured JSON."""
    log_level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)

    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=log_level,
        force=True,
    )

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str = "websec") -> structlog.stdlib.BoundLogger:
    """Return a bound structlog logger instance."""
    return structlog.get_logger(name)


async def record_security_event_async(
    db: AsyncSession,
    *,
    event_type: str,
    message: str,
    severity: str = "info",
    actor: str | None = None,
    source_ip: str | None = None,
    asset_id: uuid.UUID | None = None,
    audit_run_id: uuid.UUID | None = None,
    details: dict[str, Any] | None = None,
    commit: bool = True,
) -> SecurityEventLog:
    """Persist a structured security audit event from an async FastAPI context."""
    entry = SecurityEventLog(
        event_type=event_type,
        severity=severity,
        actor=actor,
        source_ip=source_ip,
        asset_id=asset_id,
        audit_run_id=audit_run_id,
        message=message,
        details=details or {},
    )
    db.add(entry)
    if commit:
        await db.commit()
        await db.refresh(entry)
    get_logger("websec.audit").info(
        message,
        event_type=event_type,
        security_severity=severity,
        actor=actor,
        asset_id=str(asset_id) if asset_id else None,
        audit_run_id=str(audit_run_id) if audit_run_id else None,
    )
    return entry


def record_security_event_sync(
    db: Session,
    *,
    event_type: str,
    message: str,
    severity: str = "info",
    actor: str | None = None,
    source_ip: str | None = None,
    asset_id: uuid.UUID | None = None,
    audit_run_id: uuid.UUID | None = None,
    details: dict[str, Any] | None = None,
    commit: bool = True,
) -> SecurityEventLog:
    """Persist a structured security audit event from a sync Celery worker context."""
    entry = SecurityEventLog(
        event_type=event_type,
        severity=severity,
        actor=actor,
        source_ip=source_ip,
        asset_id=asset_id,
        audit_run_id=audit_run_id,
        message=message,
        details=details or {},
    )
    db.add(entry)
    if commit:
        db.commit()
        db.refresh(entry)
    get_logger("websec.worker.audit").info(
        message,
        event_type=event_type,
        security_severity=severity,
        actor=actor,
        asset_id=str(asset_id) if asset_id else None,
        audit_run_id=str(audit_run_id) if audit_run_id else None,
    )
    return entry

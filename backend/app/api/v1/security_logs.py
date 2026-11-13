"""Security event audit trail routes (OWASP A09:2025)."""

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_async_db
from app.models.audit_log import SecurityEventLog
from app.schemas.audit import SecurityEventLogOut

router = APIRouter(prefix="/security-logs", tags=["security-logs"])


@router.get("", response_model=list[SecurityEventLogOut])
async def list_security_logs(
    event_type: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    db: AsyncSession = Depends(get_async_db),
) -> list[SecurityEventLog]:
    """List structured security audit logs ordered newest first."""
    stmt = select(SecurityEventLog).order_by(SecurityEventLog.created_at.desc())
    if event_type:
        stmt = stmt.where(SecurityEventLog.event_type == event_type)
    stmt = stmt.limit(limit)
    result = await db.scalars(stmt)
    return list(result.all())

"""OWASP Top 10:2025 catalog API routes."""

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ResourceNotFoundError
from app.db.session import get_async_db
from app.models.owasp import OwaspCategory
from app.schemas.owasp import OwaspCategoryOut

router = APIRouter(prefix="/owasp", tags=["owasp"])


@router.get("/categories", response_model=list[OwaspCategoryOut])
async def list_owasp_categories(
    db: AsyncSession = Depends(get_async_db),
) -> list[OwaspCategory]:
    """Return the complete OWASP Top 10:2025 catalog ordered by official rank."""
    result = await db.scalars(select(OwaspCategory).order_by(OwaspCategory.rank.asc()))
    return list(result.all())


@router.get("/categories/{code}", response_model=OwaspCategoryOut)
async def get_owasp_category(
    code: str,
    db: AsyncSession = Depends(get_async_db),
) -> OwaspCategory:
    """Return details for a specific OWASP Top 10:2025 category (e.g. A01:2025)."""
    category = await db.get(OwaspCategory, code.upper())
    if category is None:
        raise ResourceNotFoundError(f"Categoría OWASP '{code}' no encontrada.")
    return category

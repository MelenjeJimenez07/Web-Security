"""FastAPI application entrypoint with correlation IDs, CORS, and centralized handlers."""

import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import redis.asyncio as aioredis
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from app.api.v1.router import api_v1_router
from app.api.ws import router as ws_router
from app.core.config import get_settings
from app.core.exceptions import register_exception_handlers
from app.core.logging import configure_logging
from app.db.session import async_engine

configure_logging()
settings = get_settings()


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    settings.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    yield
    await async_engine.dispose()


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "Plataforma de auditoría de seguridad y diagnóstico de infraestructura mapeada contra "
        "OWASP Top 10:2025."
    ),
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


@app.middleware("http")
async def correlation_and_security_headers_middleware(
    request: Request, call_next: object
) -> Response:
    """Attach correlation ID and defensive API response headers."""
    correlation_id = request.headers.get("X-Correlation-ID") or str(uuid.uuid4())
    request.state.correlation_id = correlation_id
    response = await call_next(request)  # type: ignore[operator]
    response.headers["X-Correlation-ID"] = correlation_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"
    return response


register_exception_handlers(app)
app.include_router(api_v1_router)
app.include_router(ws_router)


@app.get("/health", tags=["health"])
async def healthcheck() -> dict[str, str]:
    """Verify PostgreSQL and Redis readiness."""
    async with async_engine.connect() as conn:
        await conn.execute(text("SELECT 1"))

    redis_status = "connected"
    client = aioredis.from_url(settings.REDIS_URL, decode_responses=True, socket_timeout=2.0)
    try:
        await client.ping()
    except Exception:
        redis_status = "unavailable"
    finally:
        await client.aclose()

    return {
        "status": "ok" if redis_status == "connected" else "degraded",
        "database": "connected",
        "redis": redis_status,
        "phase": "2",
    }

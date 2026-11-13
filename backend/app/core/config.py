"""Application configuration loaded via Pydantic Settings."""

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Centralized configuration for API, Celery workers, and security controls."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    APP_NAME: str = "WebSec Audit Dashboard"
    APP_VERSION: str = "0.1.0"
    APP_ENV: str = "development"
    LOG_LEVEL: str = "INFO"

    # PostgreSQL connections
    DATABASE_URL: str = (
        "postgresql+asyncpg://websec:CHANGE_ME_STRONG_LOCAL_PASSWORD@postgres:5432/websec_audit"
    )
    SYNC_DATABASE_URL: str = (
        "postgresql+psycopg://websec:CHANGE_ME_STRONG_LOCAL_PASSWORD@postgres:5432/websec_audit"
    )

    # Redis & Celery
    REDIS_URL: str = "redis://redis:6379/0"
    CELERY_BROKER_URL: str = "redis://redis:6379/1"
    CELERY_RESULT_BACKEND: str = "redis://redis:6379/2"

    # Security & Governance Controls
    REQUIRE_DOMAIN_VERIFICATION: bool = True
    CORS_ORIGINS: list[str] = Field(
        default_factory=lambda: [
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://localhost:5173",
        ]
    )
    MAX_SCAN_TIMEOUT_SECONDS: int = 180
    HTTP_REQUEST_TIMEOUT_SECONDS: int = 15
    DOMAIN_VERIFICATION_TTL_HOURS: int = 24
    REPORTS_DIR: Path = Path("/app/data/reports")

    # External passive intelligence endpoints
    CRT_SH_BASE_URL: str = "https://crt.sh"
    NVD_API_BASE_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_API_KEY: str | None = None


@lru_cache
def get_settings() -> Settings:
    """Return cached settings singleton."""
    return Settings()

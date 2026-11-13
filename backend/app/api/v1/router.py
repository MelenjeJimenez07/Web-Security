"""API v1 router aggregator."""

from fastapi import APIRouter

from app.api.v1 import assets, audits, owasp, reports, security_logs

api_v1_router = APIRouter(prefix="/api/v1")
api_v1_router.include_router(owasp.router)
api_v1_router.include_router(assets.router)
api_v1_router.include_router(audits.router)
api_v1_router.include_router(reports.router)
api_v1_router.include_router(security_logs.router)

"""Celery application configuration for background security audits."""

from celery import Celery

from app.core.config import get_settings

settings = get_settings()

celery_app = Celery(
    "websec_audit_worker",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=["app.worker.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_track_started=True,
    task_time_limit=900,
    task_soft_time_limit=840,
)

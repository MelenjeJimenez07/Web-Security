"""Redis Pub/Sub and bounded history buffer for real-time audit log streaming."""

import json
import uuid
from datetime import UTC, datetime
from typing import Any

import redis
import redis.asyncio as aioredis

from app.core.config import get_settings

settings = get_settings()

_HISTORY_TTL_SECONDS = 86400  # 24 hours
_MAX_BUFFERED_EVENTS = 500


def audit_channel_name(audit_run_id: uuid.UUID | str) -> str:
    return f"audit:stream:{audit_run_id}"


def audit_history_key(audit_run_id: uuid.UUID | str) -> str:
    return f"audit:logs:{audit_run_id}"


class AuditStreamPublisher:
    """Synchronous Redis publisher used inside Celery worker tasks."""

    def __init__(self) -> None:
        self._client = redis.Redis.from_url(
            settings.REDIS_URL,
            decode_responses=True,
            socket_timeout=3.0,
        )

    def publish(
        self,
        audit_run_id: uuid.UUID | str,
        *,
        event_type: str,
        level: str,
        message: str,
        module_key: str | None = None,
        progress_percent: int | None = None,
        data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "audit_run_id": str(audit_run_id),
            "timestamp": datetime.now(UTC).isoformat(),
            "event_type": event_type,
            "level": level,
            "module_key": module_key,
            "progress_percent": progress_percent,
            "message": message,
            "data": data or {},
        }
        serialized = json.dumps(payload, default=str)
        history_key = audit_history_key(audit_run_id)
        channel = audit_channel_name(audit_run_id)
        try:
            pipe = self._client.pipeline()
            pipe.rpush(history_key, serialized)
            pipe.ltrim(history_key, -_MAX_BUFFERED_EVENTS, -1)
            pipe.expire(history_key, _HISTORY_TTL_SECONDS)
            pipe.publish(channel, serialized)
            pipe.execute()
        except Exception:
            # Never fail a security scan if Redis Pub/Sub telemetry temporarily hiccups
            pass
        return payload

    def close(self) -> None:
        try:
            self._client.close()
        except Exception:
            pass


async def fetch_buffered_events(audit_run_id: uuid.UUID | str) -> list[dict[str, Any]]:
    """Fetch buffered historical log events for an audit run (async)."""
    client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    try:
        raw_items = await client.lrange(audit_history_key(audit_run_id), 0, -1)
        events: list[dict[str, Any]] = []
        for item in raw_items:
            try:
                events.append(json.loads(item))
            except json.JSONDecodeError:
                continue
        return events
    finally:
        await client.aclose()

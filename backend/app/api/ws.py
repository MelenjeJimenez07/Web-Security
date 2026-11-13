"""WebSocket endpoint for real-time audit log and progress streaming."""

import asyncio
import json
import uuid

import redis.asyncio as aioredis
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketState

from app.core.config import get_settings
from app.db.session import AsyncSessionLocal
from app.models.audit import AuditRun
from app.models.enums import AuditStatus
from app.worker.events import audit_channel_name, fetch_buffered_events

router = APIRouter(tags=["websocket"])
settings = get_settings()

_TERMINAL_STATUSES = {
    AuditStatus.COMPLETED,
    AuditStatus.PARTIAL_FAILURE,
    AuditStatus.FAILED,
    AuditStatus.CANCELLED,
}


@router.websocket("/ws/audits/{audit_id}")
async def audit_logs_websocket(websocket: WebSocket, audit_id: uuid.UUID) -> None:
    """Stream buffered and live audit execution telemetry over WebSocket."""
    await websocket.accept()

    async with AsyncSessionLocal() as db:
        run = await db.get(AuditRun, audit_id)
        if run is None:
            await websocket.send_json(
                {"event_type": "ERROR", "level": "error", "message": "Auditoría no encontrada."}
            )
            await websocket.close(code=4404)
            return

    client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    pubsub = client.pubsub()
    channel = audit_channel_name(audit_id)
    await pubsub.subscribe(channel)
    seen_keys: set[tuple[str | None, str | None, str | None]] = set()

    try:
        buffered = await fetch_buffered_events(audit_id)
        for event in buffered:
            seen_keys.add((event.get("timestamp"), event.get("event_type"), event.get("message")))
            await websocket.send_json(event)

        async with AsyncSessionLocal() as db:
            latest_run = await db.get(AuditRun, audit_id)
            if latest_run is not None and latest_run.status in _TERMINAL_STATUSES:
                await websocket.send_json(
                    {
                        "event_type": "STREAM_EOF",
                        "level": "info",
                        "audit_run_id": str(audit_id),
                        "status": latest_run.status.value,
                        "message": "Auditoría finalizada.",
                    }
                )
                return

        idle_ticks = 0
        while True:
            msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
            if msg and msg.get("type") == "message":
                idle_ticks = 0
                raw = msg["data"]
                try:
                    parsed = json.loads(raw)
                    key = (parsed.get("timestamp"), parsed.get("event_type"), parsed.get("message"))
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)
                    await websocket.send_text(raw)
                    if parsed.get("event_type") in ("AUDIT_COMPLETED", "AUDIT_FAILED"):
                        break
                except json.JSONDecodeError:
                    await websocket.send_text(raw)
            else:
                idle_ticks += 1
                if idle_ticks >= 4:
                    idle_ticks = 0
                    async with AsyncSessionLocal() as db:
                        latest_run = await db.get(AuditRun, audit_id)
                        if latest_run is not None and latest_run.status in _TERMINAL_STATUSES:
                            await websocket.send_json(
                                {
                                    "event_type": "STREAM_EOF",
                                    "level": "info",
                                    "audit_run_id": str(audit_id),
                                    "status": latest_run.status.value,
                                    "message": "Auditoría finalizada.",
                                }
                            )
                            break
                await websocket.send_json(
                    {"event_type": "HEARTBEAT", "audit_run_id": str(audit_id)}
                )
                await asyncio.sleep(1.5)
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        await pubsub.unsubscribe(channel)
        await pubsub.close()
        await client.aclose()
        if websocket.client_state == WebSocketState.CONNECTED:
            try:
                await websocket.close(code=1000)
            except RuntimeError:
                pass

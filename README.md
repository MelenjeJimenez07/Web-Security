# WebSec Audit Dashboard (OWASP Top 10:2025)

Plataforma modular de auditoría de seguridad defensiva y diagnóstico de infraestructura web que centraliza análisis de red, HTTP/Cookies, criptografía SSL/TLS, enumeración DNS pasiva y análisis de cadena de suministro, mapeando cada hallazgo al estándar **OWASP Top 10:2025**.

## Arquitectura del Monorepo

```text
websec-audit-dashboard/
├── docker-compose.yml               # Orquestación multi-servicio y redes aisladas
├── .env.example                     # Plantilla de variables de entorno
├── backend/
│   ├── Dockerfile                   # Multi-stage: api (mínimo privilegio) y worker (Nmap + DNS CLI)
│   ├── entrypoint.sh                # Espera segura de PostgreSQL antes de ejecutar procesos
│   ├── requirements.txt             # Dependencias de producción (FastAPI, SQLAlchemy 2, Celery, etc.)
│   ├── requirements-dev.txt         # Dependencias de testing y linting
│   ├── pyproject.toml               # Configuración de pytest y ruff
│   ├── alembic.ini                  # Configuración de Alembic
│   ├── alembic/                     # Migraciones y seed inicial del catálogo OWASP Top 10:2025
│   └── app/
│       ├── core/                    # Configuración (Pydantic Settings) y controles de seguridad
│       ├── db/                      # Engine async/sync, mixins base y catálogo OWASP Top 10:2025
│       ├── models/                  # Modelos SQLAlchemy 2.0 (Assets, Audits, Findings, Logs, Reports)
│       ├── schemas/                 # Esquemas Pydantic v2 (activos, auditorías, hallazgos, reportes)
│       ├── api/                     # Endpoints REST v1 y streaming WebSocket/SSE
│       ├── scanners/                # Motor de plugins y 5 módulos de auditoría OWASP 2025
│       ├── worker/                  # Tareas Celery + publicación de progreso en Redis Pub/Sub
│       └── reports/                 # Exportación de reportes ejecutivos/técnicos (PDF WeasyPrint y JSON)
└── frontend/
    ├── Dockerfile                   # Multi-stage: Node 20 build -> nginx-unprivileged
    ├── nginx.conf                   # Reverse proxy API/WS + cabeceras de seguridad
    └── src/                         # Dashboard React + Tailwind + Shadcn/UI + Recharts
```

## Controles de Seguridad Integrados (Self-Hardening)

1. **Principio de Mínimo Privilegio en Contenedores:**
   - Tanto `backend`, `celery_worker` como `frontend` corren como usuarios sin privilegios (`websec` UID `10001` y `nginx` UID `101`) con `no-new-privileges:true` y capacidades Linux eliminadas (`cap_drop: ALL`).
   - Las herramientas CLI (`nmap`, `bind9-dnsutils`, `whois`, `openssl`) solo se instalan en la imagen del `worker`, reduciendo la superficie de la API web.
   - `postgres` y `redis` operan exclusivamente en una red interna aislada (`internal: true`) sin exposición pública de puertos por defecto.
2. **Autorización Explícita y Verificación de Propiedad:**
   - El modelo de datos exige confirmación explícita de autorización y registro de verificación de dominio (`DNS TXT` o `.well-known/security-audit.txt`) antes de ejecutar escaneos activos.
3. **Trazabilidad (`A09:2025`) y Manejo de Excepciones (`A10:2025`):**
   - Tabla dedicada `security_event_logs` para registrar eventos críticos de seguridad y ejecuciones por módulo (`audit_module_executions`) resilientes a fallos parciales.

## Estado de Implementación

- [x] **Fase 1:** Estructura del monorepo, `Dockerfile` (API + Worker con Nmap/DNS utils), `docker-compose.yml`, modelos SQLAlchemy 2.0 y migración inicial con catálogo **OWASP Top 10:2025**.
- [x] **Fase 2:** API FastAPI, validación anti-SSRF / anti-Command Injection, Celery + streaming en tiempo real (WebSocket/SSE) y los 5 módulos de auditoría.
- [x] **Fase 3:** Dashboard React (lanzamiento de escaneo, consola de logs en vivo, gráficos Recharts de severidad y OWASP Top 10:2025, detalle de hallazgos).
- [x] **Fase 4:** Exportación de reportes ejecutivos y técnicos en PDF/JSON con matriz de cumplimiento OWASP Top 10:2025 y suite de pruebas unitarias (`pytest`).

## Exportación de Reportes (API v1)

- `GET /api/v1/audits/{audit_id}/reports` — Lista los reportes generados para una auditoría.
- `POST /api/v1/audits/{audit_id}/reports` — Genera un reporte en `pdf` o `json` (`report_type`: `full`, `executive` o `technical`) con checksum SHA-256.
- `GET /api/v1/reports/{report_id}/download` — Descarga segura con `Content-Disposition: attachment`, `X-Content-Type-Options: nosniff` y registro en `security_event_logs` (`REPORT_EXPORTED`).

## Inicio Rápido

```bash
cp .env.example .env
# Edita .env con contraseñas seguras antes de continuar
docker compose build
docker compose up -d postgres redis
docker compose run --rm migrate
docker compose up -d
```

## Ejecución de Pruebas Unitarias (Backend)

```bash
cd backend
pip install -r requirements.txt -r requirements-dev.txt
pytest
```

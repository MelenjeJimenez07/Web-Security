# WebSec Audit Dashboard (OWASP Top 10:2025)

Plataforma modular de auditoría de seguridad defensiva y diagnóstico de infraestructura web. Orquesta análisis de red, configuración HTTP/Cookies, criptografía SSL/TLS, enumeración DNS pasiva y fingerprinting de tecnologías/cadena de suministro, mapeando cada hallazgo al catálogo oficial **OWASP Top 10:2025** con exportación de informes en **PDF, DOCX y JSON**.

---

## Stack Tecnológico

| Capa | Tecnologías principales |
| :--- | :--- |
| **Backend API** | Python 3.11, FastAPI, Pydantic v2, SQLAlchemy 2.0 (async `asyncpg`), Alembic |
| **Motor de Escaneo** | Celery + Redis (Pub/Sub + broker), `python-nmap`, `dnspython`, `cryptography`, `httpx`, `beautifulsoup4`, `lxml` |
| **Reportes** | Jinja2 (autoescape HTML/XML), WeasyPrint (PDF), `python-docx` (Word), SHA-256 checksum |
| **Base de Datos** | PostgreSQL 16 (persistencia), Redis 7 (cola Celery y buffer de streaming) |
| **Frontend** | React 18, TypeScript, Vite, Tailwind CSS, Recharts, Lucide Icons, Nginx unprivileged |

---

## Módulos de Auditoría (`OWASP Top 10:2025`)

| `module_key` | Módulo | Modo | Alcance y OWASP mapeado |
| :--- | :--- | :--- | :--- |
| `dns_passive` | Enumeración DNS y Superficie Pasiva | Pasivo | Registros `A/AAAA/MX/TXT/NS/CNAME/CAA`, SPF/DMARC y logs CT (`crt.sh`) (`A02:2025`) |
| `nmap_recon` | Reconocimiento de Red y Superficie Expuesta | Activo | Puertos TCP abiertos, servicios (`quick`, `top_1000`, `service_version`) y paneles expuestos (`A01:2025`, `A02:2025`) |
| `ssl_tls` | Análisis Criptográfico SSL/TLS | Activo | Certificados X.509, cadena de confianza, protocolos TLS 1.0–1.3 y suites débiles (`A04:2025`) |
| `http_headers` | Auditoría de Cabeceras HTTP y Cookies | Activo | CSP, HSTS, `X-Frame-Options`, `X-Content-Type-Options`, flags de cookies, trazas de error y nota `A+..F` (`A02:2025`, `A05:2025`, `A07:2025`, `A10:2025`) |
| `tech_supply_chain` | Fingerprinting y Cadena de Suministro | Activo | Detección de stack web/JS, validación Subresource Integrity (SRI) y consulta pasiva NVD CVE (`A03:2025`, `A08:2025`) |

---

## Arquitectura del Monorepo

```text
websec-audit-dashboard/
├── docker-compose.yml               # Postgres, Redis, migrate, backend, celery_worker, frontend
├── .env.example                     # Plantilla de variables de entorno (copiar a .env)
├── backend/
│   ├── Dockerfile                   # Multi-stage: api (sin CLI de escaneo) y worker (nmap/dig/openssl)
│   ├── entrypoint.sh                # Espera activa de PostgreSQL antes de arrancar procesos
│   ├── requirements.txt             # Dependencias de ejecución
│   ├── requirements-dev.txt         # pytest, pytest-asyncio, pytest-mock, ruff
│   ├── pyproject.toml               # Configuración de pytest (asyncio_mode=auto) y ruff
│   ├── alembic/                     # Migraciones y seed automático del catálogo OWASP 2025
│   ├── app/
│   │   ├── core/                    # Config Pydantic Settings, validación anti-SSRF/injection y logging JSON
│   │   ├── db/                      # Engines async/sync, modelos base y seed OWASP 2025
│   │   ├── models/                  # Asset, DomainVerification, AuditRun, Finding, AuditReport, SecurityEventLog
│   │   ├── schemas/                 # Contratos Pydantic v2 de entrada/salida
│   │   ├── api/v1/                  # Endpoints REST (assets, audits, reports, owasp, security_logs)
│   │   ├── api/ws.py                # WebSocket /ws/audits/{audit_id} para telemetría en vivo
│   │   ├── scanners/                # Registry y los 5 plugins modulares de escaneo
│   │   ├── worker/                  # Tareas Celery y publicación de eventos en Redis Pub/Sub
│   │   └── reports/                 # Generación segura PDF/DOCX/JSON y protección path-traversal
│   └── tests/                       # Suite unitaria y de contratos API (pytest)
└── frontend/
    ├── Dockerfile                   # Build React/Vite + Nginx unprivileged en puerto 8080
    ├── nginx.conf                   # Proxy /api y /ws hacia backend + cabeceras defensivas
    └── src/
        ├── services/api.ts          # Cliente HTTP tipado + WebSocket/SSE
        └── views/                   # Resumen, Activos y Verificación, Lanzar Auditoría, Consola/Historial, OWASP, Logs
```

---

## Flujo de Uso y Re-auditoría en Vivo

1. **Registrar y Verificar Activo (`Activos y Verificación`):**
   - Cada URL/dominio se normaliza y valida contra SSRF (`POST /api/v1/assets`).
   - Si el objetivo ya existe en el inventario (`409 Conflict`), la alerta muestra un acceso directo **"Volver a auditar activo existente"** para saltar al lanzador sin tener que eliminar el activo ni perder su verificación.
   - En entornos estándar requiere verificación de propiedad (`DNS TXT` o archivo `.well-known/security-audit.txt`).
2. **Lanzar y Monitorear Auditoría (`Lanzar Auditoría` / `Auditorías y Consola`):**
   - Selecciona activo verificado, perfil Nmap (`quick`, `top_1000`, `service_version`), módulos deseados y confirmación explícita de autorización.
   - Sigue los eventos en vivo por WebSocket (`/ws/audits/{audit_id}`) o SSE (`/api/v1/audits/{audit_id}/events`).
3. **Re-auditar y Gestionar Historial:**
   - Tanto en la tabla de **Historial de Auditorías** como en el encabezado de **Detalle de Auditoría** dispones de:
     - **Volver a auditar:** abre directamente **Lanzar Auditoría** con el activo preseleccionado para comparar iteraciones (p. ej. estado vulnerable vs. mitigado).
     - **Eliminar (confirmación en dos pasos):** invoca `DELETE /api/v1/audits/{audit_id}`, limpia en cascada módulos, hallazgos y archivos de reporte generados dentro de `REPORTS_DIR`, preserva el rastro de auditoría en `security_event_logs` (`audit_run_id = NULL`) y registra el evento `AUDIT_DELETED`. Las auditorías en ejecución devuelven `409 Conflict` para evitar estados inconsistentes.
4. **Exportar Evidencia:**
   - Genera y descarga informes `full`, `executive` o `technical` en formato `pdf`, `docx` o `json` con resumen de severidad, matriz OWASP Top 10:2025, vector CVSS, fragmentos de remediación y SHA-256.

---

## Referencia Rápida de API v1 y Streaming

| Área | Endpoints |
| :--- | :--- |
| **Salud y Catálogo** | `GET /health` · `GET /api/v1/scanners` · `GET /api/v1/owasp/categories` · `GET /api/v1/owasp/categories/{code}` |
| **Activos** | `GET /api/v1/assets` · `POST /api/v1/assets` · `GET /api/v1/assets/{asset_id}` · `DELETE /api/v1/assets/{asset_id}` |
| **Verificación** | `POST /api/v1/assets/{asset_id}/verifications` · `POST /api/v1/assets/{asset_id}/verifications/{verification_id}/check` |
| **Auditorías** | `GET /api/v1/dashboard/stats` · `GET /api/v1/audits` · `POST /api/v1/audits` · `GET /api/v1/audits/{audit_id}` · `DELETE /api/v1/audits/{audit_id}` |
| **Hallazgos y Logs** | `GET /api/v1/audits/{audit_id}/findings` · `PATCH /api/v1/findings/{finding_id}` · `GET /api/v1/audits/{audit_id}/logs` · `GET /api/v1/security-logs` |
| **Streaming en Vivo** | `GET /api/v1/audits/{audit_id}/events` (SSE) · `WS /ws/audits/{audit_id}` (WebSocket) |
| **Reportes** | `GET /api/v1/audits/{audit_id}/reports` · `POST /api/v1/audits/{audit_id}/reports` · `GET /api/v1/reports/{report_id}/download` |

---

## Controles de Seguridad Integrados (Self-Hardening)

1. **Mínimo privilegio en contenedores:** `backend` y `celery_worker` corren como usuario sin privilegios `websec` (UID `10001`), y `frontend` como `nginx` unprivileged (UID `101`, puerto `8080`), todos con `no-new-privileges:true` y `cap_drop: ALL`.
2. **Aislamiento de superficie y red:** Las utilidades CLI (`nmap`, `bind9-dnsutils`, `whois`, `openssl`) existen únicamente en `celery_worker`, nunca en `backend`. `postgres` y `redis` permanecen en red interna (`internal_net`, `internal: true`).
3. **Anti-SSRF y Anti-Command Injection:** Validación estricta de esquemas/IPs públicas antes y después de resolver DNS (`SSRFBlockedError`), ejecución sin shell (`shell=False`), terminador `--` en Nmap y parser XML endurecido (`resolve_entities=False`, `no_network=True`).
4. **Descarga segura de reportes y trazabilidad (`A09:2025`):** Verificación estricta de rutas dentro de `REPORTS_DIR` (`resolve_safe_report_path`), cabecera `X-Content-Type-Options: nosniff` y registro persistente en `security_event_logs`.

---

## Despliegue Rápido con Docker Compose

```bash
cp .env.example .env
# Edita .env con contraseñas seguras para PostgreSQL antes de iniciar
docker compose build
docker compose up -d postgres redis
docker compose run --rm migrate
docker compose up -d
```

Puertos locales por defecto (enlazados a `127.0.0.1`):
- **Frontend Dashboard:** `http://127.0.0.1:3000`
- **Backend FastAPI / OpenAPI:** `http://127.0.0.1:8000` (`http://127.0.0.1:8000/docs`)

---

## Modo Laboratorio Local Opcional (Pruebas Controladas)

Por defecto el sistema bloquea direcciones privadas/loopback y exige verificación de propiedad de dominio (`REQUIRE_DOMAIN_VERIFICATION=true`). Para auditar únicamente un laboratorio local autorizado (por ejemplo, `http://aurawear.lab` dentro de la red compartida Docker o un servicio local), configura explícitamente en `.env`:

```dotenv
APP_ENV=development
ALLOW_LAB_LOCAL_TARGETS=true
LAB_TARGET_ALLOWLIST=["aurawear.lab"]
REQUIRE_DOMAIN_VERIFICATION=false
```

> Los rangos de metadatos cloud (`169.254.0.0/16`) y cualquier destino privado fuera de `LAB_TARGET_ALLOWLIST` permanecen bloqueados en todo momento.

---

## Pruebas Automatizadas (Backend)

Con entorno local Python 3.11+:

```bash
cd backend
pip install -r requirements.txt -r requirements-dev.txt
pytest -v
```

O ejecutando la suite dentro de un contenedor efímero sobre la imagen construida de `backend`:

```bash
docker run --rm --user root -e DATABASE_URL= -e SYNC_DATABASE_URL= \
  -v "$(pwd)/backend:/app" websec-audit-dashboard-backend:latest \
  sh -lc "pip install --no-cache-dir -q pytest pytest-asyncio pytest-mock && PYTHONPATH=/app pytest -v"
```

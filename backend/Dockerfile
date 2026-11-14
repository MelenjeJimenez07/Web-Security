# =============================================================================
# WebSec Audit Dashboard - Backend & Worker Multi-Stage Dockerfile
# =============================================================================
# Stage 'api'    : Least-privilege FastAPI runtime (no scanning CLI binaries)
# Stage 'worker' : Celery worker with Nmap, bind9-dnsutils (dig/nslookup),
#                  whois, and OpenSSL CLI utilities pre-installed.
# =============================================================================

FROM python:3.11-slim-bookworm AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Runtime libraries for WeasyPrint PDF reports + TLS certificates
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    fonts-dejavu-core \
    libcairo2 \
    libffi8 \
    libgdk-pixbuf-2.0-0 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libpangoft2-1.0-0 \
    shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

# Create unprivileged application user
RUN groupadd -r -g 10001 websec && \
    useradd -r -u 10001 -g websec -m -d /home/websec -s /usr/sbin/nologin websec

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt


# -----------------------------------------------------------------------------
# Target 1: FastAPI API Server (Minimal Attack Surface)
# -----------------------------------------------------------------------------
FROM base AS api

COPY --chown=websec:websec . .
RUN mkdir -p /app/data/reports && \
    chmod +x /app/entrypoint.sh && \
    chown websec:websec /app && \
    chown -R websec:websec /app/data

USER websec
EXPOSE 8000

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]


# -----------------------------------------------------------------------------
# Target 2: Celery Audit Worker (Nmap + DNS CLI Tools Pre-installed)
# Default final stage if `docker build ./backend` is run without `--target`
# -----------------------------------------------------------------------------
FROM base AS worker

USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
    bind9-dnsutils \
    iputils-ping \
    nmap \
    openssl \
    whois \
    && nmap --version \
    && dig -v \
    && rm -rf /var/lib/apt/lists/*

COPY --chown=websec:websec . .
RUN mkdir -p /app/data/reports && \
    chmod +x /app/entrypoint.sh && \
    chown websec:websec /app && \
    chown -R websec:websec /app/data

USER websec

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["celery", "-A", "app.worker.celery_app:celery_app", "worker", "--loglevel=info", "--concurrency=4"]

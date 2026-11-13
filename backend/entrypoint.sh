#!/bin/sh
set -eu

# Wait for PostgreSQL readiness before running migrations or starting workers
python - <<'PY'
import os
import sys
import time
import psycopg

sync_url = os.environ.get("SYNC_DATABASE_URL", "")
if not sync_url:
    sys.exit(0)

# Convert SQLAlchemy driver prefix to libpq URI for readiness check
pg_dsn = sync_url.replace("postgresql+psycopg://", "postgresql://", 1)

max_attempts = 30
for attempt in range(1, max_attempts + 1):
    try:
        with psycopg.connect(pg_dsn, connect_timeout=3) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
        print("PostgreSQL connection verified.")
        break
    except Exception as exc:
        if attempt == max_attempts:
            print(f"PostgreSQL unavailable after {max_attempts} attempts: {exc}", file=sys.stderr)
            sys.exit(1)
        print(f"Waiting for PostgreSQL ({attempt}/{max_attempts})...")
        time.sleep(2)
PY

exec "$@"

#!/bin/sh
# Control-api container startup: migrate -> seed -> serve.
# Each step is idempotent, so container restarts are safe.
set -eu

echo "[entrypoint] applying database migrations (alembic upgrade head)..."
alembic upgrade head

echo "[entrypoint] seeding admin user, default profile, sample agent..."
python -m app.seed

echo "[entrypoint] starting control-api on 0.0.0.0:8080 ..."
exec uvicorn app.main:app --host 0.0.0.0 --port 8080

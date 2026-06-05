# MLPEF control-api image.
# Build context is the REPO ROOT (it needs ../../common and ../../pyproject.toml):
#   docker build -f control-plane/control-api/Dockerfile -t mlpef-control-api .
# docker-compose sets `context: .` + this dockerfile.
# syntax=docker/dockerfile:1
FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install dependencies first for better layer caching: only the project metadata
# and the `common` package are needed for the editable install.
COPY pyproject.toml ./
COPY common ./common
RUN pip install --upgrade pip && pip install -e ".[control]"

# Application code + migrations.
COPY control-plane/control-api ./control-plane/control-api

# Run from the service dir so `app.*`, alembic.ini, and the migrations resolve.
# Pin PYTHONPATH so `app` imports under uvicorn regardless of launcher cwd
# (`common` is already importable via the editable install at /app).
WORKDIR /app/control-plane/control-api
ENV PYTHONPATH=/app/control-plane/control-api
RUN chmod +x docker-entrypoint.sh

EXPOSE 8080
# Migrate (alembic) + seed (idempotent) + serve. See docker-entrypoint.sh.
ENTRYPOINT ["./docker-entrypoint.sh"]

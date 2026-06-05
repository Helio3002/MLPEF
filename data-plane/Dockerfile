# MLPEF data-plane proxy image.
# Build context is the REPO ROOT (needs ../common and ../pyproject.toml):
#   docker build -f data-plane/Dockerfile -t mlpef-proxy .
# docker-compose sets `context: .` + this dockerfile.
# syntax=docker/dockerfile:1
FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Dependencies first (layer caching): metadata + the `common` package only.
COPY pyproject.toml ./
COPY common ./common
RUN pip install --upgrade pip && pip install -e ".[proxy]"

# Data-plane code (proxy, ingress, layer1..layer5).
COPY data-plane ./data-plane

# Run from the data-plane root so layer/proxy/ingress import as top-level packages.
# Pin PYTHONPATH so they resolve under uvicorn regardless of launcher cwd
# (`common` is already importable via the editable install at /app).
WORKDIR /app/data-plane
ENV PYTHONPATH=/app/data-plane

EXPOSE 8090
# The demo proxy disables the sandbox (no Docker-in-Docker); L1/L2/L5 are live.
# Sandbox execution needs a mounted docker socket + a real command_builder.
CMD ["uvicorn", "proxy.server:app", "--host", "0.0.0.0", "--port", "8090"]

# =============================================================================
# SMTP Relay — UI container
# =============================================================================
# Build context: repository root (set by docker-compose).
# =============================================================================

# Base image pinned by digest for reproducible builds and supply-chain safety.
# The tag is kept for readability; Docker resolves the digest. Digest bumps are
# automated via Dependabot (.github/dependabot.yml).
FROM python:3.12-slim-bookworm@sha256:76d4b7b6305788c6b4c6a19d6a22a3921bf802e9af4d5e1e5bd771208dba74bf AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Apply all outstanding OS security patches from the Debian base image.
RUN apt-get update && apt-get upgrade -y && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 1000 ui \
    && useradd --system --uid 1000 --gid 1000 --home /app --shell /usr/sbin/nologin ui \
    && mkdir -p /app /data \
    && chown ui:ui /app /data

WORKDIR /app

COPY ui/requirements.txt ./requirements.txt
RUN pip install --upgrade pip -r requirements.txt

# Shared modules first, then UI.
COPY --chown=ui:ui common/ ./common/
COPY --chown=ui:ui ui/ ./ui/

USER ui

EXPOSE 8000

# Entrypoint script: run migrations, optionally apply ADMIN_RESET, then exec
# uvicorn. Placed inline as a small bash block for transparency.
ENTRYPOINT ["/bin/sh", "-c", "\
  set -eu; \
  cd /app && \
  alembic -c ui/alembic.ini upgrade head && \
  python -m ui.bootstrap && \
  exec uvicorn ui.main:app \
      --host 0.0.0.0 \
      --port 8000 \
      --proxy-headers \
      --forwarded-allow-ips=${FORWARDED_ALLOW_IPS:-127.0.0.1} \
      --no-server-header \
      --log-config=ui/log_config.json \
"]
# NB: --forwarded-allow-ips must list ONLY the reverse proxy (nginx) address so
# uvicorn trusts X-Forwarded-For from it and nobody else. docker-compose pins
# nginx to a static address and passes it via FORWARDED_ALLOW_IPS. Never set
# this to '*' in production: combined with a proxy that forwards client headers
# it would let any client spoof its source IP.

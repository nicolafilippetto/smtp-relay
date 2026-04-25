# =============================================================================
# SMTP Relay — relay container
# =============================================================================
# Build context: repository root (set by docker-compose).
# =============================================================================

FROM python:3.12-slim-bookworm AS base

# Basic hardening / small image layer.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Apply all outstanding OS security patches from the Debian base image.
RUN apt-get update && apt-get upgrade -y && apt-get clean && rm -rf /var/lib/apt/lists/*

# Create non-root user (uid 1000) that will own /app and run the process.
RUN groupadd --system --gid 1000 relay \
    && useradd --system --uid 1000 --gid 1000 --home /app --shell /usr/sbin/nologin relay \
    && mkdir -p /app /data \
    && chown relay:relay /app /data

WORKDIR /app

# Install deps as root (layer caching) then drop privileges.
COPY relay/requirements.txt ./requirements.txt
RUN pip install --upgrade pip -r requirements.txt

# Copy the shared package first (rarely changes) then the service code.
COPY --chown=relay:relay common/ ./common/
COPY --chown=relay:relay relay/ ./relay/

USER relay

# SMTP listener port inside the container.
EXPOSE 2525

# The relay has no healthcheck on the HTTP side — instead it updates
# a heartbeat row in the DB, which the UI renders on the dashboard.

ENTRYPOINT ["python", "-m", "relay.main"]

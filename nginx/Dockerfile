# =============================================================================
# SMTP Relay — nginx TLS terminator
# =============================================================================
# Build context: repository root (set by docker-compose).
#
# Nginx terminates TLS in front of the uvicorn-based UI. The UI never
# speaks HTTP to the internet directly. On first start, if no
# fullchain.pem / privkey.pem is present in /etc/nginx/certs, the
# entrypoint generates a self-signed pair so the service is immediately
# reachable over HTTPS. To use a real certificate, mount the two files
# into the `certs` volume before starting the stack.
#
# The image is based on nginx/nginx-unprivileged so the process runs as
# a non-root user (uid 101) and listens on high ports (8080/8443). The
# compose file maps the conventional host ports 80/443 onto those.
# (The old `nginxinc/nginx-unprivileged` name on Docker Hub is no longer
# maintained and stopped receiving rebuilds in October 2026.)
# =============================================================================

# Base image pinned by digest for reproducible builds and supply-chain safety.
# The tag is kept for readability; Docker resolves the digest. Digest bumps are
# automated via Dependabot (.github/dependabot.yml).
FROM nginx/nginx-unprivileged:1.31-alpine@sha256:86628f2c9eaa5e84e3b98d25e26563c4a4f9b0ead9cf5656da4731d86e0621de

# The unprivileged base image runs as uid 101 ("nginx"). Switch to root only
# for the build steps that need it, then drop back.
USER root

# - apk upgrade: apply Alpine security fixes the base image does not carry
#   yet (it is not rebuilt for every Alpine package update). Only patch
#   releases of the image's own Alpine branch; nginx itself comes from the
#   nginx.org repository and is not touched.
# - openssl: required by the self-signed-cert entrypoint (absent from the
#   alpine base image).
# - /etc/nginx/certs owned by uid 101: a freshly created `certs` named volume
#   inherits this ownership (Docker copies the image dir's ownership into a new
#   empty volume), so the entrypoint can write the self-signed pair while
#   running unprivileged.
# - remove the stock default server so the base image's
#   10-listen-on-ipv6-on-ipv4 entrypoint exits early instead of rewriting it
#   in place (which would fail on a read-only root filesystem).
RUN apk upgrade --no-cache \
    && apk add --no-cache openssl \
    && mkdir -p /etc/nginx/certs \
    && chown 101:101 /etc/nginx/certs \
    && rm -f /etc/nginx/conf.d/default.conf

COPY nginx/nginx.conf /etc/nginx/nginx.conf
COPY nginx/entrypoint.sh /docker-entrypoint.d/10-generate-selfsigned.sh

RUN chmod +x /docker-entrypoint.d/10-generate-selfsigned.sh

# Drop back to the unprivileged nginx user (uid 101). nginx listens on high
# ports (8080/8443), so no privileged-port capability is required.
USER 101

EXPOSE 8080 8443

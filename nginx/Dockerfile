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
# The image is based on nginxinc/nginx-unprivileged so the process runs as
# a non-root user (uid 101) and listens on high ports (8080/8443). The
# compose file maps the conventional host ports 80/443 onto those.
# =============================================================================

# Base image pinned by digest for reproducible builds and supply-chain safety.
# The tag is kept for readability; Docker resolves the digest. Digest bumps are
# automated via Dependabot (.github/dependabot.yml).
FROM nginxinc/nginx-unprivileged:1.31-alpine@sha256:054e14f543eb688809d59ec2ad1644d1a61678e247c87a318ad605977eb37eaf

# The unprivileged base image runs as uid 101 ("nginx"). Switch to root only
# for the build steps that need it, then drop back.
USER root

# - openssl: required by the self-signed-cert entrypoint (absent from the
#   alpine base image).
# - /etc/nginx/certs owned by uid 101: a freshly created `certs` named volume
#   inherits this ownership (Docker copies the image dir's ownership into a new
#   empty volume), so the entrypoint can write the self-signed pair while
#   running unprivileged.
# - remove the stock default server so the base image's
#   10-listen-on-ipv6-on-ipv4 entrypoint exits early instead of rewriting it
#   in place (which would fail on a read-only root filesystem).
RUN apk add --no-cache openssl \
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

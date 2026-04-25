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
# =============================================================================

FROM nginx:1.29-alpine

RUN apk add --no-cache openssl

COPY nginx/nginx.conf /etc/nginx/nginx.conf
COPY nginx/entrypoint.sh /docker-entrypoint.d/10-generate-selfsigned.sh

RUN chmod +x /docker-entrypoint.d/10-generate-selfsigned.sh

EXPOSE 80 443

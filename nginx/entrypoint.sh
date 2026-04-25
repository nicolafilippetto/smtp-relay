#!/bin/sh
# =============================================================================
# Generate a self-signed certificate if the operator has not supplied one.
# Runs as part of the nginx official image's entrypoint chain, before
# the nginx process is started.
#
# If both /etc/nginx/certs/fullchain.pem and /etc/nginx/certs/privkey.pem
# exist we leave them alone. The self-signed pair gets a 10-year
# lifetime and a SAN covering the typical cases: localhost, 127.0.0.1,
# and whatever hostname NGINX_SERVER_NAME is set to (defaults to the
# container hostname).
# =============================================================================
set -eu

CERT_DIR=/etc/nginx/certs
CRT="$CERT_DIR/fullchain.pem"
KEY="$CERT_DIR/privkey.pem"

mkdir -p "$CERT_DIR"

if [ -s "$CRT" ] && [ -s "$KEY" ]; then
  echo "[nginx entrypoint] Using existing certificate at $CRT"
  exit 0
fi

CN="${NGINX_SERVER_NAME:-$(hostname)}"

echo "[nginx entrypoint] No cert found; generating self-signed for CN=$CN (valid 10 years)."
echo "[nginx entrypoint] Replace $CRT and $KEY with a real certificate for production."

cat >/tmp/openssl.cnf <<EOF
[req]
distinguished_name = dn
x509_extensions    = v3
prompt             = no

[dn]
CN = ${CN}
O  = SMTP Relay (self-signed)

[v3]
subjectAltName = @san
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[san]
DNS.1 = ${CN}
DNS.2 = localhost
IP.1  = 127.0.0.1
EOF

openssl req \
    -x509 \
    -newkey rsa:4096 \
    -sha256 \
    -days 3650 \
    -nodes \
    -keyout "$KEY" \
    -out "$CRT" \
    -config /tmp/openssl.cnf

chmod 600 "$KEY"
chmod 644 "$CRT"

echo "[nginx entrypoint] Self-signed certificate created."

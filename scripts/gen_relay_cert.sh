#!/usr/bin/env bash
# Generate a self-signed cert for the relay and print the SHA-256 pin the client
# must trust (cert_fingerprint_sha256). Dev/internal use; for production use a cert
# from your internal CA — pinning the leaf works the same either way.
set -euo pipefail

CN="${1:?usage: gen_relay_cert.sh <hostname>}"
OUT_DIR="${2:-.}"
CRT="$OUT_DIR/relay.crt"
KEY="$OUT_DIR/relay.key"

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$KEY" -out "$CRT" -days 365 -nodes \
    -subj "/CN=$CN" -addext "subjectAltName=DNS:$CN"

chmod 600 "$KEY"

PIN="$(openssl x509 -in "$CRT" -noout -fingerprint -sha256 | sed 's/.*=//; s/://g' | tr 'A-Z' 'a-z')"

echo
echo "wrote $CRT and $KEY"
echo "cert_fingerprint_sha256 = \"$PIN\""
echo
echo "Serve with, e.g.:"
echo "  uvicorn netapprove_relay.app:app --host 0.0.0.0 --port 8443 --ssl-keyfile $KEY --ssl-certfile $CRT"

#!/usr/bin/env bash
# Generate a synthetic self-signed RSA signing key+cert for F-032 lab demos.
# Do NOT use these materials in production. Do NOT commit private keys.
set -euo pipefail
OUT_DIR="${1:-/tmp/foreman-f032-signing}"
mkdir -p "$OUT_DIR"
umask 077
openssl req -x509 -newkey rsa:2048 -sha256 -days 30 -nodes \
  -keyout "$OUT_DIR/signing.key" \
  -out "$OUT_DIR/signing.crt" \
  -subj "/CN=Foreman F-032 Lab Signing/O=Foreman Lab/C=US"
chmod 600 "$OUT_DIR/signing.key"
chmod 644 "$OUT_DIR/signing.crt"
echo "Wrote $OUT_DIR/signing.key and $OUT_DIR/signing.crt"
echo "Export: FOREMAN_SIGNING_KEY_FILE=$OUT_DIR/signing.key"
echo "        FOREMAN_SIGNING_CERT_FILE=$OUT_DIR/signing.crt"
echo "        FOREMAN_SIGNING_ENABLED=true"

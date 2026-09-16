#!/usr/bin/env bash
# Generate CA + server + client certificates for JOCKY mTLS demo
# Usage: ./scripts/gen-certs.sh [output-dir]
# Requires: openssl >= 1.1

set -euo pipefail

OUT="${1:-certs}"
mkdir -p "$OUT"

echo "==> Generating JOCKY mTLS certificates in $OUT/"

# ── CA ────────────────────────────────────────────────────────────────────────
openssl ecparam -name prime256v1 -genkey -noout -out "$OUT/ca.key"
openssl req -new -x509 -days 3650 -key "$OUT/ca.key" \
  -subj "/CN=JOCKY-Forensics-CA/O=NTRO/C=IN" \
  -out "$OUT/ca.crt"

# ── Server cert ───────────────────────────────────────────────────────────────
openssl ecparam -name prime256v1 -genkey -noout -out "$OUT/server.key"
openssl req -new -key "$OUT/server.key" \
  -subj "/CN=forensics-gw.ntro.gov.in/O=NTRO/C=IN" \
  -out "$OUT/server.csr"
openssl x509 -req -days 365 -in "$OUT/server.csr" \
  -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" -CAcreateserial \
  -extfile <(printf "subjectAltName=DNS:localhost,DNS:forensics-gw.ntro.gov.in,IP:127.0.0.1") \
  -out "$OUT/server.crt"

# ── Client cert (agent identity) ──────────────────────────────────────────────
openssl ecparam -name prime256v1 -genkey -noout -out "$OUT/client.key"
openssl req -new -key "$OUT/client.key" \
  -subj "/CN=jocky-agent-01/O=NTRO/C=IN" \
  -out "$OUT/client.csr"
openssl x509 -req -days 365 -in "$OUT/client.csr" \
  -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" -CAcreateserial \
  -extfile <(printf "extendedKeyUsage=clientAuth") \
  -out "$OUT/client.crt"

rm -f "$OUT"/*.csr "$OUT"/*.srl

echo ""
echo "Generated:"
echo "  $OUT/ca.crt          — CA certificate (trust anchor)"
echo "  $OUT/server.{crt,key} — Server TLS (set in server env vars)"
echo "  $OUT/client.{crt,key} — Client cert (loaded by agent)"
echo ""
echo "Start server with:"
echo "  JOCKY_TLS_CERT=$OUT/server.crt JOCKY_TLS_KEY=$OUT/server.key \\"
echo "  JOCKY_TLS_CA=$OUT/ca.crt go run ./server"

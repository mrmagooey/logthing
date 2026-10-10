#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
COMPOSE_FILE="$ROOT_DIR/docker-compose.yml"

# wef-interop [--samba]: Windows-shaped WEF clients (tools: wef-client-emulator) against
# logthing over Kerberos-encrypted HTTP (MIT KDC) and HTTPS client certificates, verified from
# the files logthing writes. Exits non-zero if any emulator, checks or verifier container fails.
wef_interop() {
  case "${1:-}" in
    "") ;;
    --samba) echo "wef-interop --samba: not yet implemented" >&2; exit 2 ;;
    *) echo "usage: run.sh wef-interop [--samba]" >&2; exit 2 ;;
  esac
  dc=(docker compose -f "$COMPOSE_FILE" --profile wef-interop)
  trap 'rc=$?; [ $rc -eq 0 ] || "${dc[@]}" logs --no-color kdc logthing-wef-krb logthing-wef-mtls | tail -n 150; "${dc[@]}" down -v >/dev/null 2>&1 || true' EXIT
  "${dc[@]}" build kdc logthing-wef-krb wefemu-krb-checks wef-interop-verifier
  "${dc[@]}" up -d --wait kdc logthing-wef-krb logthing-wef-mtls
  # `run` (not `up --abort-on-container-exit`): that flag stops everything when the first
  # emulator exits, even successfully, and loses the other containers' exit codes.
  echo "== Kerberos auth checks"
  "${dc[@]}" run --rm wefemu-krb-checks
  echo "== Kerberos-over-HTTP client flow"
  "${dc[@]}" run --rm wefemu-krb
  echo "== HTTPS client-certificate client flow"
  "${dc[@]}" run --rm wefemu-mtls
  echo "== Verifying what logthing wrote"
  "${dc[@]}" run --rm wef-interop-verifier
  echo "wef-interop passed"
}

if [ "${1:-}" = "wef-interop" ]; then
  shift
  wef_interop "$@"
  exit 0
fi

cleanup() {
  docker compose -f "$COMPOSE_FILE" down -v >/dev/null 2>&1 || true
}

trap cleanup EXIT

echo "========================================"
echo "Building E2E test images..."
echo "========================================"
docker compose -f "$COMPOSE_FILE" build

echo ""
echo "========================================"
echo "Running Standard E2E Tests"
echo "========================================"
docker compose -f "$COMPOSE_FILE" up -d minio
docker compose -f "$COMPOSE_FILE" run --rm minio-setup
docker compose -f "$COMPOSE_FILE" up -d logthing

docker compose -f "$COMPOSE_FILE" run --rm wef-generator
docker compose -f "$COMPOSE_FILE" run --rm syslog-generator
docker compose -f "$COMPOSE_FILE" run --rm s3-verifier
docker compose -f "$COMPOSE_FILE" run --rm wef-local-verifier

echo ""
echo "========================================"
echo "Running IPFIX E2E Tests"
echo "========================================"
docker compose -f "$COMPOSE_FILE" run --rm ipfix-generator
docker compose -f "$COMPOSE_FILE" run --rm ipfix-s3-verifier
docker compose -f "$COMPOSE_FILE" run --rm ipfix-local-verifier
echo "IPFIX E2E Tests Completed Successfully"

echo ""
echo "========================================"
echo "Running Zeek NDJSON E2E Tests"
echo "========================================"
docker compose -f "$COMPOSE_FILE" run --rm zeek-generator
docker compose -f "$COMPOSE_FILE" run --rm zeek-s3-verifier
docker compose -f "$COMPOSE_FILE" run --rm zeek-local-verifier
echo "Zeek E2E Tests Completed Successfully"

echo ""
echo "========================================"
echo "Running OTLP E2E Tests"
echo "========================================"
docker compose -f "$COMPOSE_FILE" run --rm otlp-generator
docker compose -f "$COMPOSE_FILE" run --rm --no-deps otlp-local-verifier
echo "OTLP E2E Tests Completed Successfully"

echo ""
echo "========================================"
echo "Running Parsing Validator"
echo "========================================"
docker compose -f "$COMPOSE_FILE" run --rm parsing-validator

echo ""
echo "========================================"
echo "Standard E2E Tests Completed Successfully"
echo "========================================"

echo ""
echo "========================================"
echo "Running Performance Test (1M Events)"
echo "========================================"
docker compose -f "$COMPOSE_FILE" up -d logthing
docker compose -f "$COMPOSE_FILE" run --rm performance-test

echo ""
echo "========================================"
echo "Running Sustained 10k RPS Test (100MB Parquet)"
echo "========================================"
docker compose -f "$COMPOSE_FILE" up -d logthing-10k-sustained
docker compose -f "$COMPOSE_FILE" run --rm performance-test-10k-sustained

echo ""
echo "========================================"
echo "Running Performance Test (100k RPS Target)"
echo "========================================"
docker compose -f "$COMPOSE_FILE" run --rm performance-test-100k || echo "100k RPS test completed with warnings"

echo ""
echo "========================================"
echo "Running Performance Test (200k RPS Target)"
echo "========================================"
docker compose -f "$COMPOSE_FILE" run --rm performance-test-200k || echo "200k RPS test completed with warnings"

echo ""
echo "========================================"
echo "Running Performance Test (500k RPS Target)"
echo "========================================"
docker compose -f "$COMPOSE_FILE" run --rm performance-test-500k || echo "500k RPS test completed with warnings"

echo ""
echo "========================================"
echo "Running Zeek TCP Load Test (loadgen)"
echo "========================================"
docker compose -f "$COMPOSE_FILE" up -d logthing
docker compose -f "$COMPOSE_FILE" run --rm loadgen-zeek

echo ""
echo "========================================"
echo "Running IPFIX UDP Load Test (loadgen)"
echo "========================================"
docker compose -f "$COMPOSE_FILE" run --rm loadgen-ipfix

echo ""
echo "========================================"
echo "Running HEC HTTP Load Test (loadgen)"
echo "========================================"
docker compose -f "$COMPOSE_FILE" run --rm loadgen-hec

echo ""
echo "========================================"
echo "Running Generic HTTP Load Test (loadgen)"
echo "========================================"
docker compose -f "$COMPOSE_FILE" run --rm loadgen-generic

echo ""
echo "========================================"
echo "Running TLS E2E Tests"
echo "========================================"
docker compose -f "$COMPOSE_FILE" stop logthing
docker compose -f "$COMPOSE_FILE" up -d logthing-tls
docker compose -f "$COMPOSE_FILE" run --rm tls-test

echo ""
echo "========================================"
echo "All E2E Tests Completed Successfully"
echo "========================================"

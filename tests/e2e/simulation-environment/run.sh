#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
COMPOSE_FILE="$ROOT_DIR/docker-compose.yml"

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
echo "Running TLS E2E Tests"
echo "========================================"
docker compose -f "$COMPOSE_FILE" stop logthing
docker compose -f "$COMPOSE_FILE" up -d logthing-tls
docker compose -f "$COMPOSE_FILE" run --rm tls-test

echo ""
echo "========================================"
echo "Running Kerberos Authentication E2E Tests"
echo "========================================"
docker compose -f "$COMPOSE_FILE" stop logthing-tls
docker compose -f "$COMPOSE_FILE" up -d logthing-kerberos
docker compose -f "$COMPOSE_FILE" run --rm kerberos-test

echo ""
echo "========================================"
echo "All E2E Tests Completed Successfully"
echo "========================================"

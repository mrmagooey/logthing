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
docker compose -f "$COMPOSE_FILE" up -d wef-server

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
echo "Running TLS E2E Tests"
echo "========================================"
docker compose -f "$COMPOSE_FILE" up -d wef-server-tls
docker compose -f "$COMPOSE_FILE" run --rm tls-test

echo ""
echo "========================================"
echo "Running Kerberos Authentication E2E Tests"
echo "========================================"
docker compose -f "$COMPOSE_FILE" up -d wef-server-kerberos
docker compose -f "$COMPOSE_FILE" run --rm kerberos-test

echo ""
echo "========================================"
echo "All E2E Tests Completed Successfully"
echo "========================================"

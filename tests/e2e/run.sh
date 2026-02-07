#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
COMPOSE_FILE="$ROOT_DIR/docker-compose.yml"

cleanup() {
  docker compose -f "$COMPOSE_FILE" down -v >/dev/null 2>&1 || true
}

trap cleanup EXIT

docker compose -f "$COMPOSE_FILE" build
docker compose -f "$COMPOSE_FILE" up -d minio
docker compose -f "$COMPOSE_FILE" run --rm minio-setup
docker compose -f "$COMPOSE_FILE" up -d wef-server

docker compose -f "$COMPOSE_FILE" run --rm wef-generator
docker compose -f "$COMPOSE_FILE" run --rm syslog-generator
docker compose -f "$COMPOSE_FILE" run --rm s3-verifier

#!/usr/bin/env bash
# End-to-end test: logthing receives syslog over UDP, writes Parquet + Iceberg
# descriptors to MinIO, the committer container drains the descriptor queue
# into a real Lakekeeper (Iceberg REST) catalog, and verify.py reads the
# resulting table back through the catalog + S3 -- the outermost interfaces
# on every side, no internal function calls.
#
# Requires Docker (compose v2) and a built logthing release binary.
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
COMMITTER_DIR=$(cd -- "$ROOT_DIR/../.." && pwd)
REPO_ROOT=$(cd -- "$COMMITTER_DIR/.." && pwd)
COMPOSE_FILE="$ROOT_DIR/docker-compose.yml"

LOGTHING_BIN="${LOGTHING_BIN:-$REPO_ROOT/target/release/logthing}"
PYTHON="$COMMITTER_DIR/.venv/bin/python3"
[ -x "$PYTHON" ] || PYTHON="python3"

N_MESSAGES=50
MARKER="e2e-marker-$(date +%s)-$$"
SYSLOG_UDP_PORT=15514
SYSLOG_TCP_PORT=15601
HEALTH_ADDR="127.0.0.1:18080"
DATA_BUCKET="logthing-data"
WAREHOUSE="logthing-warehouse"
NAMESPACE="logs"

CFG_DIR=$(mktemp -d)
LOGTHING_PID=""

cleanup() {
  if [ -n "$LOGTHING_PID" ] && kill -0 "$LOGTHING_PID" 2>/dev/null; then
    kill -TERM "$LOGTHING_PID" 2>/dev/null || true
    wait "$LOGTHING_PID" 2>/dev/null || true
  fi
  docker compose -f "$COMPOSE_FILE" down -v >/dev/null 2>&1 || true
  rm -rf "$CFG_DIR"
}
trap cleanup EXIT

if [ ! -x "$LOGTHING_BIN" ]; then
  echo "logthing binary not found or not executable at $LOGTHING_BIN" >&2
  echo "build it first: CARGO_TARGET_DIR=<dir> cargo build --release, or set LOGTHING_BIN" >&2
  exit 1
fi

echo "== [1/8] compose up (postgres, minio) =="
docker compose -f "$COMPOSE_FILE" up -d postgres minio

echo "== [2/8] bucket + Lakekeeper migrate/serve =="
docker compose -f "$COMPOSE_FILE" run --rm minio-setup
docker compose -f "$COMPOSE_FILE" run --rm lakekeeper-migrate
docker compose -f "$COMPOSE_FILE" up -d --wait lakekeeper

echo "== [3/8] bootstrap Lakekeeper + create warehouse =="
curl -sf -X POST http://localhost:8181/management/v1/bootstrap \
  -H 'Content-Type: application/json' \
  --data '{"accept-terms-of-use": true}' -o /dev/null

curl -sf -X POST http://localhost:8181/management/v1/warehouse \
  -H 'Content-Type: application/json' \
  --data "$(cat <<JSON
{
  "warehouse-name": "$WAREHOUSE",
  "storage-profile": {
    "type": "s3",
    "bucket": "$DATA_BUCKET",
    "key-prefix": "iceberg-warehouse",
    "endpoint": "http://minio:9000",
    "region": "us-east-1",
    "path-style-access": true,
    "flavor": "s3-compat",
    "sts-enabled": false
  },
  "storage-credential": {
    "type": "s3",
    "credential-type": "access-key",
    "access-key-id": "minioadmin",
    "secret-access-key": "minioadmin"
  }
}
JSON
)" -o /dev/null

echo "== [4/8] generate logthing config + start logthing =="
cat > "$CFG_DIR/logthing.toml" <<TOML
bind_address = "$HEALTH_ADDR"

[logging]
level = "info"
format = "pretty"

[metrics]
enabled = false

[syslog]
enabled = true
udp_port = $SYSLOG_UDP_PORT
tcp_port = $SYSLOG_TCP_PORT
parse_dns = false

[syslog.s3]
endpoint      = "http://localhost:9000"
bucket        = "$DATA_BUCKET"
region        = "us-east-1"
access_key    = "minioadmin"
secret_key    = "minioadmin"
prefix        = "syslog"
max_buffer_rows      = 1000
flush_interval_secs  = 2
channel_capacity     = 4096

[iceberg.s3]
endpoint   = "http://localhost:9000"
bucket     = "$DATA_BUCKET"
region     = "us-east-1"
access_key = "minioadmin"
secret_key = "minioadmin"
prefix     = "_iceberg_descriptors"
TOML

(cd "$CFG_DIR" && exec "$LOGTHING_BIN") &
LOGTHING_PID=$!

for _ in $(seq 1 30); do
  if curl -sf "http://$HEALTH_ADDR/health" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
curl -sf "http://$HEALTH_ADDR/health" >/dev/null || {
  echo "logthing never became healthy on http://$HEALTH_ADDR/health" >&2
  exit 1
}

echo "== [5/8] send $N_MESSAGES syslog messages (marker: $MARKER) =="
"$PYTHON" - "$SYSLOG_UDP_PORT" "$N_MESSAGES" "$MARKER" <<'PYEOF'
import socket
import sys
import time

port = int(sys.argv[1])
n = int(sys.argv[2])
marker = sys.argv[3]

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
now = time.strftime("%b %e %H:%M:%S")
for i in range(n):
    msg = f"<134>{now} e2ehost committer-e2e: {marker} message {i}"
    sock.sendto(msg.encode(), ("127.0.0.1", port))
sock.close()
PYEOF

echo "== [6/8] wait for Iceberg descriptors to appear in S3 =="
"$PYTHON" - <<'PYEOF'
import os
import sys
import time

import boto3

client = boto3.client(
    "s3",
    endpoint_url="http://localhost:9000",
    aws_access_key_id="minioadmin",
    aws_secret_access_key="minioadmin",
    region_name="us-east-1",
)

deadline = time.time() + 30
found = 0
while time.time() < deadline:
    resp = client.list_objects_v2(Bucket="logthing-data", Prefix="_iceberg_descriptors/")
    found = len(resp.get("Contents", []))
    if found > 0:
        # Give the flush_interval_secs=2 timer one more full cycle to fold in
        # any messages still in-flight, so all N rows land before the
        # committer runs rather than racing a second, later descriptor.
        time.sleep(3)
        break
    time.sleep(1)
else:
    print("timed out waiting for descriptors under _iceberg_descriptors/", file=sys.stderr)
    sys.exit(1)

print(f"found {found} descriptor(s)")
PYEOF

echo "== [7/8] build + run committer (first pass) =="
docker build -t logthing-committer:e2e "$COMMITTER_DIR"

run_committer() {
  docker run --rm --network host \
    -e DATA_BUCKET="$DATA_BUCKET" \
    -e S3_ENDPOINT="http://localhost:9000" \
    -e S3_ACCESS_KEY="minioadmin" \
    -e S3_SECRET_KEY="minioadmin" \
    -e CATALOG_URI="http://localhost:8181/catalog" \
    -e WAREHOUSE="$WAREHOUSE" \
    -e ICEBERG_NAMESPACE="$NAMESPACE" \
    logthing-committer:e2e
}

run_committer
echo "committer (first pass) exited 0"

echo "== [8/8] verify via catalog + S3, then re-run committer for idempotency =="
CATALOG_URI="http://localhost:8181/catalog" WAREHOUSE="$WAREHOUSE" \
  S3_ENDPOINT="http://localhost:9000" S3_ACCESS_KEY="minioadmin" S3_SECRET_KEY="minioadmin" \
  DATA_BUCKET="$DATA_BUCKET" \
  "$PYTHON" "$ROOT_DIR/verify.py" "$MARKER" "$N_MESSAGES"

run_committer
echo "committer (second pass, idempotency) exited 0"

CATALOG_URI="http://localhost:8181/catalog" WAREHOUSE="$WAREHOUSE" \
  S3_ENDPOINT="http://localhost:9000" S3_ACCESS_KEY="minioadmin" S3_SECRET_KEY="minioadmin" \
  DATA_BUCKET="$DATA_BUCKET" \
  "$PYTHON" "$ROOT_DIR/verify.py" "$MARKER" "$N_MESSAGES"

echo ""
echo "========================================"
echo "Committer E2E test PASSED"
echo "========================================"

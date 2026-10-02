#!/usr/bin/env bash
# End-to-end: compose stack up -> syslog into logthing -> committer -> Trino and Hue see the rows.
# Requires Docker and an AVX2-capable CPU (or TRINO_IMAGE/HUE_IMAGE overrides).
set -euo pipefail
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ANALYTICS=$(cd -- "$HERE/../.." && pwd)
. "$HERE/lib.sh"
preflight_cpu

PROJECT="lt-e2e-$$"
# Non-default host ports so a developer's running stack does not collide.
SYSLOG_UDP_PORT=25514
HUE_PORT=28888
N=40
MARKER="analytics-e2e-$(date +%s)-$$"
PY=${PYTHON:-python3}

# Hermetic config: an explicit env file means a developer's deploy/analytics/.env is ignored.
ENVFILE=$(mktemp)
cat >"$ENVFILE" <<ENV
LOGTHING_FLUSH_INTERVAL_SECS=5
COMMIT_INTERVAL_SECS=10
SYSLOG_UDP_PORT=$SYSLOG_UDP_PORT
SYSLOG_TCP_PORT=25601
IPFIX_PORT=24739
SFLOW_PORT=26343
ZEEK_PORT=47761
LOGTHING_HEALTH_PORT=25985
GARAGE_S3_PORT=23901
LAKEKEEPER_PORT=28182
TRINO_PORT=28080
HUE_PORT=$HUE_PORT
ENV
[ -z "${TRINO_IMAGE:-}" ] || echo "TRINO_IMAGE=$TRINO_IMAGE" >>"$ENVFILE"
[ -z "${HUE_IMAGE:-}" ] || echo "HUE_IMAGE=$HUE_IMAGE" >>"$ENVFILE"
# Don't let image/credential overrides from the caller's shell leak in beyond the two above.
DC=(docker compose -p "$PROJECT" --env-file "$ENVFILE" -f "$ANALYTICS/docker-compose.yml")

cleanup() {
  "${DC[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -f "$ENVFILE"
}
trap cleanup EXIT

dump_logs() { "${DC[@]}" logs --no-color --tail 80 "$@" >&2 || true; }

echo "== [1/5] up (project $PROJECT) =="
timeout 540 "${DC[@]}" up -d --wait || { echo "stack failed to become healthy" >&2; dump_logs; exit 1; }

echo "== [2/5] send $N syslog messages ($MARKER) =="
"$PY" - "$SYSLOG_UDP_PORT" "$N" "$MARKER" <<'PYEOF'
import socket, sys, time
port, n, marker = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
now = time.strftime("%b %e %H:%M:%S")
for i in range(n):
    s.sendto(f"<134>{now} e2ehost analytics-e2e: {marker} message {i}".encode(), ("127.0.0.1", port))
PYEOF

COUNT_SQL="SELECT count(*) FROM iceberg.logs.syslog WHERE message LIKE '%$MARKER%'"
trino_count() {
  "${DC[@]}" exec -T trino trino --output-format TSV --execute "$COUNT_SQL" 2>/dev/null | tr -d '"\r' || true
}

echo "== [3/5] wait (<=300s) for committer to land rows in iceberg.logs.syslog =="
deadline=$(( $(date +%s) + 300 ))
until [ "$(trino_count)" = "$N" ]; do
  if [ "$(date +%s)" -ge "$deadline" ]; then
    echo "timed out after 300s waiting for $N rows in iceberg.logs.syslog" >&2
    dump_logs committer logthing lakekeeper trino
    exit 1
  fi
  sleep 5
done

echo "== [4/5] Trino count =="
[ "$(trino_count)" = "$N" ] || { echo "Trino count mismatch" >&2; exit 1; }
echo "trino: $N"

echo "== [5/5] same query through Hue's REST API =="
HUE_COUNT=$("$PY" "$HERE/hue_query.py" "http://127.0.0.1:$HUE_PORT" admin e2e-admin-pass \
  "SELECT count(*) FROM syslog WHERE message LIKE '%$MARKER%'") \
  || { dump_logs hue trino; exit 1; }
[ "$HUE_COUNT" = "$N" ] || { echo "Hue returned $HUE_COUNT, expected $N" >&2; dump_logs hue; exit 1; }
echo "hue: $HUE_COUNT"

echo "Analytics compose E2E PASSED"

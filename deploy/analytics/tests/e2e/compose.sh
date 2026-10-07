#!/usr/bin/env bash
# End-to-end: compose stack up -> syslog into logthing -> committer -> Trino (HTTPS + password) sees the rows.
# Requires Docker and an AVX2-capable CPU (or a TRINO_IMAGE override such as trinodb/trino:470).
set -euo pipefail
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ANALYTICS=$(cd -- "$HERE/../.." && pwd)
. "$HERE/lib.sh"
preflight_cpu

PROJECT="lt-e2e-$$"
# Non-default host ports so a developer's running stack does not collide.
SYSLOG_UDP_PORT=25514
TRINO_PORT=28443
N=40
MARKER="analytics-e2e-$(date +%s)-$$"
PY=${PYTHON:-python3}

# Hermetic config: an explicit env file means a developer's deploy/analytics/.env is ignored.
ENVFILE=$(mktemp)
"$ANALYTICS/scripts/gen-analytics-env.sh" --force "$ENVFILE" 2>/dev/null
cat >>"$ENVFILE" <<ENV
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
TRINO_PORT=$TRINO_PORT
ENV
[ -z "${TRINO_IMAGE:-}" ] || echo "TRINO_IMAGE=$TRINO_IMAGE" >>"$ENVFILE"
envval() { grep "^$1=" "$ENVFILE" | cut -d= -f2-; }
TRINO_ADMIN_PASSWORD=$(envval TRINO_ADMIN_PASSWORD)
CA=$(mktemp)
# --env-file means a developer's deploy/analytics/.env is ignored. Variables exported in the
# caller's shell still take precedence over this file (compose's normal rule).
DC=(docker compose -p "$PROJECT" --env-file "$ENVFILE" -f "$ANALYTICS/docker-compose.yml")

cleanup() {
  "${DC[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -f "$ENVFILE" "$CA"
}
trap cleanup EXIT

dump_logs() { "${DC[@]}" logs --no-color --tail 80 "$@" >&2 || true; }
fail() { echo "FAIL: $*" >&2; dump_logs trino; exit 1; }
# Run the Trino CLI inside the container (TRINO_PASSWORD is the admin password there).
TRINO_CLI=(trino --server https://localhost:8443 --truststore-path /etc/trino/tls/ca.pem
           --user admin --password)

echo "== [1/5] up (project $PROJECT) =="
timeout 540 "${DC[@]}" up -d --wait || { echo "stack failed to become healthy" >&2; dump_logs; exit 1; }

echo "== [2/5] Trino security: HTTPS + password, negative tests =="
"${DC[@]}" exec -T trino cat /etc/trino/tls/ca.pem >"$CA"
trino_security_checks "https://localhost:$TRINO_PORT" "$CA" "$TRINO_ADMIN_PASSWORD" \
  || { dump_logs trino; exit 1; }
# Topology B: plain-HTTP 8080 exists inside the container only and must never be published.
# (`compose port` prints "invalid IP:0" with exit 0 for an unpublished port.)
case "$("${DC[@]}" port trino 8080 2>/dev/null || true)" in
  ""|*:0) ;;
  *) fail "Trino port 8080 is published to the host" ;;
esac
[ "$("${DC[@]}" exec -T trino "${TRINO_CLI[@]}" --execute 'SELECT 1' | tr -d '"\r')" = 1 ] \
  || fail "Trino CLI over the generated CA failed"
if "${DC[@]}" exec -T -e TRINO_PASSWORD=wrong trino "${TRINO_CLI[@]}" --execute 'SELECT 1' >/dev/null 2>&1; then
  fail "Trino CLI accepted a wrong password"
fi

echo "== [3/5] send $N syslog messages ($MARKER) =="
"$PY" - "$SYSLOG_UDP_PORT" "$N" "$MARKER" <<'PYEOF'
import socket, sys, time
port, n, marker = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
now = time.strftime("%b %e %H:%M:%S")
for i in range(n):
    s.sendto(f"<134>{now} e2ehost analytics-e2e: {marker} message {i}".encode(), ("127.0.0.1", port))
    time.sleep(0.02)  # pace sends so the UDP socket buffer is not overrun; never retried
PYEOF

COUNT_SQL="SELECT count(*) FROM iceberg.logs.syslog WHERE message LIKE '%$MARKER%'"
trino_count() {
  "${DC[@]}" exec -T trino "${TRINO_CLI[@]}" --output-format TSV --execute "$COUNT_SQL" 2>/dev/null \
    | tr -d '"\r' || true
}

echo "== [4/5] wait (<=300s) for committer to land rows in iceberg.logs.syslog =="
deadline=$(( $(date +%s) + 300 ))
until [ "$(trino_count)" = "$N" ]; do
  if [ "$(date +%s)" -ge "$deadline" ]; then
    echo "timed out after 300s waiting for $N rows in iceberg.logs.syslog" >&2
    dump_logs committer logthing lakekeeper trino
    exit 1
  fi
  sleep 5
done

echo "== [5/5] Trino count =="
[ "$(trino_count)" = "$N" ] || { echo "Trino count mismatch" >&2; exit 1; }
echo "trino: $N"

echo "Analytics compose E2E PASSED"

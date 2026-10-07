#!/usr/bin/env bash
# End-to-end: compose stack up -> syslog, Zeek, OTLP and HEC into logthing -> committer -> Trino (HTTPS + password) and Metabase see the rows.
# Requires Docker and an AVX2-capable CPU (or a TRINO_IMAGE override such as trinodb/trino:470).
set -euo pipefail
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ANALYTICS=$(cd -- "$HERE/../.." && pwd)
. "$HERE/lib.sh"
preflight_cpu
DBT=${DBT:-$ANALYTICS/.venv/bin/dbt}
[ -x "$DBT" ] || { echo "dbt not found at $DBT: run $ANALYTICS/.venv/bin/pip install -r $ANALYTICS/tests/requirements.txt (or set DBT=)" >&2; exit 1; }
ENVFILE=""; CA=""; DBT_WORK=""
cleanup() {
  [ -z "${DC:-}" ] || "${DC[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -f "$ENVFILE" "$CA"
  [ -z "$DBT_WORK" ] || rm -rf "$DBT_WORK"
}
trap cleanup EXIT
DBT_WORK=$(mktemp -d)
build_local_images   # logthing + committer from THIS checkout (A1 code); set LOGTHING_IMAGE/COMMITTER_IMAGE to skip

PROJECT="lt-e2e-$$"
# Non-default host ports so a developer's running stack does not collide.
SYSLOG_UDP_PORT=25514
ZEEK_PORT=47761
TRINO_PORT=28443
METABASE_PORT=23000
HTTP_PORT=25985
N=40
MARKER="analytics-e2e-$(date +%s)-$$"
PY=${PYTHON:-python3}
# Bound on `up --wait`. A slow host (Metabase migrations) may need UP_TIMEOUT_SECS=2400 together
# with METABASE_HEALTH_RETRIES=180 in the environment.
UP_TIMEOUT_SECS=${UP_TIMEOUT_SECS:-540}

# Hermetic config: an explicit env file means a developer's deploy/analytics/.env is ignored.
ENVFILE=$(mktemp)
"$ANALYTICS/scripts/gen-analytics-env.sh" --force "$ENVFILE"
cat >>"$ENVFILE" <<ENV
LOGTHING_FLUSH_INTERVAL_SECS=5
COMMIT_INTERVAL_SECS=10
SYSLOG_UDP_PORT=$SYSLOG_UDP_PORT
SYSLOG_TCP_PORT=25601
IPFIX_PORT=24739
SFLOW_PORT=26343
ZEEK_PORT=$ZEEK_PORT
LOGTHING_HEALTH_PORT=$HTTP_PORT
GARAGE_S3_PORT=23901
TRINO_PORT=$TRINO_PORT
METABASE_PORT=$METABASE_PORT
ENV
printf 'LOGTHING_IMAGE=%s\nCOMMITTER_IMAGE=%s\n' "$LOGTHING_IMAGE" "$COMMITTER_IMAGE" >>"$ENVFILE"
[ -z "${TRINO_IMAGE:-}" ] || echo "TRINO_IMAGE=$TRINO_IMAGE" >>"$ENVFILE"
envval() { grep "^$1=" "$ENVFILE" | cut -d= -f2-; }
TRINO_ADMIN_PASSWORD=$(envval TRINO_ADMIN_PASSWORD)
HEC_TOKEN=$(envval HEC_TOKEN)
OTLP_BEARER_TOKEN=$(envval OTLP_BEARER_TOKEN)
CA=$(mktemp)
# --env-file means a developer's deploy/analytics/.env is ignored. Variables exported in the
# caller's shell still take precedence over this file (compose's normal rule).
DC=(docker compose -p "$PROJECT" --env-file "$ENVFILE" -f "$ANALYTICS/docker-compose.yml")

run_dbt() {
  env TRINO_HOST=localhost TRINO_PORT="$TRINO_PORT" TRINO_USER=admin \
    TRINO_PASSWORD="$TRINO_ADMIN_PASSWORD" TRINO_CA_CERT="$CA" DBT_SEND_ANONYMOUS_USAGE_STATS=false \
    "$DBT" --log-path "$DBT_WORK/logs" "$@" --project-dir "$ANALYTICS/dbt" \
    --profiles-dir "$ANALYTICS/dbt" --target-path "$DBT_WORK/target"
}

dump_logs() { "${DC[@]}" logs --no-color --tail 80 "$@" >&2 || true; }
fail() { echo "FAIL: $*" >&2; dump_logs trino; exit 1; }
# Run the Trino CLI inside the container (TRINO_PASSWORD is the admin password there).
TRINO_CLI=(trino --server https://localhost:8443 --truststore-path /etc/trino/tls/ca.pem
           --user admin --password)

echo "== [1/8] up (project $PROJECT) =="
timeout "$UP_TIMEOUT_SECS" "${DC[@]}" up -d --wait || { echo "stack failed to become healthy" >&2; dump_logs; exit 1; }

echo "== [2/8] Trino security: HTTPS + password, negative tests =="
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
# Isolation: Lakekeeper, Postgres and the Garage admin API must not be published to the host.
# (Use Publishers from `ps`: `compose port` exits 0 with "invalid IP:0" when unpublished.)
# `ps --format json` is NDJSON or one array depending on the compose version; the helper
# handles both and refuses an empty listing.
"${DC[@]}" ps --format json | "$PY" "$HERE/published_ports.py" || fail "an internal port is published to the host"
echo "isolation: lakekeeper, postgres and garage admin are not published"

echo "== [3/8] send $N syslog messages ($MARKER) =="
"$PY" - "$SYSLOG_UDP_PORT" "$N" "$MARKER" <<'PYEOF'
import socket, sys, time
port, n, marker = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
now = time.strftime("%b %e %H:%M:%S")
for i in range(n):
    s.sendto(f"<134>{now} e2ehost analytics-e2e: {marker} message {i}".encode(), ("127.0.0.1", port))
    time.sleep(0.02)  # pace sends so the UDP socket buffer is not overrun; never retried
PYEOF

"$PY" - "$ZEEK_PORT" "$MARKER" <<'PYEOF'
import json, socket, sys, time
port, marker = int(sys.argv[1]), sys.argv[2]
ts = time.time()
recs = [
    {"_path": "conn", "ts": ts, "uid": marker, "id.orig_h": "10.20.30.40", "id.orig_p": 51234,
     "id.resp_h": "198.51.100.9", "id.resp_p": 443, "proto": "tcp", "service": "ssl",
     "duration": 1.5, "orig_bytes": 100, "resp_bytes": 2000, "conn_state": "SF",
     "history": "ShADadFf", "orig_pkts": 4, "resp_pkts": 6},
    {"_path": "dns", "ts": ts, "uid": marker, "id.orig_h": "10.20.30.40", "id.orig_p": 53211,
     "id.resp_h": "10.20.30.1", "id.resp_p": 53, "proto": "udp", "trans_id": 4242,
     "query": f"{marker}.example.test", "qtype_name": "A", "qclass_name": "C_INTERNET",
     "rcode_name": "NOERROR", "answers": ["192.0.2.10"]},
]
s = socket.create_connection(("127.0.0.1", port), 10)
for r in recs:
    s.sendall((json.dumps(r) + "\n").encode())
s.close()
PYEOF

echo "== [3b/8] send $N OTLP records and $N HEC events with the generated tokens ($MARKER) =="
HEC_TOKEN=$HEC_TOKEN OTLP_BEARER_TOKEN=$OTLP_BEARER_TOKEN \
  "$PY" "$HERE/send_app_logs.py" "http://127.0.0.1:$HTTP_PORT" "$MARKER" "$N" \
  || { dump_logs logthing; exit 1; }

COUNT_SQL="SELECT count(*) FROM iceberg.logs.syslog WHERE message LIKE '%$MARKER%'"
trino_count() {
  "${DC[@]}" exec -T trino "${TRINO_CLI[@]}" --output-format TSV --execute "$COUNT_SQL" 2>/dev/null \
    | tr -d '"\r' || true
}

echo "== [4/8] wait (<=300s) for committer to land rows in iceberg.logs.syslog =="
deadline=$(( $(date +%s) + 300 ))
until [ "$(trino_count)" = "$N" ]; do
  if [ "$(date +%s)" -ge "$deadline" ]; then
    echo "timed out after 300s waiting for $N rows in iceberg.logs.syslog" >&2
    dump_logs committer logthing lakekeeper trino
    exit 1
  fi
  sleep 5
done

sql() { "${DC[@]}" exec -T trino "${TRINO_CLI[@]}" --output-format TSV --execute "$1" | tr -d '"\r'; }
zeek_landed() { [ "$(sql "SELECT count(*) FROM iceberg.logs.$1 WHERE uid = '$MARKER'")" = 1 ]; }
wait_until 300 "zeek_conn row" zeek_landed zeek_conn || { dump_logs committer logthing; exit 1; }
wait_until 300 "zeek_dns row" zeek_landed zeek_dns || { dump_logs committer logthing; exit 1; }

echo "== [4b/8] wait (<=300s) for OTLP and HEC rows, assert typed columns =="
wait_until 300 "otlp + hec rows" app_logs_landed || { dump_logs committer logthing; exit 1; }
assert_app_log_rows || { dump_logs committer logthing; exit 1; }
echo "otlp: $N typed rows; hec: $N rows with event_uuid"

echo "== [5/8] Trino count =="
[ "$(trino_count)" = "$N" ] || { echo "Trino count mismatch" >&2; exit 1; }
echo "trino: $N"

echo "== [6/8] same query through Metabase's API (Trino over TLS) =="
MB_COUNT=$(METABASE_PASSWORD=$(envval METABASE_ADMIN_PASSWORD) "$PY" "$HERE/metabase_query.py" \
  "http://127.0.0.1:$METABASE_PORT" admin@logthing.example "$COUNT_SQL") \
  || { dump_logs metabase metabase-init trino; exit 1; }
[ "$MB_COUNT" = "$N" ] || { echo "Metabase returned $MB_COUNT, expected $N" >&2; dump_logs metabase; exit 1; }
echo "metabase: $MB_COUNT"
OTLP_MB=$(METABASE_PASSWORD=$(envval METABASE_ADMIN_PASSWORD) "$PY" "$HERE/metabase_query.py" \
  "http://127.0.0.1:$METABASE_PORT" admin@logthing.example \
  "SELECT count(*) FROM iceberg.logs.otlp WHERE $(_otlp_where)") \
  || { dump_logs metabase trino; exit 1; }
[ "$OTLP_MB" = "$N" ] || { echo "Metabase otlp count $OTLP_MB, expected $N" >&2; exit 1; }
echo "metabase otlp: $OTLP_MB"

echo "== [7/8] dbt build (staging views + tests) against Trino over TLS =="
rc=0; DBT_OUT=$(run_dbt build 2>&1) || rc=$?
printf '%s\n' "$DBT_OUT"
dbt_ok "$rc" "$DBT_OUT" || { echo "dbt build failed (exit $rc or ERROR>0 in summary)" >&2; dump_logs trino; exit 1; }
[ "$("${DC[@]}" exec -T trino "${TRINO_CLI[@]}" --output-format TSV \
     --execute "SELECT count(*) FROM iceberg.logs.stg_wef" | tr -d '"\r')" = 0 ] \
  || fail "stg_wef should be empty: this stack sends no WEF data"
echo "dbt: build ok"
assert_staging_dedup || { dump_logs trino; exit 1; }
echo "staging: stg_otlp/stg_hec = $N, duplicate event_uuid deduped"

echo "== [8/8] OCSF views and detection analyses over the Zeek rows =="
[ "$(sql "SELECT count(*) FROM iceberg.logs.ocsf_network_activity WHERE metadata_correlation_uid = '$MARKER' AND class_uid = 4001 AND src_endpoint_ip = '10.20.30.40' AND dst_endpoint_port = 443 AND connection_info_protocol_num = 6")" = 1 ] \
  || fail "ocsf_network_activity did not map the Zeek conn record"
[ "$(sql "SELECT count(*) FROM iceberg.logs.ocsf_dns_activity WHERE metadata_correlation_uid = '$MARKER' AND query_hostname = '$MARKER.example.test' AND activity_id = 2")" = 1 ] \
  || fail "ocsf_dns_activity did not map the Zeek dns record"
run_dbt compile >/dev/null || fail "dbt compile failed"
analyses=0
for f in "$DBT_WORK"/target/compiled/logthing_analytics/analyses/*.sql; do
  sql "$(cat "$f")" >/dev/null || fail "analysis $(basename "$f") failed to execute"
  analyses=$((analyses + 1))
done
[ "$analyses" = 3 ] || fail "expected 3 compiled analyses, found $analyses"
rare=$(sql "$(cat "$DBT_WORK"/target/compiled/logthing_analytics/analyses/detect_rare_outbound_port.sql)")
printf '%s\n' "$rare" | awk -F'\t' '$1 == 443 { found = 1 } END { exit !found }' || fail "detect_rare_outbound_port did not return port 443 on the fresh lake: $rare"
echo "ocsf: network + dns mapped; $analyses analyses executed"

echo "Analytics compose E2E PASSED"

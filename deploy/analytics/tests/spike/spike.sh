#!/usr/bin/env bash
# Spike: Trino HTTPS + password auth, Trino CLI over a PEM CA, Metabase -> Trino over the CA.
# Usage: [TRINO_IMAGE=trinodb/trino:470] deploy/analytics/tests/spike/spike.sh [pem|insecure]
# Prints SPIKE-RESULT lines; exits nonzero on the first hard failure.
set -euo pipefail
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
MODE=${1:-pem}
PROJECT="lt-spike-$$"
ADMIN_PW=spikeAdminPw0123456789
MB_PW=spikeMetabasePw0123456789
ENVFILE=$(mktemp)
CA=$(mktemp)
cat >"$ENVFILE" <<ENV
TRINO_ADMIN_PASSWORD=$ADMIN_PW
TRINO_METABASE_PASSWORD=$MB_PW
TRINO_SHARED_SECRET=spikeSharedSecret0123456789abcdef
ENV
[ -z "${TRINO_IMAGE:-}" ] || echo "TRINO_IMAGE=$TRINO_IMAGE" >>"$ENVFILE"
DC=(docker compose -p "$PROJECT" --env-file "$ENVFILE" -f "$HERE/docker-compose.spike.yml")
cleanup() { "${DC[@]}" down -v --remove-orphans >/dev/null 2>&1 || true; rm -f "$ENVFILE" "$CA"; }
trap cleanup EXIT
result() { echo "SPIKE-RESULT $1=$2"; }
code() { curl -sS -o /dev/null -w '%{http_code}' "$@" 2>/dev/null || true; }
port() { "${DC[@]}" port "$1" "$2" | awk -F: '{print $NF}'; }

if ! "${DC[@]}" up -d --wait trino metabase; then
  "${DC[@]}" logs --no-color --tail 80 trino >&2 || true
  result stack_healthy fail
  exit 1
fi
result stack_healthy pass

"${DC[@]}" exec -T trino cat /etc/trino/tls/ca.pem >"$CA"
TP=$(port trino 8443)
STMT=(-X POST -H 'X-Trino-User: admin' -d 'select 1' "https://localhost:$TP/v1/statement")

[ "$(code --cacert "$CA" "${STMT[@]}")" = 401 ] && result unauth_401 pass || { result unauth_401 fail; exit 1; }
[ "$(code --cacert "$CA" -u "admin:$ADMIN_PW" "${STMT[@]}")" = 200 ] && result auth_200 pass || { result auth_200 fail; exit 1; }
[ "$(code --cacert "$CA" -u "admin:wrong" "${STMT[@]}")" = 401 ] && result wrong_password_401 pass || { result wrong_password_401 fail; exit 1; }
plain=$(code --max-time 5 "http://localhost:$TP/v1/info")
case "$plain" in 000|400) result plain_http_refused pass ;; *) result plain_http_refused "fail($plain)"; exit 1 ;; esac

CLI=(trino --server https://localhost:8443 --truststore-path /etc/trino/tls/ca.pem --user admin --password --execute 'select 1')
if "${DC[@]}" exec -T trino "${CLI[@]}" >/dev/null 2>&1; then
  result cli_pem_truststore pass
else
  result cli_pem_truststore fail
  "${DC[@]}" exec -T trino "${CLI[@]}" 2>&1 | tail -5 >&2 || true
fi

MP=$(port metabase 3000)
TRINO_PASSWORD=$MB_PW python3 "$HERE/spike_metabase.py" "http://localhost:$MP" "$MODE"

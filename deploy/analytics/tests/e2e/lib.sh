# shellcheck shell=bash
# Shared helpers for the analytics e2e scripts. Source, don't execute.

CPUINFO=${CPUINFO:-/proc/cpuinfo}

# Exit 1 unless the CPU has AVX2 or TRINO_IMAGE is overridden. (Metabase and every other image
# run without AVX2; only Trino >= 480 needs x86-64-v3. trinodb/trino:470 is known to start.)
preflight_cpu() {
  if grep -qw avx2 "$CPUINFO"; then return 0; fi
  if [ -n "${TRINO_IMAGE:-}" ]; then
    echo "preflight: CPU lacks AVX2; using override TRINO_IMAGE=$TRINO_IMAGE" >&2
    echo "preflight: this run does NOT verify the default Trino image" >&2
    return 0
  fi
  echo "preflight: this CPU lacks AVX2/x86-64-v3 and trinodb/trino:483 crashes on it. Run on" >&2
  echo "preflight: modern hardware, or set TRINO_IMAGE (e.g. trinodb/trino:470)." >&2
  exit 1
}

# trino_security_checks <https_base_url> <ca_pem> <admin_password>
# HTTP-level negative and positive checks against Trino's HTTPS listener (shared by the compose
# and Helm e2e scripts). Returns 1 with a message on stderr at the first failed check.
trino_security_checks() {
  local url=$1 ca=$2 pw=$3 code
  local stmt=(-X POST -H 'X-Trino-User: admin' -d 'select 1' "$url/v1/statement")
  _tsc_code() { curl -sS -o /dev/null -w '%{http_code}' --max-time 20 "$@" 2>/dev/null || true; }
  [ "$(_tsc_code --cacert "$ca" "${stmt[@]}")" = 401 ] \
    || { echo "FAIL: unauthenticated request must be 401" >&2; return 1; }
  [ "$(_tsc_code --cacert "$ca" -u admin:wrong-password "${stmt[@]}")" = 401 ] \
    || { echo "FAIL: wrong password must be 401" >&2; return 1; }
  [ "$(_tsc_code --cacert "$ca" -u "admin:$pw" "${stmt[@]}")" = 200 ] \
    || { echo "FAIL: valid credentials over the generated CA must be 200" >&2; return 1; }
  # Plain HTTP to the TLS port must never be served (connection error, or 400 from Jetty).
  code=$(_tsc_code --max-time 5 "${url/https:/http:}/v1/info")
  case "$code" in
    000|400) ;;
    *) echo "FAIL: plain HTTP to the TLS port answered $code" >&2; return 1 ;;
  esac
  # A client that does not trust the generated CA must refuse the server certificate.
  if curl -sS -o /dev/null --max-time 10 -u "admin:$pw" "${stmt[@]}" 2>/dev/null; then
    echo "FAIL: client without the CA accepted the server certificate" >&2; return 1
  fi
  echo "trino security: ok"
}

# wait_until <timeout_secs> <description> <cmd...>: poll a simple predicate until it succeeds.
wait_until() {
  local timeout=$1 what=$2; shift 2
  local deadline=$(( $(date +%s) + timeout ))
  until "$@" >/dev/null 2>&1; do
    if [ "$(date +%s)" -ge "$deadline" ]; then
      echo "timed out after ${timeout}s waiting for: $what" >&2
      return 1
    fi
    sleep 3
  done
}

# dbt_ok <exit_code> <output>: dbt succeeded only if it exited 0 AND its summary line reports
# ERROR=0. (Never test "ERROR absent": the summary itself is "Done. PASS=6 WARN=0 ERROR=0 ...".)
dbt_ok() {
  [ "$1" = 0 ] && printf '%s\n' "$2" | grep -Eq 'Done\. PASS=[0-9]+ WARN=[0-9]+ ERROR=0 '
}

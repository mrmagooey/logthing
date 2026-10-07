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

# build_local_images: the stack's logthing and committer images must contain the A1 code
# (typed OTLP sink, HEC columns, committer evolution), which no published image has yet. Build both
# from this checkout. The tag is the commit, plus for a dirty tree "-dirty-<hash of the diff and
# untracked files>", so uncommitted edits never reuse a stale image (docker's layer cache keeps a
# repeat build cheap). Pre-set LOGTHING_IMAGE / COMMITTER_IMAGE to skip a build.
# Needs ANALYTICS (deploy/analytics) from the caller; exports both variables.
build_local_images() {
  local root tag h
  if [ -z "${LOGTHING_IMAGE:-}" ] || [ -z "${COMMITTER_IMAGE:-}" ]; then
    root=$(cd "$ANALYTICS/../.." && pwd)
    tag=$(git -C "$root" rev-parse --short HEAD)
    if [ -n "$(git -C "$root" status --porcelain -- . ':!.codegraph')" ]; then
      h=$({ git -C "$root" diff HEAD -- . ':!.codegraph'
            git -C "$root" ls-files -o --exclude-standard -z -- . ':!.codegraph' \
              | (cd "$root" && xargs -0 -r sha256sum); } | sha256sum | cut -c1-12)
      tag=$tag-dirty-$h
    fi
  fi
  if [ -z "${LOGTHING_IMAGE:-}" ]; then
    LOGTHING_IMAGE=logthing-analytics-e2e/logthing:$tag
    docker build -t "$LOGTHING_IMAGE" "$root" || return 1
  fi
  if [ -z "${COMMITTER_IMAGE:-}" ]; then
    COMMITTER_IMAGE=logthing-analytics-e2e/committer:$tag
    docker build -t "$COMMITTER_IMAGE" "$root/committer" || return 1
  fi
  export LOGTHING_IMAGE COMMITTER_IMAGE
}

# Row selectors for the rows send_app_logs.py wrote (MARKER, N come from the caller).
_otlp_where() { printf "body LIKE '%%%s otlp %%' AND service_name = 'e2e-app'" "$MARKER"; }
_hec_where() { printf "json_extract_scalar(fields, '\$.message') LIKE '%s hec %%'" "$MARKER"; }

# app_logs_landed: true once all N OTLP and N HEC rows are queryable. Predicate for wait_until.
app_logs_landed() {
  [ "$(sql "SELECT count(*) FROM iceberg.logs.otlp WHERE $(_otlp_where)")" = "$N" ] \
    && [ "$(sql "SELECT count(*) FROM iceberg.logs.hec WHERE $(_hec_where)")" = "$N" ]
}

# assert_app_log_rows: typed, complete, uniquely identified rows in both tables.
assert_app_log_rows() {
  local w
  w=$(_otlp_where)
  [ "$(sql "SELECT count(*) FROM iceberg.logs.otlp WHERE $w AND severity_number = 9 AND event_uuid IS NOT NULL AND \"time\" IS NOT NULL AND host_name = 'e2ehost' AND json_extract_scalar(attributes, '\$[\"http.route\"]') = '/e2e'")" = "$N" ] \
    || { fail "otlp rows missing typed values (service/severity/time/host/attributes)"; return 1; }
  [ "$(sql "SELECT count(distinct event_uuid) FROM iceberg.logs.otlp WHERE $w")" = "$N" ] \
    || { fail "otlp event_uuid not unique"; return 1; }
  [ "$(sql "SELECT typeof(severity_number) || '/' || typeof(\"time\") FROM iceberg.logs.otlp WHERE $w LIMIT 1")" = "integer/timestamp(6) with time zone" ] \
    || { fail "otlp column types are not integer / timestamp(6) with time zone"; return 1; }
  w=$(_hec_where)
  [ "$(sql "SELECT count(*) FROM iceberg.logs.hec WHERE $w AND event_uuid IS NOT NULL AND source = 'e2e' AND \"index\" = 'main' AND sourcetype = 'e2e:app' AND json_extract_scalar(indexed_fields, '\$.env') = 'e2e'")" = "$N" ] \
    || { fail "hec rows missing event_uuid/source/index/indexed_fields"; return 1; }
  [ "$(sql "SELECT count(distinct event_uuid) FROM iceberg.logs.hec WHERE $w")" = "$N" ] \
    || { fail "hec event_uuid not unique"; return 1; }
}

# assert_staging_dedup: after `dbt build`, stg_otlp/stg_hec hold N rows each; then one OTLP row is
# re-inserted (a duplicate event_uuid, as a retried committer file would produce): the raw table
# gains a row and the staging view does not. logthing never reuses a uuid, so this is the only
# way to put a duplicate into the lake from outside.
assert_staging_dedup() {
  local ow hw
  ow=$(_otlp_where); hw=$(_hec_where)
  [ "$(sql "SELECT count(*) FROM iceberg.logs.stg_otlp WHERE $ow")" = "$N" ] \
    || { fail "stg_otlp row count != $N"; return 1; }
  [ "$(sql "SELECT count(*) FROM iceberg.logs.stg_hec WHERE $hw")" = "$N" ] \
    || { fail "stg_hec row count != $N"; return 1; }
  sql "INSERT INTO iceberg.logs.otlp SELECT * FROM iceberg.logs.otlp WHERE $ow AND body LIKE '% otlp 0'" >/dev/null \
    || { fail "could not insert a duplicate otlp row"; return 1; }
  [ "$(sql "SELECT count(*) FROM iceberg.logs.otlp WHERE $ow")" = "$((N + 1))" ] \
    || { fail "duplicate otlp row was not inserted"; return 1; }
  [ "$(sql "SELECT count(*) FROM iceberg.logs.stg_otlp WHERE $ow")" = "$N" ] \
    || { fail "stg_otlp did not dedup the duplicate event_uuid"; return 1; }
}

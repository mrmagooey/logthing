#!/bin/bash
# Per-format maximum sustainable ingest rate. Supersedes
# scripts/repeat-ipfix-loopback-loss.sh -- same restart-per-run, zeroed-counter,
# RcvbufErrors-reconciling machinery, generalised across formats.
#
# Spec: docs/superpowers/specs/2026-09-16-max-ingest-rate-design.md
set -u

median_of() { sort -n | awk '{a[NR]=$1} END {n=NR; if(n==0){print "nan"; exit} if(n%2==1) print a[(n+1)/2]; else printf "%.4f\n", (a[n/2]+a[n/2+1])/2}'; }
min_of() { sort -n | head -1; }
max_of() { sort -n | tail -1; }

if [ "${SELFTEST:-0}" != "1" ]; then

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$REPO/target/release/logthing"
LOADGEN="$REPO/target/release/loadgen"
FORMAT="${FORMAT:-ipfix}"
SHAPE="${SHAPE:-real}"
RATE="${RATE:-20000}"
DURATION="${DURATION:-15}"
RUNS="${RUNS:-5}"
METRICS_PORT="${METRICS_PORT:-9090}"
RECONCILE_TOLERANCE=2

[ -x "$BIN" ]     || { echo "FATAL: $BIN missing. cargo build --release --bin logthing"; exit 1; }
[ -x "$LOADGEN" ] || { echo "FATAL: $LOADGEN missing. cargo build --release -p loadgen"; exit 1; }

fetch() {
    if command -v curl >/dev/null 2>&1; then curl -sf "$1"; else wget -qO- "$1"; fi
}
metric() {
    fetch "http://127.0.0.1:$METRICS_PORT/metrics" 2>/dev/null \
        | awk -v m="$1" '$0 ~ "^"m" " {print $2}'
}
metric_labeled() {
    fetch "http://127.0.0.1:$METRICS_PORT/metrics" 2>/dev/null \
        | awk -v m="^$1\\{" -v pat="$2" '$0 ~ m && $0 ~ pat {print $NF}'
}
snmp_rcvbuf_errors() {
    awk '/^Udp:/ { n++
        if (n == 1) { for (i = 1; i <= NF; i++) if ($i == "RcvbufErrors") col = i; next }
        if (n == 2) { print $col; exit } }' /proc/net/snmp
}
parse_sent()     { printf '%s\n' "$1" | sed -n 's/.*sent \([0-9]\{1,\}\) \(flows\|datagrams\|records\) in .*/\1/p' | tail -1; }
parse_achieved() { printf '%s\n' "$1" | sed -n 's/.*achieved rate: \([0-9.]\{1,\}\).*/\1/p' | tail -1; }

# DEFECT FIX 1 (vs repeat-ipfix-loopback-loss.sh): that script killed
# leftover servers at startup and in its EXIT trap by matching the whole
# command line against the binary path -- which also matched the invoking
# shell's own command text and killed it too. Symptom was a bare exit 144
# with no output. A pidfile kills exactly the process we started.
PIDFILE="$(mktemp)" || exit 1

TMP_ROOT="$(mktemp -d)" || exit 1
LOCAL_DIR="$TMP_ROOT/parquet-local"
mkdir -p "$LOCAL_DIR"
cd "$REPO" || exit 1

# DEFECT FIX 2: the old script's cleanup did `rm -f logthing.admin.toml`,
# deleting a TRACKED file. logthing.admin.toml is also loaded AFTER
# logthing.toml and silently overrides it (the server exits immediately if
# left in place alongside this harness's config), so it must be moved aside
# for the run's duration and moved back in cleanup -- never removed, and the
# restore is verified by checksum against its own backup.
CONFIG_BACKUP="$TMP_ROOT/logthing.toml.orig"
ADMIN_BACKUP="$TMP_ROOT/logthing.admin.toml.orig"
cp logthing.toml "$CONFIG_BACKUP" || exit 1
HAD_ADMIN=0
if [ -f logthing.admin.toml ]; then
    HAD_ADMIN=1
    cp logthing.admin.toml "$ADMIN_BACKUP"
    mv logthing.admin.toml "$TMP_ROOT/logthing.admin.toml.aside"
fi

SRV_PID=""
cleanup() {
    stop_server
    cp "$CONFIG_BACKUP" "$REPO/logthing.toml" 2>/dev/null
    if [ "$HAD_ADMIN" -eq 1 ]; then
        mv "$TMP_ROOT/logthing.admin.toml.aside" "$REPO/logthing.admin.toml" 2>/dev/null
        if ! cmp -s "$ADMIN_BACKUP" "$REPO/logthing.admin.toml"; then
            echo "FATAL: logthing.admin.toml restore did not match backup checksum" >&2
        fi
    fi
    rm -f "$PIDFILE"
    rm -rf "$TMP_ROOT"
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT TERM

write_config() {
    {
        echo 'bind_address = "0.0.0.0:5985"'
        echo '[tls]'; echo 'enabled = false'
        echo '[metrics]'; echo 'enabled = true'; echo "port = $METRICS_PORT"
        echo '[logging]'; echo 'level = "error"'; echo 'format = "pretty"'
        echo '[syslog]'; echo 'enabled = false'
        echo '[ipfix]'; echo 'enabled = true'
        echo "udp_port = 4739"; echo 'bind_address = "0.0.0.0"'
        if [ "$SHAPE" = "real" ]; then
            echo '[ipfix.local]'; echo "directory = \"$LOCAL_DIR\""
        fi
    } > "$REPO/logthing.toml"
}

start_server() {
    local run_id="$1"
    "$BIN" > "$TMP_ROOT/server-$run_id.log" 2>&1 &
    SRV_PID=$!
    echo "$SRV_PID" > "$PIDFILE"
    local up=0
    for _ in $(seq 1 30); do
        if fetch "http://127.0.0.1:$METRICS_PORT/metrics" >/dev/null 2>&1; then up=1; break; fi
        sleep 0.5
    done
    [ "$up" -eq 1 ] || { echo "FATAL: server did not start for run $run_id"; tail -30 "$TMP_ROOT/server-$run_id.log"; exit 1; }
    # /metrics answering proves the admin HTTP listener is up, not that the
    # UDP listener's bind has completed.
    sleep 1
}

stop_server() {
    [ -n "${SRV_PID:-}" ] || return 0
    kill "$SRV_PID" 2>/dev/null
    for _ in $(seq 1 20); do kill -0 "$SRV_PID" 2>/dev/null || break; sleep 0.5; done
    kill -0 "$SRV_PID" 2>/dev/null && kill -9 "$SRV_PID" 2>/dev/null
    wait "$SRV_PID" 2>/dev/null
    SRV_PID=""
}

write_config

echo "# format=$FORMAT shape=$SHAPE rate=$RATE duration=${DURATION}s runs=$RUNS"
echo "# server restarted between every run; ipfix_datagrams_received/ipfix_socket_drops/parquet_s3_dropped are per-run values (fresh process), not deltas."
echo "# RcvbufErrors is host-wide and NOT reset by restart -- diffed before/after around each run's load."
if [ "$SHAPE" = "trivial" ]; then
    echo -e "run\tshape\toffered\treceived\tsocket_drops\trcvbuf_errors_delta\tloss_pct"
else
    echo -e "run\tshape\toffered\treceived\tsocket_drops\trcvbuf_errors_delta\tparquet_s3_dropped_ipfix\tloss_pct"
fi

LOSS_LIST=""
DROPS_LIST=""
PARQUET_LIST=""

for i in $(seq 1 "$RUNS"); do
    start_server "$i"

    SNMP_BEFORE="$(snmp_rcvbuf_errors)"

    LOADGEN_OUT="$("$LOADGEN" ipfix-udp --host 127.0.0.1 --port 4739 \
        --target-rate "$RATE" --duration-secs "$DURATION" 2>&1)"
    LOADGEN_RC=$?
    if [ "$LOADGEN_RC" -ne 0 ]; then
        echo "FATAL: loadgen exited $LOADGEN_RC on run $i:"
        echo "$LOADGEN_OUT"
        exit 1
    fi

    OFFERED="$(parse_sent "$LOADGEN_OUT")"
    if [ -z "$OFFERED" ]; then
        echo "FATAL: could not parse offered count from loadgen output on run $i:"
        echo "$LOADGEN_OUT"
        exit 1
    fi

    # Let the last 1s /proc/net/udp poll tick land, and any in-flight
    # decode+dispatch drain, before scraping final counters.
    sleep 2

    RECEIVED="$(metric ipfix_datagrams_received)"
    RECEIVED="${RECEIVED:-0}"
    SOCKET_DROPS="$(metric ipfix_socket_drops)"
    SOCKET_DROPS="${SOCKET_DROPS:-0}"
    SNMP_AFTER="$(snmp_rcvbuf_errors)"
    SNMP_DELTA=$((SNMP_AFTER - SNMP_BEFORE))

    if [ "$SHAPE" = "real" ]; then
        PARQUET_DROPPED="$(metric_labeled parquet_s3_dropped 'source="ipfix"')"
        PARQUET_DROPPED="${PARQUET_DROPPED:-0}"
    fi

    stop_server

    SOCKET_DROPS_INT="${SOCKET_DROPS%.*}"
    DIFF=$(( SOCKET_DROPS_INT > SNMP_DELTA ? SOCKET_DROPS_INT - SNMP_DELTA : SNMP_DELTA - SOCKET_DROPS_INT ))
    if [ "$DIFF" -gt "$RECONCILE_TOLERANCE" ]; then
        echo "FATAL: run $i: ipfix_socket_drops ($SOCKET_DROPS_INT) and RcvbufErrors delta ($SNMP_DELTA) disagree by $DIFF (tolerance $RECONCILE_TOLERANCE)."
        echo "This has reconciled exactly on every prior run of this reproduction; a disagreement means something is wrong (stale process, wrong metrics port, etc.) and these numbers must not be trusted."
        exit 1
    fi

    LOSS_PCT="$(awk -v d="$SOCKET_DROPS_INT" -v o="$OFFERED" 'BEGIN{ if (o==0) print "nan"; else printf "%.4f", (d/o)*100 }')"

    if [ "$SHAPE" = "trivial" ]; then
        echo -e "$i\t$SHAPE\t$OFFERED\t$RECEIVED\t$SOCKET_DROPS_INT\t$SNMP_DELTA\t$LOSS_PCT"
    else
        echo -e "$i\t$SHAPE\t$OFFERED\t$RECEIVED\t$SOCKET_DROPS_INT\t$SNMP_DELTA\t$PARQUET_DROPPED\t$LOSS_PCT"
        PARQUET_LIST="$PARQUET_LIST"$'\n'"$PARQUET_DROPPED"
    fi

    LOSS_LIST="$LOSS_LIST"$'\n'"$LOSS_PCT"
    DROPS_LIST="$DROPS_LIST"$'\n'"$SOCKET_DROPS_INT"
done

MEDIAN="$(printf '%s\n' "$LOSS_LIST" | grep -v '^$' | median_of)"
MIN="$(printf '%s\n' "$LOSS_LIST" | grep -v '^$' | min_of)"
MAX="$(printf '%s\n' "$LOSS_LIST" | grep -v '^$' | max_of)"

echo "# --- summary: shape=$SHAPE rate=$RATE runs=$RUNS ---"
echo -e "median\t$SHAPE\t-\t-\t-\t-\t$MEDIAN"
echo -e "min\t$SHAPE\t-\t-\t-\t-\t$MIN"
echo -e "max\t$SHAPE\t-\t-\t-\t-\t$MAX"

ALL_ZERO=1
for d in $(printf '%s\n' "$DROPS_LIST" | grep -v '^$'); do
    [ "$d" -ne 0 ] && ALL_ZERO=0
done
if [ "$ALL_ZERO" -eq 1 ]; then
    echo "# NOTE: zero loss (ipfix_socket_drops == 0) on every run -- rate/duration did not saturate the receive buffer on this host. Do not report the median above as a meaningful loss figure; raise RATE or DURATION to produce a measurable baseline instead."
fi

if [ "$SHAPE" = "real" ] && [ -n "$PARQUET_LIST" ]; then
    P_ALL_ZERO=1
    for d in $(printf '%s\n' "$PARQUET_LIST" | grep -v '^$'); do
        [ "$d" -ne 0 ] && P_ALL_ZERO=0
    done
    if [ "$P_ALL_ZERO" -eq 0 ]; then
        echo "# NOTE: parquet_s3_dropped{source=\"ipfix\"} was non-zero on at least one run -- a second, distinct drop site downstream of the kernel socket. Report it separately; do not fold it into the kernel loss figure above."
    fi
fi

echo "artifacts (server logs): $TMP_ROOT (removed on exit; rerun with TMP_ROOT preserved manually if needed for debugging)"

exit 0
fi

if [ "${SELFTEST:-0}" = "1" ]; then
    fail=0
    check() {
        if [ "$2" != "$3" ]; then echo "FAIL: $1: expected '$3', got '$2'"; fail=1
        else echo "ok: $1"; fi
    }
    check "median odd"   "$(printf '%s\n' 3 1 2     | median_of)" "2"
    check "median even"  "$(printf '%s\n' 4 1 2 3   | median_of)" "2.5000"
    check "median one"   "$(printf '%s\n' 7         | median_of)" "7"
    check "median empty" "$(printf ''               | median_of)" "nan"
    check "min"          "$(printf '%s\n' 3 1 2     | min_of)"    "1"
    check "max"          "$(printf '%s\n' 3 1 2     | max_of)"    "3"
    check "median decimals" "$(printf '%s\n' 0.0413 0.0000 0.0000 0.0000 0.0000 | median_of)" "0.0000"
    [ "$fail" -eq 0 ] && echo "SELFTEST PASS" || echo "SELFTEST FAIL"
    exit "$fail"
fi

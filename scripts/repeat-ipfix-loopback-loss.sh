#!/bin/bash
# Repeat the loopback IPFIX loss reproduction N times and report per-run and
# aggregate (median/min/max) loss, for both handler shapes.
#
# Why N repeats: every loss figure in this repo so far is single-run, and
# run-to-run spread is large enough to swallow the effects being measured
# (see docs/performance/2026-09-14-throughput-baseline-repeats.md). Tier 1's
# acceptance gate needs a median and a [min, max] range per shape, not one
# number -- this script (finding #8's non-profiling cousin of
# scripts/profile-ipfix-udp.sh) produces exactly that.
#
# Why both handler shapes: DefaultIpfixHandler (trivial) never allocates or
# touches parquet_s3_dropped, so it can't show Tier 1's main risk (per-
# datagram allocation under a real handler) or its guard metric. A real
# [ipfix.local] sink is local-disk only -- no external service needed.
#
# Server is restarted between every run so every counter this script reads
# starts at zero for that run -- no delta bookkeeping needed for
# ipfix_datagrams_received / ipfix_socket_drops / parquet_s3_dropped.
# /proc/net/snmp's RcvbufErrors is host-wide and NOT reset by a restart, so
# it is always diffed before/after around the load run regardless.
#
# Parameters (env vars, matching scripts/profile-ipfix-udp.sh's convention):
#   RATE      target flows/s offered to the generator (default 20000)
#   DURATION  generator duration in seconds (default 15)
#   RUNS      number of repeats (default 5)
#   SHAPE     "trivial" (DefaultIpfixHandler, no sink) or
#             "real" ([ipfix.local] Parquet sink, temp dir) (default trivial)
#
# Example:
#   RATE=20000 DURATION=15 RUNS=5 SHAPE=trivial ./scripts/repeat-ipfix-loopback-loss.sh
#   RATE=20000 DURATION=15 RUNS=5 SHAPE=real    ./scripts/repeat-ipfix-loopback-loss.sh
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
RATE="${RATE:-20000}"
DURATION="${DURATION:-15}"
RUNS="${RUNS:-5}"
SHAPE="${SHAPE:-trivial}"
METRICS_PORT="${METRICS_PORT:-9090}"
IPFIX_PORT="${IPFIX_PORT:-4739}"
RECONCILE_TOLERANCE=2

BIN="$REPO/target/release/logthing"
LOADGEN="$REPO/target/release/loadgen"

case "$SHAPE" in
    trivial|real) ;;
    *) echo "FATAL: SHAPE must be 'trivial' or 'real', got '$SHAPE'"; exit 1 ;;
esac

if [ ! -x "$BIN" ]; then
    echo "FATAL: $BIN not found. Build it first: cargo build --release --bin logthing"
    exit 1
fi
if [ ! -x "$LOADGEN" ]; then
    echo "FATAL: $LOADGEN not found. Build it first: cargo build --release -p loadgen"
    exit 1
fi

# curl is absent from the docker e2e image but present locally; wget is
# available everywhere this script has been run. Try curl first, fall back.
fetch() {
    if command -v curl >/dev/null 2>&1; then
        curl -sf "$1"
    else
        wget -qO- "$1"
    fi
}

metric() {
    fetch "http://127.0.0.1:$METRICS_PORT/metrics" 2>/dev/null \
        | awk -v m="$1" '$0 ~ "^"m" " {print $2}'
}

# For labelled metrics (parquet_s3_dropped{source="ipfix",target="local"} N).
# Match on the metric name as a brace-prefixed anchor plus a label
# substring, and take the last whitespace-separated field (the value) --
# robust to label ordering, since metrics-exporter-prometheus doesn't
# guarantee it.
metric_labeled() {
    fetch "http://127.0.0.1:$METRICS_PORT/metrics" 2>/dev/null \
        | awk -v m="^$1\\{" -v pat="$2" '$0 ~ m && $0 ~ pat {print $NF}'
}

# RcvbufErrors' column index is read from the header line rather than
# hardcoded, in case kernel version changes the column order.
snmp_rcvbuf_errors() {
    awk '
        /^Udp:/ {
            n++
            if (n == 1) {
                for (i = 1; i <= NF; i++) if ($i == "RcvbufErrors") col = i
                next
            }
            if (n == 2) { print $col; exit }
        }
    ' /proc/net/snmp
}

median_of() { sort -n | awk '{a[NR]=$1} END {n=NR; if(n==0){print "nan"; exit} if(n%2==1) print a[(n+1)/2]; else printf "%.4f\n", (a[n/2]+a[n/2+1])/2}'; }
min_of() { sort -n | head -1; }
max_of() { sort -n | tail -1; }

echo "Cleaning up leftover logthing processes (a stale one holding port $IPFIX_PORT silently invalidates a run)..."
pkill -f "$BIN" 2>/dev/null || true
sleep 1

TMP_ROOT="$(mktemp -d)" || { echo "FATAL: mktemp -d failed"; exit 1; }
LOCAL_DIR="$TMP_ROOT/parquet-local"
mkdir -p "$LOCAL_DIR"

cd "$REPO" || { echo "FATAL: cd to $REPO failed"; exit 1; }
CONFIG_BACKUP="$TMP_ROOT/logthing.toml.orig"
ADMIN_BACKUP="$TMP_ROOT/logthing.admin.toml.orig"
HAD_ADMIN=0
cp logthing.toml "$CONFIG_BACKUP" || { echo "FATAL: backup of logthing.toml failed"; exit 1; }
if [ -f logthing.admin.toml ]; then
    HAD_ADMIN=1
    cp logthing.admin.toml "$ADMIN_BACKUP"
fi

SRV_PID=""
cleanup() {
    if [ -n "$SRV_PID" ]; then
        kill "$SRV_PID" 2>/dev/null
        sleep 1
        kill -9 "$SRV_PID" 2>/dev/null
    fi
    [ -f "$CONFIG_BACKUP" ] && cp "$CONFIG_BACKUP" "$REPO/logthing.toml"
    rm -f "$REPO/logthing.admin.toml"
    if [ "$HAD_ADMIN" -eq 1 ] && [ -f "$ADMIN_BACKUP" ]; then
        cp "$ADMIN_BACKUP" "$REPO/logthing.admin.toml"
    fi
    rm -rf "$TMP_ROOT"
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT TERM

rm -f logthing.admin.toml

write_config() {
    {
        echo 'bind_address = "0.0.0.0:5985"'
        echo '[tls]'
        echo 'enabled = false'
        echo '[metrics]'
        echo 'enabled = true'
        echo "port = $METRICS_PORT"
        echo '[syslog]'
        echo 'enabled = false'
        echo '[ipfix]'
        echo 'enabled = true'
        echo "udp_port = $IPFIX_PORT"
        echo 'bind_address = "0.0.0.0"'
        if [ "$SHAPE" = "real" ]; then
            echo '[ipfix.local]'
            echo "directory = \"$LOCAL_DIR\""
        fi
        echo '[logging]'
        echo 'level = "error"'
        echo 'format = "pretty"'
    } > "$REPO/logthing.toml"
}

write_config

start_server() {
    local run_id="$1"
    LOGTHING__IPFIX__ENABLED=true \
    LOGTHING__SYSLOG__ENABLED=false \
        "$BIN" > "$TMP_ROOT/server-$run_id.log" 2>&1 &
    SRV_PID=$!
    local up=0
    for _ in $(seq 1 30); do
        if fetch "http://127.0.0.1:$METRICS_PORT/metrics" >/dev/null 2>&1; then
            up=1
            break
        fi
        sleep 0.5
    done
    if [ "$up" -ne 1 ]; then
        echo "FATAL: server did not come up for run $run_id; see $TMP_ROOT/server-$run_id.log"
        tail -30 "$TMP_ROOT/server-$run_id.log"
        exit 1
    fi
    # Small settle time: /metrics answering proves the HTTP admin listener is
    # up, not necessarily that the UDP listener's bind has completed.
    sleep 1
}

stop_server() {
    if [ -n "$SRV_PID" ]; then
        kill "$SRV_PID" 2>/dev/null
        for _ in $(seq 1 20); do
            kill -0 "$SRV_PID" 2>/dev/null || break
            sleep 0.5
        done
        kill -0 "$SRV_PID" 2>/dev/null && kill -9 "$SRV_PID" 2>/dev/null
        wait "$SRV_PID" 2>/dev/null
    fi
    SRV_PID=""
}

echo "# shape=$SHAPE rate=$RATE duration=${DURATION}s runs=$RUNS"
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

    LOADGEN_OUT="$("$LOADGEN" ipfix-udp --host 127.0.0.1 --port "$IPFIX_PORT" \
        --target-rate "$RATE" --duration-secs "$DURATION" 2>&1)"
    LOADGEN_RC=$?
    if [ "$LOADGEN_RC" -ne 0 ]; then
        echo "FATAL: loadgen exited $LOADGEN_RC on run $i:"
        echo "$LOADGEN_OUT"
        exit 1
    fi

    OFFERED="$(printf '%s\n' "$LOADGEN_OUT" | sed -n 's/.*sent \([0-9]\+\) flows.*/\1/p' | tail -1)"
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

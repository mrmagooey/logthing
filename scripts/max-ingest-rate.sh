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

# Sink `source` labels below are the sinks' own source() values
# (src/forwarding/*_s3.rs). Note `generic` and `hec` share BOTH the received
# counter (src/ingest/handlers.rs:219) and the sink label
# (src/forwarding/generic_s3.rs:163) -- they are indistinguishable in the
# metrics, which is why this harness runs exactly one format per invocation.
#
# PORT env var overrides the per-format default (e.g. binding syslog's
# standard UDP 514 requires root/CAP_NET_BIND_SERVICE; without it, rerun with
# PORT=<unprivileged port> and say so in any results reported).
resolve_format() {
    STRUCTURED="${STRUCTURED:-0}"
    local port_override="${PORT:-}"
    case "${FORMAT:-}" in
        syslog)
            SUB="syslog-udp"; PORT=514; TRANSPORT=udp
            RECV_METRIC="syslog_messages_received"; DROP_METRIC="syslog_socket_drops"
            CONFIG_SECTION="syslog"
            if [ "$STRUCTURED" = "1" ]; then SOURCE_LABEL="structured_syslog"; else SOURCE_LABEL="syslog"; fi
            ;;
        ipfix)
            SUB="ipfix-udp"; PORT=4739; TRANSPORT=udp
            RECV_METRIC="ipfix_datagrams_received"; DROP_METRIC="ipfix_socket_drops"
            SOURCE_LABEL="ipfix"; CONFIG_SECTION="ipfix" ;;
        sflow)
            SUB="sflow-udp"; PORT=6343; TRANSPORT=udp
            RECV_METRIC="sflow_datagrams_received"; DROP_METRIC="sflow_socket_drops"
            SOURCE_LABEL="sflow"; CONFIG_SECTION="sflow" ;;
        zeek)
            SUB="zeek-tcp"; PORT=47760; TRANSPORT=tcp
            RECV_METRIC="zeek_records_received"; DROP_METRIC=""
            SOURCE_LABEL="zeek"; CONFIG_SECTION="zeek" ;;
        suricata)
            SUB="suricata-tcp"; PORT=47761; TRANSPORT=tcp
            RECV_METRIC="suricata_records_received"; DROP_METRIC=""
            SOURCE_LABEL="suricata"; CONFIG_SECTION="suricata" ;;
        hec)
            SUB="hec-http"; PORT=5985; TRANSPORT=http
            RECV_METRIC="hec_events_received"; DROP_METRIC=""
            SOURCE_LABEL="hec"; CONFIG_SECTION="hec" ;;
        generic)
            SUB="generic-http"; PORT=5985; TRANSPORT=http
            RECV_METRIC="hec_events_received"; DROP_METRIC=""
            SOURCE_LABEL="hec"; CONFIG_SECTION="hec" ;;
        *)
            echo "FATAL: unknown FORMAT '${FORMAT:-}' (want one of: syslog ipfix sflow zeek suricata hec generic)" >&2
            return 1 ;;
    esac
    [ -n "$port_override" ] && PORT="$port_override"
    return 0
}

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
# Real-shape local sinks flush on this interval (write_config below); a run
# shorter than twice it can end before the first flush ever fires, so
# parquet_s3_records_written stays 0/absent and the liveness assertion FATALs
# with a message that (correctly, but unhelpfully in a hurry) blames the sink
# rather than DURATION. Single source of truth for both write_config and the
# guard right below, so the two can never drift apart.
FLUSH_INTERVAL_SECS=5

resolve_format || exit 1

[ -x "$BIN" ]     || { echo "FATAL: $BIN missing. cargo build --release --bin logthing"; exit 1; }
[ -x "$LOADGEN" ] || { echo "FATAL: $LOADGEN missing. cargo build --release -p loadgen"; exit 1; }

if [ "$SHAPE" = "real" ] && [ "$DURATION" -lt $((FLUSH_INTERVAL_SECS * 2)) ]; then
    echo "FATAL: real-shape runs need DURATION >= $((FLUSH_INTERVAL_SECS * 2))s because the local sink is configured with flush_interval_secs=$FLUSH_INTERVAL_SECS and nothing is durably written before the first flush; use a longer DURATION, or SHAPE=trivial if you do not need the writer path."
    exit 1
fi

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
#
# DEFECT FIX 2: the old script's cleanup did `rm -f logthing.admin.toml`,
# deleting a TRACKED file. logthing.admin.toml is also loaded AFTER
# logthing.toml and silently overrides it (the server exits immediately if
# left in place alongside this harness's config), so it must be moved aside
# for the run's duration and moved back in cleanup -- never removed, and the
# restore is verified by checksum against its own backup.
#
# `cleanup` is defined and both traps are registered BEFORE any tracked
# file is touched (before PIDFILE/TMP_ROOT even exist), so a signal landing
# anywhere after this point -- including in the couple of statements before
# logthing.admin.toml is actually moved aside -- always has a handler ready
# to put things back. Every var cleanup touches is pre-declared empty so
# `set -u` doesn't choke if cleanup runs before that var is ever assigned,
# and every restore step is individually guarded on its source existing.
SRV_PID=""
PIDFILE=""
TMP_ROOT=""
CONFIG_BACKUP=""
ADMIN_BACKUP=""
HAD_ADMIN=0
cleanup() {
    stop_server
    [ -n "$CONFIG_BACKUP" ] && [ -f "$CONFIG_BACKUP" ] && cp "$CONFIG_BACKUP" "$REPO/logthing.toml" 2>/dev/null
    if [ "$HAD_ADMIN" -eq 1 ] && [ -n "$TMP_ROOT" ] && [ -f "$TMP_ROOT/logthing.admin.toml.aside" ]; then
        mv "$TMP_ROOT/logthing.admin.toml.aside" "$REPO/logthing.admin.toml" 2>/dev/null
        if ! cmp -s "$ADMIN_BACKUP" "$REPO/logthing.admin.toml"; then
            echo "FATAL: logthing.admin.toml restore did not match backup checksum" >&2
        fi
    fi
    [ -n "$PIDFILE" ] && rm -f "$PIDFILE"
    [ -n "$TMP_ROOT" ] && rm -rf "$TMP_ROOT"
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT TERM

PIDFILE="$(mktemp)" || exit 1

TMP_ROOT="$(mktemp -d)" || exit 1
LOCAL_DIR="$TMP_ROOT/parquet-local"
mkdir -p "$LOCAL_DIR"
cd "$REPO" || exit 1

CONFIG_BACKUP="$TMP_ROOT/logthing.toml.orig"
ADMIN_BACKUP="$TMP_ROOT/logthing.admin.toml.orig"
cp logthing.toml "$CONFIG_BACKUP" || exit 1
if [ -f logthing.admin.toml ]; then
    HAD_ADMIN=1
    cp logthing.admin.toml "$ADMIN_BACKUP"
    mv logthing.admin.toml "$TMP_ROOT/logthing.admin.toml.aside"
fi

write_config() {
    {
        echo 'bind_address = "0.0.0.0:5985"'
        echo '[tls]'; echo 'enabled = false'
        echo '[metrics]'; echo 'enabled = true'; echo "port = $METRICS_PORT"
        echo '[logging]'; echo 'level = "error"'; echo 'format = "pretty"'
        # Every listener off by default, so an unrelated one can never bind a
        # port or consume CPU during another format's run. Skipped when the
        # format under test IS syslog -- the enabled section is written once,
        # below, instead of contradicting/duplicating this off line.
        if [ "$CONFIG_SECTION" != "syslog" ]; then
            echo '[syslog]'; echo 'enabled = false'
        fi

        case "$TRANSPORT" in
            udp)
                echo "[$CONFIG_SECTION]"; echo 'enabled = true'
                echo "udp_port = $PORT"
                if [ "$CONFIG_SECTION" = "syslog" ]; then
                    # SyslogListener always binds tcp_port too (default 601,
                    # itself a privileged port -- see src/config/mod.rs
                    # default_syslog_tcp_port), even though this harness only
                    # drives the UDP arm. Pin it next to PORT so overriding
                    # PORT to an unprivileged value actually gets the server
                    # to start, instead of leaving the privileged TCP default
                    # in place to fail the bind on its own.
                    echo "tcp_port = $((PORT + 1))"
                fi
                echo 'bind_address = "0.0.0.0"' ;;
            tcp)
                echo "[$CONFIG_SECTION]"; echo 'enabled = true'
                echo "tcp_port = $PORT"; echo 'bind_address = "0.0.0.0"' ;;
            http)
                echo '[hec]'; echo 'enabled = true'; echo 'token = ""' ;;
        esac

        if [ "$SHAPE" = "real" ]; then
            # flush_interval_secs defaults to 900s and flush_threshold_bytes
            # to 100 MiB; a short run reaches neither, so the writer buffers
            # everything and flushes nothing durably -- parquet_s3_records_written
            # would be absent from /metrics entirely (not zero: the counter
            # doesn't exist until the first flush). Force a flush well inside
            # DURATION so the real shape exercises the actual write path.
            echo "[$CONFIG_SECTION.local]"
            echo "directory = \"$LOCAL_DIR\""
            echo "flush_interval_secs = $FLUSH_INTERVAL_SECS"
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

run_generator() {
    local rate="$1" secs="$2"
    local extra=""
    case "$FORMAT" in
        hec|generic) extra="--events-per-request ${EVENTS_PER_REQUEST:-1} --concurrency ${CONCURRENCY:-64}" ;;
        syslog)      [ "${STRUCTURED:-0}" = "1" ] && extra="--structured" ;;
    esac
    # shellcheck disable=SC2086
    "$LOADGEN" "$SUB" --host 127.0.0.1 --port "$PORT" \
        --target-rate "$rate" --duration-secs "$secs" $extra 2>&1
}

# Prints: received  kernel_drops  writer_drops  buffer_drops  written
scrape_losses() {
    local recv kd wd bd wr
    recv="$(metric "$RECV_METRIC")"; recv="${recv:-0}"
    if [ -n "$DROP_METRIC" ]; then kd="$(metric "$DROP_METRIC")"; kd="${kd:-0}"; else kd="n/a"; fi
    wd="$(metric_labeled parquet_s3_dropped "source=\"$SOURCE_LABEL\"")";        wd="${wd:-0}"
    bd="$(metric_labeled parquet_s3_buffer_dropped "source=\"$SOURCE_LABEL\"")"; bd="${bd:-0}"
    wr="$(metric_labeled parquet_s3_records_written "source=\"$SOURCE_LABEL\"")"; wr="${wr:-0}"
    printf '%s\t%s\t%s\t%s\t%s\n' "$recv" "$kd" "$wd" "$bd" "$wr"
}

write_config

echo "# format=$FORMAT shape=$SHAPE rate=$RATE duration=${DURATION}s runs=$RUNS transport=$TRANSPORT port=$PORT"
DROP_METRIC_DISPLAY="${DROP_METRIC:-n/a}"
echo "# server restarted between every run; $RECV_METRIC/$DROP_METRIC_DISPLAY/parquet_s3_dropped are per-run values (fresh process), not deltas."
if [ -n "$DROP_METRIC" ]; then
    echo "# RcvbufErrors is host-wide and NOT reset by restart -- diffed before/after around each run's load."
fi
echo -e "run\tformat\tshape\toffered\tachieved\treceived\tkernel_drops\twriter_drops\tbuffer_drops\twritten\tloss_pct"

LOSS_LIST=""
DROPS_LIST=""
WRITER_DROPS_LIST=""

for i in $(seq 1 "$RUNS"); do
    start_server "$i"

    SNMP_BEFORE="$(snmp_rcvbuf_errors)"

    LOADGEN_OUT="$(run_generator "$RATE" "$DURATION")"
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
    ACHIEVED="$(parse_achieved "$LOADGEN_OUT")"
    ACHIEVED="${ACHIEVED:-n/a}"

    # Let the last 1s /proc/net/udp poll tick land, and any in-flight
    # decode+dispatch drain, before scraping final counters.
    sleep 2

    SCRAPE="$(scrape_losses)"
    RECEIVED="$(printf '%s' "$SCRAPE" | cut -f1)"
    KERNEL_DROPS="$(printf '%s' "$SCRAPE" | cut -f2)"
    WRITER_DROPS="$(printf '%s' "$SCRAPE" | cut -f3)"
    BUFFER_DROPS="$(printf '%s' "$SCRAPE" | cut -f4)"
    WRITTEN="$(printf '%s' "$SCRAPE" | cut -f5)"
    SNMP_AFTER="$(snmp_rcvbuf_errors)"
    SNMP_DELTA=$((SNMP_AFTER - SNMP_BEFORE))

    stop_server

    # Guarded on DROP_METRIC being set: TCP and HTTP cannot lose datagrams
    # in a socket buffer, so there is nothing here to reconcile against
    # RcvbufErrors -- skipped, not reported as zero.
    if [ -n "$DROP_METRIC" ]; then
        KERNEL_DROPS_INT="${KERNEL_DROPS%.*}"
        DIFF=$(( KERNEL_DROPS_INT > SNMP_DELTA ? KERNEL_DROPS_INT - SNMP_DELTA : SNMP_DELTA - KERNEL_DROPS_INT ))
        if [ "$DIFF" -gt "$RECONCILE_TOLERANCE" ]; then
            echo "FATAL: run $i: $DROP_METRIC ($KERNEL_DROPS_INT) and RcvbufErrors delta ($SNMP_DELTA) disagree by $DIFF (tolerance $RECONCILE_TOLERANCE)."
            echo "This has reconciled exactly on every prior run of this reproduction; a disagreement means something is wrong (stale process, wrong metrics port, etc.) and these numbers must not be trusted."
            exit 1
        fi
    fi

    # Liveness assertion: a real-shape sink that never durably wrote
    # anything (0, or absent from /metrics entirely and defaulted to 0
    # above) did not exercise the write path this run is supposed to
    # measure -- e.g. flush_interval_secs/flush_threshold_bytes never
    # tripped inside DURATION. That is not "zero loss"; it means the run's
    # numbers are meaningless and must not be reported. Treated exactly as
    # seriously as the RcvbufErrors reconciliation check above.
    if [ "$SHAPE" = "real" ]; then
        WRITTEN_INT="${WRITTEN%.*}"
        if [ "$WRITTEN_INT" -eq 0 ]; then
            echo "FATAL: run $i: parquet_s3_records_written{source=\"$SOURCE_LABEL\"} was 0 (or absent) -- the sink produced no durable writes this run. This run is invalid, not lossless; check flush_interval_secs/flush_threshold_bytes against DURATION."
            exit 1
        fi
    fi

    if [ -n "$DROP_METRIC" ]; then
        LOSS_PCT="$(awk -v d="$KERNEL_DROPS_INT" -v o="$OFFERED" 'BEGIN{ if (o==0) print "nan"; else printf "%.4f", (d/o)*100 }')"
    else
        LOSS_PCT="n/a"
    fi

    echo -e "$i\t$FORMAT\t$SHAPE\t$OFFERED\t$ACHIEVED\t$RECEIVED\t$KERNEL_DROPS\t$WRITER_DROPS\t$BUFFER_DROPS\t$WRITTEN\t$LOSS_PCT"

    if [ -n "$DROP_METRIC" ]; then
        LOSS_LIST="$LOSS_LIST"$'\n'"$LOSS_PCT"
        DROPS_LIST="$DROPS_LIST"$'\n'"$KERNEL_DROPS_INT"
    fi
    WRITER_DROPS_LIST="$WRITER_DROPS_LIST"$'\n'"$WRITER_DROPS"
done

echo "# --- summary: format=$FORMAT shape=$SHAPE rate=$RATE runs=$RUNS ---"
if [ -n "$DROP_METRIC" ]; then
    MEDIAN="$(printf '%s\n' "$LOSS_LIST" | grep -v '^$' | median_of)"
    MIN="$(printf '%s\n' "$LOSS_LIST" | grep -v '^$' | min_of)"
    MAX="$(printf '%s\n' "$LOSS_LIST" | grep -v '^$' | max_of)"

    echo -e "median\t$FORMAT\t$SHAPE\t-\t-\t-\t-\t-\t-\t-\t$MEDIAN"
    echo -e "min\t$FORMAT\t$SHAPE\t-\t-\t-\t-\t-\t-\t-\t$MIN"
    echo -e "max\t$FORMAT\t$SHAPE\t-\t-\t-\t-\t-\t-\t-\t$MAX"

    ALL_ZERO=1
    for d in $(printf '%s\n' "$DROPS_LIST" | grep -v '^$'); do
        [ "$d" -ne 0 ] && ALL_ZERO=0
    done
    if [ "$ALL_ZERO" -eq 1 ]; then
        echo "# NOTE: zero loss ($DROP_METRIC == 0) on every run -- rate/duration did not saturate the receive buffer on this host. Do not report the median above as a meaningful loss figure; raise RATE or DURATION to produce a measurable baseline instead."
    fi
else
    echo "# kernel-loss is not applicable for format=$FORMAT (transport=$TRANSPORT cannot lose datagrams in a socket buffer): loss_pct/median/min/max and the RcvbufErrors reconciliation are skipped above, not reported as zero."
fi

if [ "$SHAPE" = "real" ] && [ -n "$WRITER_DROPS_LIST" ]; then
    P_ALL_ZERO=1
    for d in $(printf '%s\n' "$WRITER_DROPS_LIST" | grep -v '^$'); do
        [ "$d" -ne 0 ] && P_ALL_ZERO=0
    done
    if [ "$P_ALL_ZERO" -eq 0 ]; then
        echo "# NOTE: parquet_s3_dropped{source=\"$SOURCE_LABEL\"} was non-zero on at least one run -- a second, distinct drop site downstream of the kernel socket. Report it separately; do not fold it into the kernel loss figure above."
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
    check "resolve ipfix sub"     "$(FORMAT=ipfix    resolve_format && echo "$SUB")"          "ipfix-udp"
    check "resolve ipfix drop"    "$(FORMAT=ipfix    resolve_format && echo "$DROP_METRIC")"  "ipfix_socket_drops"
    check "resolve zeek drop"     "$(FORMAT=zeek     resolve_format && echo "$DROP_METRIC")"  ""
    check "resolve zeek recv"     "$(FORMAT=zeek     resolve_format && echo "$RECV_METRIC")"  "zeek_records_received"
    check "resolve generic label" "$(FORMAT=generic  resolve_format && echo "$SOURCE_LABEL")" "hec"
    check "resolve hec label"     "$(FORMAT=hec      resolve_format && echo "$SOURCE_LABEL")" "hec"
    check "resolve suricata port" "$(FORMAT=suricata resolve_format && echo "$PORT")"         "47761"
    check "resolve sflow recv"    "$(FORMAT=sflow    resolve_format && echo "$RECV_METRIC")"  "sflow_datagrams_received"
    check "resolve syslog struct" "$(FORMAT=syslog STRUCTURED=1 resolve_format && echo "$SOURCE_LABEL")" "structured_syslog"
    check "resolve syslog plain"  "$(FORMAT=syslog STRUCTURED=0 resolve_format && echo "$SOURCE_LABEL")" "syslog"
    check "resolve unknown rc"    "$(FORMAT=nope resolve_format >/dev/null 2>&1; echo $?)"    "1"
    [ "$fail" -eq 0 ] && echo "SELFTEST PASS" || echo "SELFTEST FAIL"
    exit "$fail"
fi

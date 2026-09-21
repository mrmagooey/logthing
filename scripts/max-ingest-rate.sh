#!/bin/bash
# Per-format maximum sustainable ingest rate. Supersedes
# scripts/repeat-ipfix-loopback-loss.sh -- same restart-per-run, zeroed-counter,
# socket-drop-reconciling machinery, generalised across formats.
#
# Spec: docs/superpowers/specs/2026-09-16-max-ingest-rate-design.md
set -u

median_of() { sort -n | awk '{a[NR]=$1} END {n=NR; if(n==0){print "nan"; exit} if(n%2==1) print a[(n+1)/2]; else printf "%.4f\n", (a[n/2]+a[n/2+1])/2}'; }
min_of() { sort -n | head -1; }
max_of() { sort -n | tail -1; }

# Sums the drops field (last column) across every /proc/net/udp row (read
# from stdin) whose local_address (2nd column) equals $1 -- rather than
# taking just the first match -- so a port shared by more than one socket
# (SO_REUSEPORT) reports the total, not one socket's share of it. Defined
# up here, outside the SELFTEST gate below, purely as text-processing over
# stdin so SELFTEST can drive it against fixture text instead of the live
# table; socket_rcvbuf_drops (which knows about $PORT and the real
# /proc/net/udp path) wraps this for actual use. Always prints a number
# (0 when nothing matches), never empty, so callers can do arithmetic on
# the result unconditionally.
sum_proc_net_udp_drops() {
    local needle="$1"
    awk -v needle="$needle" 'NR>1 && $2==needle {sum+=$NF} END {print sum+0}'
}

# Fraction of target the generator must actually achieve for the run's loss
# figure to mean anything. docs/performance/2026-09-13-multiformat-load-results.md
# §2 read zeek achieving 15,283/s against a 20,000/s target as a generator
# ceiling; on TCP that signature is equally consistent with server
# backpressure. This harness refuses to call either one a ceiling.
ACHIEVED_FLOOR_PCT="${ACHIEVED_FLOOR_PCT:-99}"

classify_run() {
    local achieved="$1" target="$2" loss="$3" budget="$4"
    if [ "$target" != "0" ]; then
        local ok
        ok="$(awk -v a="$achieved" -v t="$target" -v f="$ACHIEVED_FLOOR_PCT" \
              'BEGIN { print (a >= t * f / 100) ? 1 : 0 }')"
        if [ "$ok" != "1" ]; then echo "GENERATOR-LIMITED"; return 0; fi
    fi
    if [ "$(awk -v l="$loss" -v b="$budget" 'BEGIN { print (l <= b) ? 1 : 0 }')" = "1" ]; then
        echo "PASS"
    else
        echo "FAIL-LOSS"
    fi
}

# Classifies an entire rate from the achieved-rate and loss series across
# ALL of its runs (each a newline-separated list, one value per run) --
# never from a single run. A lone scheduling hiccup on a shared host (one
# run out of RUNS dipping under ACHIEVED_FLOOR_PCT while the rest comfortably
# clear it) must not poison a rate the generator otherwise offered fine; see
# the ACHIEVED_FLOOR_PCT comment above. Per-run verdicts are still computed
# and printed by run_one -- that audit trail is unchanged. This is only the
# gate, and the gate now looks at the median achieved rate and median loss,
# both describing the same set of runs.
classify_rate() {
    local achieveds="$1" losses="$2" target="$3" budget="$4"
    local med_ach med
    med_ach="$(printf '%s' "$achieveds" | grep -v '^$' | median_of)"
    med="$(printf '%s' "$losses" | grep -v '^$' | median_of)"
    classify_run "$med_ach" "$target" "$med" "$budget"
}

BISECT_RESOLUTION="${BISECT_RESOLUTION:-1000}"
RAMP_MAX="${RAMP_MAX:-500000}"

# Coarse doubling to the first failing rate, then bisect between the last
# passing and first failing rate down to BISECT_RESOLUTION. A linear sweep
# would spend most of its runs far below the answer. Calls `measure_rate`,
# defined below for real use and overridden by a stub in SELFTEST so the
# search itself is under test, not the server. A GENERATOR-LIMITED verdict
# anywhere aborts the search and is reported as itself -- never treated as a
# failing rate, which would report the generator's limit as the server's
# ceiling (see the module comment on ACHIEVED_FLOOR_PCT for why that
# conflation is a documented past mistake, not a hypothetical one).
#
# HARD-FAILURE gets the identical abort-and-report treatment, for the same
# reason: an infrastructure failure (server wouldn't start, the socket-drop
# reconciliation disagreed, the writer-liveness check fired) says nothing
# about whether the rate itself is sustainable. Without this arm it falls
# into the default `*)` branch below and gets bisected exactly like a real
# FAIL-LOSS, producing a confident-looking `CEILING <n>` from a run that
# never actually measured loss at that rate -- the one output this whole
# harness exists to never print. Four outcomes, each meaning something
# different: PASS/FAIL-LOSS drive the search, GENERATOR-LIMITED and
# HARD-FAILURE both abort it, and neither collapses into CEILING.
ramp() {
    local rate="$1" last_pass=0 first_fail=0 verdict

    while [ "$rate" -le "$RAMP_MAX" ]; do
        verdict="$(measure_rate "$rate")"
        case "$verdict" in
            PASS)              last_pass="$rate" ;;
            GENERATOR-LIMITED) echo "GENERATOR-LIMITED $rate"; return 0 ;;
            HARD-FAILURE)      echo "HARD-FAILURE $rate"; return 0 ;;
            *)                 first_fail="$rate"; break ;;
        esac
        rate=$((rate * 2))
    done

    if [ "$first_fail" -eq 0 ]; then
        echo "NO-CEILING-FOUND $last_pass"
        return 0
    fi

    while [ $((first_fail - last_pass)) -gt "$BISECT_RESOLUTION" ]; do
        local mid=$(( (last_pass + first_fail) / 2 ))
        verdict="$(measure_rate "$mid")"
        case "$verdict" in
            PASS)              last_pass="$mid" ;;
            GENERATOR-LIMITED) echo "GENERATOR-LIMITED $mid"; return 0 ;;
            HARD-FAILURE)      echo "HARD-FAILURE $mid"; return 0 ;;
            *)                 first_fail="$mid" ;;
        esac
    done

    echo "CEILING $last_pass"
}

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
            RECV_METRIC="syslog_messages_received"; DROP_METRIC="syslog_udp_socket_drops"
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
# Unset by default -> ramp mode (see the RATE-set/unset branch near the end
# of this block). Set RATE explicitly for the old fixed-rate reproductions.
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
# Disjoint cpusets so generator and server never contend for the same cores
# -- a shared core would make either side's CPU figure (and thus the
# generator-saturation verdict) reflect contention instead of the thing it
# claims to measure. 12 vCPU host: generator 0-3, server 4-11.
GEN_CPUS="${GEN_CPUS:-0-3}"
SRV_CPUS="${SRV_CPUS:-4-11}"
# Concurrent generator processes (not threads -- that in-process --workers
# flag was cancelled). One loadgen process tops out well below some formats'
# real server ceiling; splitting the target rate across GEN_PROCS processes,
# all still pinned to GEN_CPUS, lets the harness reach past a single
# process's own ceiling. Default 1 keeps today's behaviour unchanged.
GEN_PROCS="${GEN_PROCS:-1}"
# See design doc §6.3: passing requires median total loss <= LOSS_BUDGET
# (percent) AND the generator achieving >= ACHIEVED_FLOOR_PCT of target in
# every run; classify_run checks the latter first (see its own comment).
LOSS_BUDGET="${LOSS_BUDGET:-0.1}"

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
# Per-socket drop counter for our own listener's UDP socket, read straight
# from the same /proc/net/udp field src/net.rs's SocketDropStats polls to
# produce $DROP_METRIC. Deliberately NOT /proc/net/snmp's Udp: RcvbufErrors:
# that figure is host-wide -- it sums every UDP socket on the machine,
# including ones that open and close mid-window -- so on a shared host,
# unrelated traffic (another tenant, a stray unrelated listener) can move it
# while this listener itself drops nothing. Matching on local_address (bind
# address + port in hex), not just port, for the same reason
# parse_proc_net_udp in src/net.rs does: two sockets can share a port bound
# to different addresses. Bind address is always 0.0.0.0 (write_config
# above), so only /proc/net/udp is relevant -- this harness never binds v6.
#
# Sums across every socket on that port (sum_proc_net_udp_drops, defined
# near the top of the file so SELFTEST can exercise it against fixture text
# without needing a live /proc/net/udp) rather than taking just the first --
# SO_REUSEPORT puts more than one socket on the same local_address:port, and
# stopping at the first would silently discard every other socket's drops.
socket_rcvbuf_drops() {
    local port_hex
    port_hex="$(printf '%04X' "$PORT")"
    sum_proc_net_udp_drops "00000000:$port_hex" < /proc/net/udp
}
parse_sent()     { printf '%s\n' "$1" | sed -n 's/.*sent \([0-9]\{1,\}\) \(flows\|datagrams\|records\) in .*/\1/p' | tail -1; }
parse_achieved() { printf '%s\n' "$1" | sed -n 's/.*achieved rate: \([0-9.]\{1,\}\).*/\1/p' | tail -1; }

# utime+stime in clock ticks from /proc/<pid>/stat (fields 14 and 15). Read
# before and after the load burst and diff; divide by `getconf CLK_TCK` and
# the wall-clock duration to get cores-used. A generator at ~4.0 cores on a
# 4-core cpuset IS the ceiling, and the run must be read as generator-limited
# regardless of what classify_run says about the rate.
cpu_ticks() {
    awk '{print $14 + $15}' "/proc/$1/stat" 2>/dev/null || echo 0
}
CLK_TCK="$(getconf CLK_TCK)"
cores_used() {
    local tick_delta="$1" wall_secs="$2"
    awk -v d="$tick_delta" -v s="$wall_secs" -v hz="$CLK_TCK" \
        'BEGIN { if (s <= 0) { print "0.00" } else { printf "%.2f", (d / hz) / s } }'
}

# DEFECT FIX 1 (vs repeat-ipfix-loopback-loss.sh): that script killed
# leftover servers at startup and in its EXIT trap by matching the whole
# command line against the binary path -- which also matched the invoking
# shell's own command text and killed it too. Symptom was a bare exit 144
# with no output. A pidfile kills exactly the process we started.
#
# DEFECT FIX 2: the old script's cleanup did `rm -f logthing.admin.toml`,
# deleting a file that was tracked at the time. logthing.admin.toml is no
# longer read by the server at all -- a leftover copy only produces a
# startup WARN now, it does not override logthing.toml -- but if a copy
# exists on disk it's still moved aside for the run's duration and moved
# back in cleanup, never removed, since this harness has no business
# deleting a file it doesn't own. The restore is verified by checksum
# against its own backup.
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
    if [ -n "$CONFIG_BACKUP" ] && [ -f "$CONFIG_BACKUP" ]; then
        cp "$CONFIG_BACKUP" "$REPO/logthing.toml" 2>/dev/null
        if ! cmp -s "$CONFIG_BACKUP" "$REPO/logthing.toml"; then
            echo "FATAL: logthing.toml restore did not match backup checksum" >&2
        fi
    fi
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
    taskset -c "$SRV_CPUS" "$BIN" > "$TMP_ROOT/server-$run_id.log" 2>&1 &
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

# Reports GEN_CORES back to the caller through a file under $TMP_ROOT, not
# a global -- the caller invokes this via `$(run_generator ...)` to capture
# loadgen's stdout, which forks a subshell; a plain variable assignment in
# here would be lost when that subshell exits. Backgrounded so its own CPU
# ticks can be polled while it runs; /proc/<pid>/stat is gone by the time a
# foregrounded `wait` returns, which is too late to read a meaningful
# "after" sample.
run_generator() {
    local rate="$1" secs="$2"
    local extra=""
    case "$FORMAT" in
        hec|generic) extra="--events-per-request ${EVENTS_PER_REQUEST:-1} --concurrency ${CONCURRENCY:-64}" ;;
        syslog)      [ "${STRUCTURED:-0}" = "1" ] && extra="--structured" ;;
    esac
    local n="${GEN_PROCS:-1}"

    if [ "$n" -le 1 ]; then
        # Single-process path, byte-for-byte unchanged from before GEN_PROCS
        # existed -- GEN_PROCS=1 (the default) must mean exactly what it
        # meant before this knob was added.
        local out_file
        out_file="$(mktemp)"
        # shellcheck disable=SC2086
        taskset -c "$GEN_CPUS" "$LOADGEN" "$SUB" --host 127.0.0.1 --port "$PORT" \
            --target-rate "$rate" --duration-secs "$secs" $extra > "$out_file" 2>&1 &
        local gen_pid=$! gen_before gen_after
        gen_before="$(cpu_ticks "$gen_pid")"
        gen_after="$gen_before"
        while kill -0 "$gen_pid" 2>/dev/null; do
            gen_after="$(cpu_ticks "$gen_pid")"
            sleep 0.5
        done
        wait "$gen_pid"
        local gen_rc=$?
        cores_used "$((gen_after - gen_before))" "$secs" > "$TMP_ROOT/gen_cores.txt"
        cat "$out_file"
        rm -f "$out_file"
        return "$gen_rc"
    fi

    # GEN_PROCS>1: split the target rate across N concurrent generator
    # processes (processes, not threads -- the in-process --workers flag
    # is still cancelled) so the offered load can exceed one process's own
    # ceiling. Remainder from integer division goes to the first
    # `remainder` processes so the parts sum to exactly `rate` -- dropping
    # it would silently under-offer load that reads back as a server limit.
    # All N stay inside GEN_CPUS; the server keeps SRV_CPUS untouched.
    local base=$((rate / n)) remainder=$((rate % n))
    local pids="" out_files="" i rp out_file
    for i in $(seq 1 "$n"); do
        rp="$base"
        [ "$i" -le "$remainder" ] && rp=$((base + 1))
        out_file="$(mktemp)"
        out_files="$out_files $out_file"
        # shellcheck disable=SC2086
        taskset -c "$GEN_CPUS" "$LOADGEN" "$SUB" --host 127.0.0.1 --port "$PORT" \
            --target-rate "$rp" --duration-secs "$secs" $extra > "$out_file" 2>&1 &
        pids="$pids $!"
    done

    local pid gen_before=0 gen_after=0 sum alive
    for pid in $pids; do gen_before=$((gen_before + $(cpu_ticks "$pid"))); done
    gen_after="$gen_before"
    alive=1
    while [ "$alive" -eq 1 ]; do
        alive=0
        sum=0
        for pid in $pids; do
            kill -0 "$pid" 2>/dev/null && alive=1
            sum=$((sum + $(cpu_ticks "$pid")))
        done
        gen_after="$sum"
        [ "$alive" -eq 1 ] && sleep 0.5
    done

    # Wait only on the pids this call spawned -- a bare `wait` would also
    # block on anything else backgrounded in this script (e.g. the server),
    # which has already caused a hang once in this plan.
    local gen_rc=0
    for pid in $pids; do
        wait "$pid" || gen_rc=1
    done
    cores_used "$((gen_after - gen_before))" "$secs" > "$TMP_ROOT/gen_cores.txt"

    # Sum each process's own sent/achieved figures via the existing parsers
    # so classify_run's 99% floor applies to the aggregate the harness
    # actually offered, not to any single process's share of it. Raw
    # per-process output is echoed first (for FATAL-path debugging); the
    # synthesized totals are echoed last so parse_sent/parse_achieved's
    # `tail -1` picks up the aggregate instead of one process's numbers.
    local total_sent=0 total_ach=0 content s a
    for out_file in $out_files; do
        content="$(cat "$out_file")"
        echo "$content"
        s="$(parse_sent "$content")"
        a="$(parse_achieved "$content")"
        [ -n "$s" ] && total_sent=$((total_sent + s))
        [ -n "$a" ] && total_ach="$(awk -v x="$total_ach" -v y="$a" 'BEGIN{printf "%.4f", x+y}')"
        rm -f "$out_file"
    done
    echo "sent $total_sent records in ${secs}s (GEN_PROCS=$n)"
    echo "achieved rate: $total_ach"
    return "$gen_rc"
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

# Polls parquet_s3_records_written until it stops climbing, so in-flight rows
# have actually landed (or been dropped) before scrape_losses reads the drop
# counters -- NOT so offered-minus-written can be treated as loss (it isn't:
# total loss is the sum of the three drop-site counters over offered,
# independent of parquet_s3_records_written; the written counter is used here
# purely as a settle signal because it is the counter that moves last).
DRAIN_MAX_SECS="${DRAIN_MAX_SECS:-30}"
drain_until_stable() {
    local metric_name="$1" label="$2"
    local prev="" cur elapsed=0
    while [ "$elapsed" -lt "$DRAIN_MAX_SECS" ]; do
        sleep 2; elapsed=$((elapsed + 2))
        cur="$(metric_labeled "$metric_name" "source=\"$label\"")"
        cur="${cur:-0}"
        if [ "$cur" = "$prev" ]; then echo "$cur"; return 0; fi
        prev="$cur"
    done
    echo "WARN: $metric_name still climbing after ${DRAIN_MAX_SECS}s; this run's written count is a lower bound" >&2
    echo "$prev"
}

write_config

echo "# format=$FORMAT shape=$SHAPE duration=${DURATION}s runs=$RUNS transport=$TRANSPORT port=$PORT"
DROP_METRIC_DISPLAY="${DROP_METRIC:-n/a}"
echo "# server restarted between every run; $RECV_METRIC/$DROP_METRIC_DISPLAY/parquet_s3_dropped are per-run values (fresh process), not deltas."
if [ -n "$DROP_METRIC" ]; then
    echo "# $DROP_METRIC is reconciled against this run's own socket's /proc/net/udp drop counter (NOT host-wide RcvbufErrors), diffed before/after around each run's load."
fi
echo -e "run\tformat\tshape\toffered\tachieved\treceived\tkernel_drops\twriter_drops\tbuffer_drops\twritten\tkernel_loss_pct\ttotal_loss_pct\tgen_cores\tsrv_cores\tverdict"

# Runs one full restart-generate-scrape-verdict cycle at `rate`, printed as
# run `run_id`. Sets RUN_LOSS (total_loss_pct: the three-drop-site total over
# offered -- NOT (offered-written)/offered, which would report near-total
# "loss" on every short run since parquet_s3_records_written legitimately
# still has rows buffered) and RUN_ACHIEVED for the caller, and returns
# non-zero only on a hard failure (server wouldn't start, loadgen failed,
# the socket-drop reconciliation disagreed, or the real-shape liveness check
# failed) -- never for a merely bad rate, which is a verdict, not a failure.
run_one() {
    local run_id="$1" rate="$2"
    # Reset every call so a stale value can never leak into a later run's
    # verdict -- each hard-failure branch below sets this explicitly right
    # before its `return 1`, so the caller never has to infer "hard failure"
    # from an empty/unset variable.
    RUN_VERDICT=""
    start_server "$run_id"

    SOCK_DROPS_BEFORE="$(socket_rcvbuf_drops)"

    SRV_BEFORE="$(cpu_ticks "$SRV_PID")"
    LOADGEN_OUT="$(run_generator "$rate" "$DURATION")"
    LOADGEN_RC=$?
    SRV_AFTER="$(cpu_ticks "$SRV_PID")"
    SRV_CORES="$(cores_used "$((SRV_AFTER - SRV_BEFORE))" "$DURATION")"
    GEN_CORES="$(cat "$TMP_ROOT/gen_cores.txt" 2>/dev/null || echo n/a)"
    if [ "$LOADGEN_RC" -ne 0 ]; then
        echo "FATAL: loadgen exited $LOADGEN_RC on run $run_id:"
        echo "$LOADGEN_OUT"
        RUN_VERDICT="HARD-FAILURE"
        return 1
    fi

    OFFERED="$(parse_sent "$LOADGEN_OUT")"
    if [ -z "$OFFERED" ]; then
        echo "FATAL: could not parse offered count from loadgen output on run $run_id:"
        echo "$LOADGEN_OUT"
        RUN_VERDICT="HARD-FAILURE"
        return 1
    fi
    ACHIEVED="$(parse_achieved "$LOADGEN_OUT")"
    ACHIEVED="${ACHIEVED:-n/a}"

    if [ "$SHAPE" = "real" ]; then
        # Poll the writer's own counter to stability so the drop counters
        # scraped below reflect settled state, not rows still in flight.
        drain_until_stable parquet_s3_records_written "$SOURCE_LABEL" >/dev/null
    else
        # trivial shape has no writer; just let the last 1s /proc/net/udp
        # poll tick land.
        sleep 2
    fi

    SCRAPE="$(scrape_losses)"
    RECEIVED="$(printf '%s' "$SCRAPE" | cut -f1)"
    KERNEL_DROPS="$(printf '%s' "$SCRAPE" | cut -f2)"
    WRITER_DROPS="$(printf '%s' "$SCRAPE" | cut -f3)"
    BUFFER_DROPS="$(printf '%s' "$SCRAPE" | cut -f4)"
    WRITTEN="$(printf '%s' "$SCRAPE" | cut -f5)"
    SOCK_DROPS_AFTER="$(socket_rcvbuf_drops)"
    SOCK_DROPS_DELTA=$((SOCK_DROPS_AFTER - SOCK_DROPS_BEFORE))

    stop_server

    # Guarded on DROP_METRIC being set: TCP and HTTP cannot lose datagrams
    # in a socket buffer, so there is nothing here to reconcile -- skipped,
    # not reported as zero.
    if [ -n "$DROP_METRIC" ]; then
        KERNEL_DROPS_INT="${KERNEL_DROPS%.*}"
        DIFF=$(( KERNEL_DROPS_INT > SOCK_DROPS_DELTA ? KERNEL_DROPS_INT - SOCK_DROPS_DELTA : SOCK_DROPS_DELTA - KERNEL_DROPS_INT ))
        if [ "$DIFF" -gt "$RECONCILE_TOLERANCE" ]; then
            echo "FATAL: run $run_id: $DROP_METRIC ($KERNEL_DROPS_INT) and this run's own socket's /proc/net/udp drop delta ($SOCK_DROPS_DELTA) disagree by $DIFF (tolerance $RECONCILE_TOLERANCE)."
            echo "This has reconciled exactly on every prior run of this reproduction; a disagreement means something is wrong (stale process, wrong metrics port, etc.) and these numbers must not be trusted."
            RUN_VERDICT="HARD-FAILURE"
            return 1
        fi
    fi

    # Liveness assertion: a real-shape sink that never durably wrote
    # anything (0, or absent from /metrics entirely and defaulted to 0
    # above) did not exercise the write path this run is supposed to
    # measure -- e.g. flush_interval_secs/flush_threshold_bytes never
    # tripped inside DURATION. That is not "zero loss"; it means the run's
    # numbers are meaningless and must not be reported. Treated exactly as
    # seriously as the socket-drop reconciliation check above.
    if [ "$SHAPE" = "real" ]; then
        WRITTEN_INT="${WRITTEN%.*}"
        if [ "$WRITTEN_INT" -eq 0 ]; then
            echo "FATAL: run $run_id: parquet_s3_records_written{source=\"$SOURCE_LABEL\"} was 0 (or absent) -- the sink produced no durable writes this run. This run is invalid, not lossless; check flush_interval_secs/flush_threshold_bytes against DURATION."
            RUN_VERDICT="HARD-FAILURE"
            return 1
        fi
    fi

    if [ -n "$DROP_METRIC" ]; then
        KERNEL_LOSS_PCT="$(awk -v d="$KERNEL_DROPS_INT" -v o="$OFFERED" 'BEGIN{ if (o==0) print "nan"; else printf "%.4f", (d/o)*100 }')"
    else
        KERNEL_LOSS_PCT="n/a"
    fi

    # Total loss for the verdict: kernel socket drops (0 contribution where
    # not applicable -- TCP/HTTP genuinely cannot lose datagrams in a socket
    # buffer, so 0 is correct here, not a stand-in for "unmeasured") plus the
    # two writer-side drop sites, over offered. Independent of
    # parquet_s3_records_written -- see drain_until_stable's comment. This is
    # the figure classify_run actually acts on, so it is reported as its own
    # column (total_loss_pct) alongside the kernel-only figure above -- a
    # FAIL-LOSS row must show the number that produced that verdict without
    # the reader summing three columns and dividing by offered themselves.
    KERNEL_FOR_TOTAL=0
    [ -n "$DROP_METRIC" ] && KERNEL_FOR_TOTAL="$KERNEL_DROPS_INT"
    WRITER_DROPS_INT="${WRITER_DROPS%.*}"
    BUFFER_DROPS_INT="${BUFFER_DROPS%.*}"
    TOTAL_DROPS=$((KERNEL_FOR_TOTAL + WRITER_DROPS_INT + BUFFER_DROPS_INT))
    TOTAL_LOSS_PCT="$(awk -v d="$TOTAL_DROPS" -v o="$OFFERED" 'BEGIN{ if (o==0) print 0; else printf "%.4f", (d/o)*100 }')"
    VERDICT="$(classify_run "$ACHIEVED" "$rate" "$TOTAL_LOSS_PCT" "$LOSS_BUDGET")"

    echo -e "$run_id\t$FORMAT\t$SHAPE\t$OFFERED\t$ACHIEVED\t$RECEIVED\t$KERNEL_DROPS\t$WRITER_DROPS\t$BUFFER_DROPS\t$WRITTEN\t$KERNEL_LOSS_PCT\t$TOTAL_LOSS_PCT\t$GEN_CORES\t$SRV_CORES\t$VERDICT"

    # total_loss_pct is meaningful for every format (kernel contributes 0
    # where not applicable, which is correct, not unmeasured), so it is
    # collected unconditionally into the caller's (measure_rate's) globals,
    # reset once per rate. DROPS_LIST (raw kernel drop counts, for the
    # kernel-specific zero-loss NOTE) stays guarded on DROP_METRIC.
    if [ -n "$DROP_METRIC" ]; then
        DROPS_LIST="$DROPS_LIST"$'\n'"$KERNEL_DROPS_INT"
    fi
    WRITER_DROPS_LIST="$WRITER_DROPS_LIST"$'\n'"$WRITER_DROPS"

    RUN_LOSS="$TOTAL_LOSS_PCT"
    RUN_ACHIEVED="$ACHIEVED"
}

# Runs `RUNS` full runs at `rate` and prints one verdict for the rate on
# stdout (PASS/FAIL-LOSS/GENERATOR-LIMITED/HARD-FAILURE) and nothing else --
# `ramp`'s `$(measure_rate ...)` capture must get exactly that single token,
# so every per-run table row and diagnostic below goes to stderr instead. In
# fixed-rate mode the entry point below redirects this call's stdout to
# /dev/null, so the stderr tables are what a fixed-rate run actually shows
# -- and the same verdict is *also* echoed to stderr (both exit paths below)
# for exactly that reason: otherwise it would be discarded, not just
# misrouted, since stdout is the only place it was ever written.
# The gate is evaluated ONCE, on the median achieved rate and median loss
# across all RUNS (see classify_rate) -- a single run dipping under
# ACHIEVED_FLOOR_PCT no longer poisons the whole rate by itself. Per-run
# verdicts are still computed and printed by run_one on every row; that
# audit trail is unchanged, only the gate moved from per-run to per-rate.
# A HARD-FAILURE is not a statistic -- it means the numbers from that run
# cannot be trusted at all -- so it keeps poisoning the rate immediately,
# same as before.
measure_rate() {
    local rate="$1" i losses="" achieveds=""
    echo "# --- rate=$rate ---" >&2
    DROPS_LIST=""
    WRITER_DROPS_LIST=""
    for i in $(seq 1 "$RUNS"); do
        # A hard run_one failure poisons the whole rate: the remaining
        # runs' medians must not paper over an infrastructure failure.
        # run_one sets RUN_VERDICT itself on every failure path, so this
        # never depends on inferring the reason from an empty/unset
        # variable.
        run_one "$i" "$rate" >&2 || { echo "$RUN_VERDICT" >&2; echo "$RUN_VERDICT"; return 0; }
        losses="$losses"$'\n'"$RUN_LOSS"
        achieveds="$achieveds"$'\n'"$RUN_ACHIEVED"
    done

    local med min max med_ach
    med="$(printf '%s' "$losses" | grep -v '^$' | median_of)"
    min="$(printf '%s' "$losses" | grep -v '^$' | min_of)"
    max="$(printf '%s' "$losses" | grep -v '^$' | max_of)"
    med_ach="$(printf '%s' "$achieveds" | grep -v '^$' | median_of)"

    echo "# --- summary: format=$FORMAT shape=$SHAPE rate=$rate runs=$RUNS ---" >&2
    echo -e "median\t$FORMAT\t$SHAPE\t-\t-\t-\t-\t-\t-\t-\t-\t$med\t-\t-\t-" >&2
    echo -e "min\t$FORMAT\t$SHAPE\t-\t-\t-\t-\t-\t-\t-\t-\t$min\t-\t-\t-" >&2
    echo -e "max\t$FORMAT\t$SHAPE\t-\t-\t-\t-\t-\t-\t-\t-\t$max\t-\t-\t-" >&2

    if [ -n "$DROP_METRIC" ]; then
        local all_zero=1 d
        for d in $(printf '%s\n' "$DROPS_LIST" | grep -v '^$'); do
            [ "$d" -ne 0 ] && all_zero=0
        done
        if [ "$all_zero" -eq 1 ]; then
            echo "# NOTE: zero kernel-socket loss ($DROP_METRIC == 0) on every run at rate=$rate -- rate/duration did not saturate the receive buffer on this host. This does not by itself mean total_loss_pct above is zero (writer_drops/buffer_drops can still be non-zero); if it is also zero, raise the rate or DURATION to produce a measurable baseline instead." >&2
        fi
    else
        echo "# kernel-loss is not applicable for format=$FORMAT (transport=$TRANSPORT cannot lose datagrams in a socket buffer): kernel_loss_pct is n/a on every row above (not reported as zero) and the socket-drop reconciliation is skipped. total_loss_pct above already reflects only the drop sites that apply to this format (writer/buffer, kernel contributing 0)." >&2
    fi

    if [ "$SHAPE" = "real" ] && [ -n "$WRITER_DROPS_LIST" ]; then
        local p_all_zero=1 d
        for d in $(printf '%s\n' "$WRITER_DROPS_LIST" | grep -v '^$'); do
            [ "$d" -ne 0 ] && p_all_zero=0
        done
        if [ "$p_all_zero" -eq 0 ]; then
            echo "# NOTE: parquet_s3_dropped{source=\"$SOURCE_LABEL\"} was non-zero on at least one run at rate=$rate -- a second, distinct drop site downstream of the kernel socket. Report it separately; do not fold it into the kernel loss figure above." >&2
        fi
    fi

    echo "# rate=$rate median_loss=${med}% median_achieved=${med_ach}" >&2
    local verdict
    verdict="$(classify_rate "$achieveds" "$losses" "$rate" "$LOSS_BUDGET")"
    # Echoed to stderr too, alongside the per-run rows and the summary line
    # above, so fixed-rate mode -- which redirects this function's stdout to
    # /dev/null below -- still shows the rate-level verdict somewhere. The
    # stdout echo right after is unchanged: ramp's `$(measure_rate ...)`
    # still needs exactly this single token on stdout and nothing else.
    echo "$verdict" >&2
    echo "$verdict"
}

# RATE set -> fixed-rate mode (reproduces the old repeat-ipfix harness and
# the Task 6 reproduce commands, which pass RATE= explicitly and keep
# working unchanged). RATE unset -> ramp mode: coarse-double then bisect to
# this format's ceiling.
if [ -n "${RATE:-}" ]; then
    measure_rate "$RATE" >/dev/null
else
    ramp "${RAMP_START:-5000}"
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
    # sum_proc_net_udp_drops: fixture mirrors /proc/net/udp's header line
    # plus rows, matched on local_address like the real table. Two sockets
    # sharing 0.0.0.0:0044 (SO_REUSEPORT) must sum, not report just the
    # first -- this is the check that would fail if `exit` ever crept back
    # into the awk.
    check "udp drops sums two reuseport sockets" \
        "$(printf '  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n 1: 00000000:0044 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 1 2 0 5\n 2: 00000000:0044 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 2 2 0 7\n' | sum_proc_net_udp_drops "00000000:0044")" \
        "12"
    check "udp drops single socket" \
        "$(printf '  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n 1: 00000000:0044 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 1 2 0 5\n' | sum_proc_net_udp_drops "00000000:0044")" \
        "5"
    check "udp drops no match yields 0" \
        "$(printf '  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n 1: 00000000:0044 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 1 2 0 5\n' | sum_proc_net_udp_drops "00000000:1234")" \
        "0"
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
    # target 20000, 99% floor = 19800
    check "classify pass"        "$(classify_run 19999 20000 0.05 0.1)" "PASS"
    check "classify at floor"    "$(classify_run 19800 20000 0.05 0.1)" "PASS"
    check "classify loss fail"   "$(classify_run 19999 20000 0.50 0.1)" "FAIL-LOSS"
    check "classify gen limited" "$(classify_run 15283 20000 0.00 0.1)" "GENERATOR-LIMITED"
    # Generator saturation is checked FIRST: a run the generator could not
    # sustain says nothing about loss, in either direction.
    check "gen limit beats loss" "$(classify_run 15283 20000 9.90 0.1)" "GENERATOR-LIMITED"
    check "classify exact budget" "$(classify_run 20000 20000 0.10 0.1)" "PASS"
    check "unbounded target"     "$(classify_run 12796 0 0.00 0.1)"     "PASS"

    # classify_rate is what measure_rate actually calls for its one verdict
    # per rate: a lone GENERATOR-LIMITED run among RUNS must not poison the
    # rate when the median achieved rate clears the floor. Target 20000,
    # 99% floor = 19800; achieved medians of [15283,19999,19999] -> 19999
    # (run_one's own per-run verdict for the 15283 run is still
    # GENERATOR-LIMITED and still printed -- that audit trail is untouched;
    # only the rate-level gate moved to the median).
    check "rate median rescues minority gen-limited run" \
        "$(classify_rate "$(printf '%s\n' 19999 19999 15283)" "$(printf '%s\n' 0.05 0.05 0.05)" 20000 0.1)" \
        "PASS"
    # A rate whose median achieved rate genuinely falls below the floor
    # must still classify GENERATOR-LIMITED, loss aside -- the generator
    # itself never offered the load, on most runs, not just a noisy one.
    check "rate median below floor stays gen-limited" \
        "$(classify_rate "$(printf '%s\n' 15000 15100 15200)" "$(printf '%s\n' 0.00 0.00 0.00)" 20000 0.1)" \
        "GENERATOR-LIMITED"

    # Stub measure_rate with a known ceiling so the search itself is under
    # test, not the server. Records every rate tried, in order.
    TRIED=""
    measure_rate() {
        TRIED="$TRIED $1"
        if [ "$1" -le "$STUB_CEILING" ]; then echo "PASS"; else echo "FAIL-LOSS"; fi
    }

    STUB_CEILING=26000 TRIED="" BISECT_RESOLUTION=1000
    RESULT="$(STUB_CEILING=26000 BISECT_RESOLUTION=1000 ramp 5000)"
    # Trace: doubling 5000/10000/20000 PASS, 40000 FAIL; bisect 30000 FAIL,
    # 25000 PASS, 27500 FAIL, 26250 FAIL, 25625 PASS; 26250-25625=625 <= 1000
    # so the search stops and reports the last passing rate.
    check "ramp finds ceiling" "$RESULT" "CEILING 25625"

    # A ramp that never fails must not claim a ceiling -- it only proves the
    # server survived everything offered.
    STUB_CEILING=99999999
    RESULT="$(STUB_CEILING=99999999 BISECT_RESOLUTION=1000 RAMP_MAX=80000 ramp 5000)"
    check "ramp hits RAMP_MAX" "$RESULT" "NO-CEILING-FOUND 80000"

    # A GENERATOR-LIMITED verdict anywhere aborts the search rather than
    # being treated as a failing rate (which would report a fake ceiling).
    measure_rate() { TRIED="$TRIED $1"; [ "$1" -ge 20000 ] && echo "GENERATOR-LIMITED" || echo "PASS"; }
    RESULT="$(BISECT_RESOLUTION=1000 ramp 5000)"
    check "ramp aborts on gen limit" "$RESULT" "GENERATOR-LIMITED 20000"

    # A HARD-FAILURE verdict during doubling aborts the search immediately,
    # same as GENERATOR-LIMITED -- an infrastructure failure says nothing
    # about the rate, so it must never fall into the failing-rate branch.
    measure_rate() { TRIED="$TRIED $1"; [ "$1" -ge 20000 ] && echo "HARD-FAILURE" || echo "PASS"; }
    RESULT="$(BISECT_RESOLUTION=1000 ramp 5000)"
    check "ramp aborts on hard failure during doubling" "$RESULT" "HARD-FAILURE 20000"

    # The bisection path is the one that would otherwise produce a
    # plausible-looking wrong number: doubling finds a real FAIL-LOSS at
    # 40000 same as "ramp finds ceiling" above, but the first bisection
    # probe (30000) hard-fails instead of measuring loss. Without the
    # HARD-FAILURE case in the bisection loop's case statement, this would
    # print a confident CEILING instead of aborting.
    measure_rate() {
        TRIED="$TRIED $1"
        if [ "$1" -eq 30000 ]; then echo "HARD-FAILURE"
        elif [ "$1" -le 26000 ]; then echo "PASS"
        else echo "FAIL-LOSS"; fi
    }
    RESULT="$(BISECT_RESOLUTION=1000 ramp 5000)"
    check "ramp aborts on hard failure during bisection" "$RESULT" "HARD-FAILURE 30000"

    [ "$fail" -eq 0 ] && echo "SELFTEST PASS" || echo "SELFTEST FAIL"
    exit "$fail"
fi

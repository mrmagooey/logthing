#!/bin/bash
# Phase 0 generator-ceiling probe. See
# docs/superpowers/specs/2026-09-16-max-ingest-rate-design.md §4.
set -u

# Every loadgen subcommand ends with the same sentence shape:
#   "loadgen <sub>: sent <N> (flows|datagrams|records) in <S>s (achieved rate: <R> ...)"
# One pair of expressions therefore covers all seven formats. `tail -1` guards
# against a subcommand that prints the phrase more than once (hec-http and
# generic-http print "sent N before aborting" on an auth failure).
parse_sent() {
    printf '%s\n' "$1" | sed -n 's/.*sent \([0-9]\{1,\}\) \(flows\|datagrams\|records\) in .*/\1/p' | tail -1
}

parse_achieved() {
    printf '%s\n' "$1" | sed -n 's/.*achieved rate: \([0-9.]\{1,\}\).*/\1/p' | tail -1
}

# Sums a newline-separated list of decimals on stdin. Prints 0.00 for empty
# input rather than an empty string, so callers can always do arithmetic.
sum_field() {
    awk '{ s += $1 } END { printf "%.2f\n", s }'
}

if [ "${SELFTEST:-0}" != "1" ]; then
REPO="$(cd "$(dirname "$0")/.." && pwd)"
LOADGEN="$REPO/target/release/loadgen"
FORMAT="${FORMAT:-ipfix}"
PROCS="${PROCS:-1 2 4}"
DURATION="${DURATION:-10}"
# BLACKHOLE=1 targets a bound-but-never-drained UDP socket. A bound port
# generates no ICMP port-unreachable (which loadgen's connect()ed socket would
# surface as ECONNREFUSED and abort on), and because nothing ever calls recv,
# no userspace receiver can become the bottleneck. The kernel fills the socket
# buffer and then drops silently. UDP only; TCP or HTTP generators need a peer.
BLACKHOLE="${BLACKHOLE:-0}"
BLACKHOLE_PORT="${BLACKHOLE_PORT:-39999}"
BLACKHOLE_TTL="${BLACKHOLE_TTL:-3600}"
GEN_CPUS="${GEN_CPUS:-0-3}"

case "$FORMAT" in
    syslog)   SUB="syslog-udp";   PORT=514;   TRANSPORT=udp ;;
    ipfix)    SUB="ipfix-udp";    PORT=4739;  TRANSPORT=udp ;;
    sflow)    SUB="sflow-udp";    PORT=6343;  TRANSPORT=udp ;;
    zeek)     SUB="zeek-tcp";     PORT=47760; TRANSPORT=tcp ;;
    suricata) SUB="suricata-tcp"; PORT=47761; TRANSPORT=tcp ;;
    hec)      SUB="hec-http";     PORT=5985;  TRANSPORT=http ;;
    generic)  SUB="generic-http"; PORT=5985;  TRANSPORT=http ;;
    *) echo "FATAL: unknown FORMAT '$FORMAT'"; exit 1 ;;
esac

if [ "$BLACKHOLE" = "1" ]; then
    if [ "$TRANSPORT" != "udp" ]; then
        echo "FATAL: BLACKHOLE=1 needs a connectionless transport; $FORMAT is $TRANSPORT."
        echo "For $TRANSPORT, run against a real server in 'trivial' shape instead"
        echo "(scripts/max-ingest-rate.sh SHAPE=trivial) and label the number as such."
        exit 1
    fi
    if ss -lun 2>/dev/null | awk '{print $5}' | grep -q ":$BLACKHOLE_PORT\$"; then
        echo "FATAL: something is bound to UDP $BLACKHOLE_PORT; it must be unbound to act as a blackhole."
        exit 1
    fi
    PORT="$BLACKHOLE_PORT"
fi

[ -x "$LOADGEN" ] || { echo "FATAL: $LOADGEN not found. cargo build --release -p loadgen"; exit 1; }

TMP="$(mktemp -d)" || exit 1
trap 'rm -rf "$TMP"; [ -n "${BLACKHOLE_PID:-}" ] && kill "$BLACKHOLE_PID" 2>/dev/null' EXIT

if [ "$BLACKHOLE" = "1" ]; then
    # A bound-but-never-drained UDP socket is the blackhole: a bound port
    # generates no ICMP port-unreachable (which loadgen's connect()ed socket
    # would surface as ECONNREFUSED and abort on), and because nothing ever
    # calls recv, no userspace receiver can become the bottleneck. The kernel
    # fills the socket buffer and then drops silently.
    python3 -c "
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('127.0.0.1', $BLACKHOLE_PORT))
time.sleep($BLACKHOLE_TTL)
" &
    BLACKHOLE_PID=$!
    sleep 0.5
    kill -0 "$BLACKHOLE_PID" 2>/dev/null || { echo "FATAL: blackhole listener failed to start on UDP $BLACKHOLE_PORT"; exit 1; }
fi

echo "# format=$FORMAT sub=$SUB port=$PORT transport=$TRANSPORT blackhole=$BLACKHOLE duration=${DURATION}s gen_cpus=$GEN_CPUS"
printf 'procs\tper_proc_rates\taggregate_rate\ttotal_sent\n'

for n in $PROCS; do
    for i in $(seq 1 "$n"); do
        # --target-rate 0 is "unbounded" in every subcommand: send as fast as
        # the loop will go. That is the number we are after.
        taskset -c "$GEN_CPUS" "$LOADGEN" "$SUB" \
            --host 127.0.0.1 --port "$PORT" \
            --target-rate 0 --duration-secs "$DURATION" \
            > "$TMP/p$i.out" 2>&1 &
    done
    wait

    RATES=""
    SENTS=""
    for i in $(seq 1 "$n"); do
        OUT="$(cat "$TMP/p$i.out")"
        R="$(parse_achieved "$OUT")"
        S="$(parse_sent "$OUT")"
        if [ -z "$R" ] || [ -z "$S" ]; then
            echo "FATAL: process $i of $n produced no parseable result:"
            cat "$TMP/p$i.out"
            exit 1
        fi
        RATES="$RATES$R"$'\n'
        SENTS="$SENTS$S"$'\n'
    done

    AGG="$(printf '%s' "$RATES" | grep -v '^$' | sum_field)"
    TOT="$(printf '%s' "$SENTS" | grep -v '^$' | sum_field)"
    PER="$(printf '%s' "$RATES" | grep -v '^$' | tr '\n' ',' | sed 's/,$//')"
    printf '%s\t%s\t%s\t%s\n' "$n" "$PER" "$AGG" "$TOT"
done

echo "# Read this as: if aggregate_rate scales ~linearly with procs, the"
echo "# per-process ceiling is not fundamental -- run more processes rather"
echo "# than optimising the generator. If it flattens, the limit is downstream."
fi

if [ "${SELFTEST:-0}" = "1" ]; then
    fail=0
    check() {
        if [ "$2" != "$3" ]; then
            echo "FAIL: $1: expected '$3', got '$2'"
            fail=1
        else
            echo "ok: $1"
        fi
    }

    IPFIX_OUT='loadgen ipfix-udp: sending to 127.0.0.1:4739 at target_rate=0 flows/s for 10s (template_interval=60s)
loadgen ipfix-udp: sent 291180 flows in 10.000s (achieved rate: 29118.0 flows/s)'
    ZEEK_OUT='loadgen zeek-tcp: sent 127960 records in 10.000s (achieved rate: 12796.0 rec/s)'
    SFLOW_OUT='loadgen sflow-udp: sent 90000 datagrams in 10.000s (achieved rate: 9000.0 rec/s); 0 send errors'

    check "parse_sent ipfix"   "$(parse_sent "$IPFIX_OUT")"   "291180"
    check "parse_sent zeek"    "$(parse_sent "$ZEEK_OUT")"    "127960"
    check "parse_sent sflow"   "$(parse_sent "$SFLOW_OUT")"   "90000"
    check "parse_achieved ipfix" "$(parse_achieved "$IPFIX_OUT")" "29118.0"
    check "parse_achieved zeek"  "$(parse_achieved "$ZEEK_OUT")"  "12796.0"
    check "parse_achieved sflow" "$(parse_achieved "$SFLOW_OUT")" "9000.0"
    check "sum_field three rates" "$(printf '%s\n' 100.5 200.25 9.25 | sum_field)" "310.00"
    check "sum_field empty"       "$(printf '' | sum_field)" "0.00"

    [ "$fail" -eq 0 ] && echo "SELFTEST PASS" || echo "SELFTEST FAIL"
    exit "$fail"
fi

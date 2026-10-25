#!/bin/bash
# Per-format CPU flame graphs of logthing's ingest path, one fixed load point per format.
#
# Usage:
#   scripts/profile-ingest.sh <fmt>... | all     profile the named formats (or all nine)
#   scripts/profile-ingest.sh --list             print the nine format names, one per line
#   scripts/profile-ingest.sh --print-config <fmt>
#                                                print the logthing.toml that would be used and
#                                                exit 0. Ports are free at print time (not
#                                                reserved) and the sink directory lives in a
#                                                fresh mktemp -d dir that is LEFT for the caller
#                                                (its parent of "out"); remove it when done.
#   Unknown format or option: usage on stderr, exit 2.
#
# Formats: syslog zeek suricata ipfix sflow hec generic otlp wef
#
# Build first (the sampler lives behind the off-by-default `pprof` feature):
#   export CC=/usr/bin/gcc CXX=/usr/bin/g++
#   cargo build --profile profiling --features pprof
#   cargo build --release -p loadgen
#   scripts/profile-ingest.sh all
#
# Output ($OUT, default <repo>/profiling-results, gitignored):
#   <fmt>/flamegraph.svg  <fmt>/profile.pb  <fmt>/profile-metadata.json
#   <fmt>/loadgen.txt     <fmt>/summary.json   and   index.html (one row per format)
# Only the <fmt>/ subdirectories of the requested formats are replaced; index.html is rebuilt
# from every <fmt>/summary.json present.
#
# Environment knobs:
#   OUT        output directory                                  (<repo>/profiling-results)
#   BIN        profiling logthing binary               (<repo>/target/profiling/logthing)
#   LOADGEN    loadgen binary                          (<repo>/target/release/loadgen)
#              (override BIN/LOADGEN when CARGO_TARGET_DIR points outside the checkout)
#   DURATION   sampling window in seconds (>= 2x the 5 s flush so a flush lands)       (25)
#   DELAY      seconds the server waits before it starts sampling                        (5)
#   HZ         sampling frequency                                                       (99)
#   RATE_<FMT> offered rec/s override, e.g. RATE_ZEEK=40000 (table defaults below)
#   SKIP_PPROF_CHECK=1  skip the "built without pprof" precheck (testing the script only)
#
# Design notes (carried over from the retired profile-syslog-udp.sh / profile-ipfix-udp.sh):
# - ONE rate point per run. The profile is a single fixed window; a multi-rate sweep would blend
#   idle and loaded regimes into one indistinguishable flamegraph. Rerun with RATE_<FMT>.
# - [logging] level = "error" is REQUIRED, not cosmetic. Every dropped record can emit its own
#   tracing::warn!; pprof's SIGPROF handler unwinds via `backtrace`, which is not
#   async-signal-safe against the allocator/stdout locks tracing holds. level=info segfaulted
#   (exit 139) reproducibly at 50k rec/s with the sampler active; level=error survives.
#   Consequence: the profile EXCLUDES logging cost (a per-drop log storm is a separate finding).
# - Representativeness is anchored to a known figure: the sampler's own activity counter
#   (parquet_s3_records_written, which every local sink increments on flush) plus this script's
#   before/after read of the same counter and loadgen's achieved rate. A format FAILS when the
#   profile is not representative, loadgen reported errors, or written/offered < 0.9.
# - The old scripts rewrote the repo's logthing.toml and deleted logthing.admin.toml (the
#   tracked admin override wins over logthing.toml, commit 87b1d5e). This script never touches
#   the repo: the server runs with cwd = a temp work dir holding its own logthing.toml, and
#   every ambient LOGTHING__* variable is unset first.
# - Never pkill / pgrep -f: they match the invoking shell. The script kills by PID only.
# - Sink is the local-disk Parquet sink with flush_interval_secs = 5, production
#   max_buffer_rows. Loadgen runs on the same host and shares CPU with the server.
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${OUT:-$REPO/profiling-results}"
DURATION="${DURATION:-25}"
DELAY="${DELAY:-5}"
HZ="${HZ:-99}"
BIN="${BIN:-$REPO/target/profiling/logthing}"
LOADGEN="${LOADGEN:-$REPO/target/release/loadgen}"
FLUSH_SECS=5

FORMATS=(syslog zeek suricata ipfix sflow hec generic otlp wef)
# Config section that owns the format's listener and its [<sink>.local] table.
declare -A SINK=(
    [syslog]=syslog [zeek]=zeek [suricata]=suricata [ipfix]=ipfix [sflow]=sflow
    [hec]=hec [generic]=hec [otlp]=otlp [wef]=wef
)
# Offered records/s (events/s for the HTTP formats). Starting values; calibrated per host.
declare -A RATE_DEFAULT=(
    [syslog]=20000 [zeek]=20000 [suricata]=20000 [ipfix]=20000 [sflow]=20000
    [hec]=20000 [generic]=20000 [otlp]=20000 [wef]=5000
)
# Transport of the format's own listener port: udp, tcp, or http (shares the HTTP bind).
declare -A PROTO=(
    [syslog]=udp [zeek]=tcp [suricata]=tcp [ipfix]=udp [sflow]=udp
    [hec]=http [generic]=http [otlp]=http [wef]=http
)
WEF_SUB_UUID="0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0"

usage() {
    {
        echo "usage: $0 <fmt>... | all"
        echo "       $0 --list"
        echo "       $0 --print-config <fmt>"
        echo "formats: ${FORMATS[*]}"
    } >&2
}

valid_format() {
    local f
    for f in "${FORMATS[@]}"; do [ "$f" = "$1" ] && return 0; done
    return 1
}

# alloc_ports <fmt>: sets HTTP_PORT METRICS_PORT LISTEN_PORT AUX_PORT. All sockets are held open
# together so the ports are distinct (separate bind-and-close calls can return the same port).
alloc_ports() {
    local fmt=$1 kinds="tcp tcp" out
    case "${PROTO[$fmt]}" in
        udp) kinds="$kinds udp" ;;
        tcp) kinds="$kinds tcp" ;;
        *) ;;
    esac
    [ "$fmt" = syslog ] && kinds="$kinds tcp"   # syslog also binds a TCP port
    # shellcheck disable=SC2086
    out=$(python3 - $kinds <<'PY'
import socket, sys
socks, ports = [], []
for kind in sys.argv[1:]:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if kind == "udp" else socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    socks.append(s)
    ports.append(str(s.getsockname()[1]))
print(" ".join(ports))
PY
    ) || return 1
    local ports
    read -ra ports <<<"$out"
    HTTP_PORT=${ports[0]}
    METRICS_PORT=${ports[1]}
    LISTEN_PORT=$HTTP_PORT
    AUX_PORT=0
    [ "${PROTO[$fmt]}" != http ] && LISTEN_PORT=${ports[2]}
    [ "$fmt" = syslog ] && AUX_PORT=${ports[3]}
    return 0
}

# listener_toml <section> <port>: the enabled listener section for one source.
listener_toml() {
    case "$1" in
        syslog)
            printf '[syslog]\nenabled = true\nudp_port = %s\ntcp_port = %s\n' "$2" "$AUX_PORT" ;;
        zeek | suricata)
            printf '[%s]\nenabled = true\ntcp_port = %s\nbind_address = "127.0.0.1"\n' "$1" "$2" ;;
        ipfix | sflow)
            printf '[%s]\nenabled = true\nudp_port = %s\nbind_address = "127.0.0.1"\n' "$1" "$2" ;;
        hec | otlp) printf '[%s]\nenabled = true\n' "$1" ;;
    esac
}

# config_toml <fmt> <work> <http_port> <metrics_port> <listener_port>
config_toml() {
    local fmt=$1 work=$2 http=$3 metrics=$4 listen=$5 sec
    printf 'bind_address = "127.0.0.1:%s"\n\n' "$http"
    printf '[tls]\nenabled = false\n\n'
    printf '[metrics]\nenabled = true\nport = %s\n\n' "$metrics"
    printf '[logging]\nlevel = "error"\n\n'
    for sec in syslog zeek suricata ipfix sflow hec otlp; do
        if [ "${SINK[$fmt]}" = "$sec" ]; then
            listener_toml "$sec" "$listen"
            printf '\n[%s.local]\ndirectory = "%s/out"\nflush_interval_secs = %s\n\n' \
                "$sec" "$work" "$FLUSH_SECS"
        else
            printf '[%s]\nenabled = false\n\n' "$sec"
        fi
    done
    if [ "$fmt" = wef ]; then
        # allow_unauthenticated: loadgen has no Kerberos/TLS. collector_url must match the bound
        # HTTP address because loadgen follows the NotifyTo URL from the Enumerate response.
        printf '[wef]\ncollector_url = "http://127.0.0.1:%s"\nallow_unauthenticated = true\n\n' \
            "$http"
        printf '[[wef.subscriptions]]\nname = "security"\nuuid = "%s"\n' "$WEF_SUB_UUID"
        printf 'channels = ["Security"]\n\n'
        printf '[wef.local]\ndirectory = "%s/out"\nflush_interval_secs = %s\n' \
            "$work" "$FLUSH_SECS"
    fi
}

# loadgen_argv <fmt> <host> <port> <rate> <secs>: prints the loadgen arguments, space separated.
loadgen_argv() {
    local fmt=$1 host=$2 port=$3 rate=$4 secs=$5
    local common="--host $host --port $port --target-rate $rate --duration-secs $secs"
    case "$fmt" in
        syslog) echo "syslog-udp $common" ;;
        zeek) echo "zeek-tcp $common" ;;
        suricata) echo "suricata-tcp $common" ;;
        ipfix) echo "ipfix-udp $common" ;;
        sflow) echo "sflow-udp $common" ;;
        hec) echo "hec-http $common --events-per-request 100" ;;
        generic) echo "generic-http $common --events-per-request 100" ;;
        otlp) echo "otlp-http $common --events-per-request 100" ;;
        wef) echo "wef-http $common --events-per-request 50 --concurrency 16" ;;
    esac
}

# ---- argument handling (before any trap or side effect) ----
if [ $# -eq 0 ]; then usage; exit 2; fi
case "$1" in
    --list)
        printf '%s\n' "${FORMATS[@]}"
        exit 0
        ;;
    --print-config)
        if [ $# -ne 2 ] || ! valid_format "$2"; then usage; exit 2; fi
        alloc_ports "$2" || { echo "FATAL: could not allocate ports" >&2; exit 1; }
        WORK="$(mktemp -d)" || exit 1
        config_toml "$2" "$WORK" "$HTTP_PORT" "$METRICS_PORT" "$LISTEN_PORT"
        exit 0
        ;;
    -h | --help) usage; exit 0 ;;
    -*) usage; exit 2 ;;
esac

REQUESTED=()
for a in "$@"; do
    if [ "$a" = all ]; then
        REQUESTED+=("${FORMATS[@]}")
    elif valid_format "$a"; then
        REQUESTED+=("$a")
    else
        echo "unknown format: $a" >&2
        usage
        exit 2
    fi
done

# ---- preconditions ----
BUILD_HELP="  export CC=/usr/bin/gcc CXX=/usr/bin/g++
  export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc
  cargo build --profile profiling --features pprof
  cargo build --release -p loadgen"
if [ ! -x "$BIN" ]; then
    echo "FATAL: $BIN not found. Build it first:"
    echo "$BUILD_HELP"
    exit 1
fi
if [ ! -x "$LOADGEN" ]; then
    echo "FATAL: $LOADGEN not found. Build it first:"
    echo "$BUILD_HELP"
    exit 1
fi
if [ "${SKIP_PPROF_CHECK:-0}" != 1 ] && command -v strings >/dev/null 2>&1 \
    && strings "$BIN" 2>/dev/null | grep -q 'built without the `pprof` feature'; then
    echo "FATAL: $BIN was built without the pprof feature. Rebuild with:"
    echo "$BUILD_HELP"
    exit 1
fi
command -v python3 >/dev/null 2>&1 || { echo "FATAL: python3 is required"; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "FATAL: curl is required"; exit 1; }

# ambient LOGTHING__* variables would override the generated config
for v in $(compgen -e | grep '^LOGTHING__'); do unset "$v"; done

# ---- cleanup ----
SRV_PID=""
LG_PID=""
WORKS=()
stop_pid() {
    local pid=$1
    [ -n "$pid" ] || return 0
    kill -0 "$pid" 2>/dev/null || { wait "$pid" 2>/dev/null; return 0; }
    kill -TERM "$pid" 2>/dev/null
    for _ in $(seq 1 100); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
    done
    kill -0 "$pid" 2>/dev/null && kill -KILL "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
    return 0
}
cleanup() {
    stop_pid "$LG_PID"; LG_PID=""
    stop_pid "$SRV_PID"; SRV_PID=""
    local w
    for w in "${WORKS[@]:-}"; do [ -n "$w" ] && rm -rf "$w"; done
    WORKS=()
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT TERM

# metric_sum <metrics_port> <name>: sum over all label sets, 0 when the series is absent, EMPTY
# when /metrics is unreachable (so a crashed server is not mistaken for a zero counter).
metric_sum() {
    local body
    body=$(curl -sf -m 5 --connect-timeout 2 "http://127.0.0.1:$1/metrics" 2>/dev/null) || return 0
    printf '%s\n' "$body" | awk -v m="$2" '
        { n = $1; sub(/\{.*/, "", n); if (n == m) s += $NF } END { printf "%d\n", s + 0 }'
}

# start_server <fmt> <work>: starts, waits for /metrics. Returns 0 up, 1 failed, 3 port clash.
start_server() {
    local fmt=$1 work=$2
    config_toml "$fmt" "$work" "$HTTP_PORT" "$METRICS_PORT" "$LISTEN_PORT" >"$work/logthing.toml"
    mkdir -p "$work/out" "$work/prof"
    (
        cd "$work" || exit 1
        export LOGTHING_PROFILE_SECS="$DURATION" LOGTHING_PROFILE_DELAY_SECS="$DELAY"
        export LOGTHING_PROFILE_HZ="$HZ" LOGTHING_PROFILE_DIR="$work/prof"
        exec "$BIN"
    ) >"$work/server.log" 2>&1 &
    SRV_PID=$!
    for _ in $(seq 1 60); do
        curl -sf -m 5 --connect-timeout 2 "http://127.0.0.1:$METRICS_PORT/metrics" >/dev/null 2>&1 \
            && curl -sf -m 5 --connect-timeout 2 "http://127.0.0.1:$HTTP_PORT/health" \
                >/dev/null 2>&1 && return 0
        if ! kill -0 "$SRV_PID" 2>/dev/null; then
            wait "$SRV_PID" 2>/dev/null
            SRV_PID=""
            grep -q 'Address already in use' "$work/server.log" && return 3
            return 1
        fi
        sleep 0.25
    done
    return 1
}

run_format() {
    local fmt=$1 var rate work attempt rc started lgsecs lg_rc=0 before after meta
    local envvars=0 outdir="$OUT/$fmt"
    var="RATE_${fmt^^}"
    rate="${!var:-${RATE_DEFAULT[$fmt]}}"
    lgsecs=$((DELAY + DURATION + 5))
    # Start from an empty result dir so a failure never presents a previous run's artifacts.
    rm -rf "$outdir"; mkdir -p "$outdir"
    work="$(mktemp -d)" || {
        echo "FAIL $fmt: mktemp -d failed"
        write_summary "$fmt" "$rate" "$lgsecs" skip skip 0 "" "mktemp -d failed"
        return 1
    }
    WORKS+=("$work")
    echo "== $fmt: offered $rate rec/s for ${lgsecs}s (sampling ${DURATION}s after ${DELAY}s)"

    rc=1
    for attempt in 1 2; do
        alloc_ports "$fmt" || {
            echo "FAIL $fmt: could not allocate ports"
            write_summary "$fmt" "$rate" "$lgsecs" skip skip 0 "$work" "could not allocate ports"
            return 1
        }
        started=$SECONDS
        start_server "$fmt" "$work"
        rc=$?
        [ "$rc" -eq 3 ] && [ "$attempt" -eq 1 ] && { echo "port clash, retrying"; continue; }
        break
    done
    if [ "$rc" -ne 0 ]; then
        echo "FAIL $fmt: server did not come up"; tail -20 "$work/server.log"
        stop_pid "$SRV_PID"; SRV_PID=""
        cp "$work/server.log" "$outdir/server.log" 2>/dev/null
        write_summary "$fmt" "$rate" "$lgsecs" skip skip 0 "$work" "server did not come up"
        return 1
    fi
    sleep 1   # let the non-HTTP listener finish binding
    envvars=$(tr '\0' '\n' <"/proc/$SRV_PID/environ" 2>/dev/null | grep -c '^LOGTHING__' || true)

    before=$(metric_sum "$METRICS_PORT" parquet_s3_records_written)
    local argv
    read -ra argv <<<"$(loadgen_argv "$fmt" 127.0.0.1 "$LISTEN_PORT" "$rate" "$lgsecs")"
    # timeout is PID-based; exit 124 (hung loadgen) takes the normal loadgen-failure path
    timeout --foreground $((lgsecs + 60)) "$LOADGEN" "${argv[@]}" >"$work/loadgen.txt" 2>&1 &
    LG_PID=$!
    wait "$LG_PID"; lg_rc=$?
    LG_PID=""
    # the last partial buffer lands on the next flush tick
    sleep $((FLUSH_SECS + 2))
    local died=""
    if ! kill -0 "$SRV_PID" 2>/dev/null; then
        died="server exited during run"
        echo "FAIL $fmt: $died"; tail -20 "$work/server.log"
    fi
    after=$(metric_sum "$METRICS_PORT" parquet_s3_records_written)

    meta="$work/prof/profile-metadata.json"
    local deadline=$((started + DELAY + DURATION + 30))
    while [ ! -f "$meta" ] && [ "$SECONDS" -lt "$deadline" ] && kill -0 "$SRV_PID" 2>/dev/null; do
        sleep 1
    done
    [ -f "$meta" ] && sleep 1   # artifacts are written just before/with the metadata file
    stop_pid "$SRV_PID"; SRV_PID=""

    local f
    for f in flamegraph.svg profile.pb profile-metadata.json; do
        [ -f "$work/prof/$f" ] && cp "$work/prof/$f" "$outdir/$f"
    done
    cp "$work/loadgen.txt" "$outdir/loadgen.txt"
    cp "$work/server.log" "$outdir/server.log" 2>/dev/null
    local extra="$died"
    if [ ! -f "$meta" ]; then
        extra="${extra:+$extra; }profile-metadata.json missing"
        extra="$extra (binary built without pprof, or sampler failed)"
    fi
    LG_RC=$lg_rc write_summary "$fmt" "$rate" "$lgsecs" "$before" "$after" "$envvars" \
        "$work" "$extra"
    local srv=$?
    rm -rf "$work"
    return $srv
}

# write_summary <fmt> <offered> <lg_secs> <before> <after> <envvars> <work> <extra_reason>
write_summary() {
    mkdir -p "$OUT/$1"
    local cpu
    cpu="$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed 's/^ *//')"
    OUT_DIR="$OUT" HOST="$(uname -n)" CPU="$cpu" \
    python3 - "$@" <<'PY'
import datetime, json, os, re, sys

fmt, offered, lg_secs, before, after, envvars, work, extra = sys.argv[1:9]
offered, lg_secs = float(offered), float(lg_secs)
out = os.path.join(os.environ["OUT_DIR"], fmt)
reasons = [extra] if extra else []

meta = {}
try:
    with open(os.path.join(out, "profile-metadata.json")) as fh:
        meta = json.load(fh)
except (OSError, ValueError):
    if not extra:
        reasons.append("profile-metadata.json missing")

text = ""
try:
    with open(os.path.join(out, "loadgen.txt")) as fh:
        text = fh.read()
except OSError:
    pass
m = re.search(r"achieved rate: ([0-9.]+)", text)
achieved = float(m.group(1)) if m else None
errors = sum(int(x) for x in re.findall(r"(\d+) requests rejected", text))
errors += sum(int(x) for x in re.findall(r"(\d+) requests abandoned", text))
lg_rc = int(os.environ.get("LG_RC", "0"))
if lg_rc != 0:
    errors += 1
    reasons.append(f"loadgen exited with status {lg_rc}")
if errors:
    reasons.append(f"loadgen reported {errors} error(s)")
if achieved is None and lg_rc == 0 and text:
    reasons.append("loadgen summary line not found")

records = None
ratio = None
if before == "skip":
    pass  # run never started; nothing was measured
elif before == "" or after == "":
    reasons.append("metrics unreachable")
else:
    records = int(after) - int(before)
    ratio = records / (offered * lg_secs) if offered * lg_secs else None
    if ratio is not None and ratio < 0.9:
        reasons.append(f"written/offered {ratio:.2f} < 0.9")
if meta and not meta.get("representative", False):
    reasons.append("profile not representative")
leak = int(envvars)
if leak:
    reasons.append("ambient LOGTHING__ env leaked")

summary = {
    "format": fmt,
    "verdict": "FAIL" if reasons else "PASS",
    "reasons": reasons,
    "offered_rate": offered,
    "achieved_rate": achieved,
    "loadgen_errors": errors,
    "records_written": records,
    "written_ratio": None if ratio is None else round(ratio, 4),
    "sample_count": meta.get("sample_count"),
    "representative": meta.get("representative"),
    "activity_metric": meta.get("activity_metric"),
    "server_logthing_env_vars": leak,
    "host": os.environ.get("HOST", ""),
    "cpu": os.environ.get("CPU", ""),
    "date": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
}
with open(os.path.join(out, "summary.json"), "w") as fh:
    json.dump(summary, fh, indent=2)
print(f"{summary['verdict']} {fmt}: " + ("; ".join(reasons) if reasons else "ok"))
sys.exit(1 if reasons else 0)
PY
}

# write_index: self-contained $OUT/index.html from every $OUT/*/summary.json.
write_index() {
    OUT_DIR="$OUT" python3 - "${FORMATS[@]}" <<'PY'
import html, json, os, sys

out = os.environ["OUT_DIR"]
rows, host = [], None
for fmt in sys.argv[1:]:
    try:
        with open(os.path.join(out, fmt, "summary.json")) as fh:
            s = json.load(fh)
    except (OSError, ValueError):
        continue
    host = host or s
    svg = os.path.join(fmt, "flamegraph.svg")
    has_svg = os.path.exists(os.path.join(out, svg))
    def num(v, spec="{:,.0f}"):
        return "-" if v is None else spec.format(v)
    link = (f'<a href="{svg}">flamegraph</a><br><img src="{svg}" alt="{fmt} flame graph" '
            'width="320">') if has_svg else "no flame graph"
    why = "; ".join(s.get("reasons", []))
    rows.append(
        f'<tr class="{s["verdict"].lower()}"><td>{html.escape(fmt)}</td>'
        f'<td>{s["verdict"]}</td><td class="n">{num(s.get("offered_rate"))}</td>'
        f'<td class="n">{num(s.get("achieved_rate"))}</td>'
        f'<td class="n">{num(s.get("records_written"))}</td>'
        f'<td class="n">{num(s.get("written_ratio"), "{:.2f}")}</td>'
        f'<td class="n">{num(s.get("sample_count"))}</td>'
        f'<td>{link}</td><td>{html.escape(why)}</td></tr>')
head = ""
if host:
    head = (f'<p>Host {html.escape(host.get("host", ""))} &middot; CPU '
            f'{html.escape(host.get("cpu", ""))} &middot; {html.escape(host.get("date", ""))}</p>')
page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>logthing ingest flame graphs</title>
<style>
body{{font:14px/1.4 system-ui,sans-serif;margin:24px;color:#222}}
table{{border-collapse:collapse}} th,td{{border:1px solid #ccc;padding:6px 10px;vertical-align:top}}
th{{background:#f0f0f0}} td.n{{text-align:right}} tr.pass td:nth-child(2){{color:#080}}
tr.fail td:nth-child(2){{color:#b00;font-weight:bold}} img{{border:1px solid #ddd}}
</style></head><body>
<h1>logthing ingest flame graphs</h1>
{head}
<table><tr><th>format</th><th>verdict</th><th>offered/s</th><th>achieved/s</th><th>written</th>
<th>written/offered</th><th>samples</th><th>flame graph</th><th>notes</th></tr>
{"".join(rows)}
</table>
<h2>Out of scope</h2>
<ul>
<li>WEF: no Kerberos or TLS (unauthenticated HTTP); authentication cost is not profiled.</li>
<li>Logging is excluded: <code>[logging] level = "error"</code> (SIGPROF unwinding is not
async-signal-safe against tracing locks).</li>
<li>Sink is the local-disk Parquet writer, not S3; upload cost is not profiled.</li>
<li>One fixed offered rate per format; loadgen shares the host CPU with the server.</li>
</ul></body></html>
"""
with open(os.path.join(out, "index.html"), "w") as fh:
    fh.write(page)
PY
}

mkdir -p "$OUT" || { echo "FATAL: cannot create $OUT"; exit 1; }
FAILED=()
for fmt in "${REQUESTED[@]}"; do
    run_format "$fmt" || FAILED+=("$fmt")
done
write_index
echo "results in $OUT (index.html)"
if [ "${#FAILED[@]}" -gt 0 ]; then
    echo "FAILED: ${FAILED[*]}"
    exit 1
fi
exit 0

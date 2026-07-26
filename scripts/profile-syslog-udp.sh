#!/bin/bash
# Profile logthing's syslog-UDP ingest path under load and assert the sampling
# window actually overlapped that load.
#
# Deliberately drives ONE rate point per run: the profile is a single fixed
# window, so a multi-rate sweep would blend idle and loaded regimes into one
# indistinguishable flamegraph.
#
# Restores repo config files on every exit path -- logthing.admin.toml is
# git-tracked and overrides logthing.toml, a trap documented in commit 87b1d5e.
#
# Build the profiling binary before running this script:
#   export CC=/usr/bin/gcc CXX=/usr/bin/g++
#   cargo build --profile profiling --features pprof
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${OUT:-$REPO/profiling-results}"
RATE="${RATE:-50000}"
DURATION="${DURATION:-30}"
DELAY="${DELAY:-5}"
HZ="${HZ:-99}"
BIN="$REPO/target/profiling/logthing"

if [ ! -x "$BIN" ]; then
    echo "FATAL: $BIN not found. Build it first:"
    echo "  export CC=/usr/bin/gcc CXX=/usr/bin/g++"
    echo "  cargo build --profile profiling --features pprof"
    exit 1
fi
if command -v strings >/dev/null 2>&1 \
    && strings "$BIN" 2>/dev/null | grep -q 'built without the `pprof` feature'; then
    echo "FATAL: $BIN was built without the pprof feature. Rebuild with:"
    echo "  cargo build --profile profiling --features pprof"
    exit 1
fi

BK="$(mktemp -d)" || { echo "FATAL: mktemp -d failed"; exit 1; }

cd "$REPO" || { echo "FATAL: cd to $REPO failed"; exit 1; }
cp logthing.toml "$BK/logthing.toml.orig" \
    || { echo "FATAL: backup of logthing.toml failed"; exit 1; }
cp logthing.admin.toml "$BK/logthing.admin.toml.orig" \
    || { echo "FATAL: backup of logthing.admin.toml failed"; exit 1; }

SRV_PID=""
restore() {
    [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null
    sleep 1
    [ -n "$SRV_PID" ] && kill -9 "$SRV_PID" 2>/dev/null
    # Idempotent: the INT/TERM trap below calls restore() explicitly and then
    # exits, which in turn fires the EXIT trap, which would call restore()
    # again. Guard on $BK still existing so the second call is a harmless
    # no-op instead of re-copying from a backup dir that's already gone.
    [ -d "$BK" ] || return 0
    cp "$BK/logthing.toml.orig" "$REPO/logthing.toml"
    cp "$BK/logthing.admin.toml.orig" "$REPO/logthing.admin.toml"
    rm -rf "$BK"
}
trap restore EXIT
# A plain `trap restore INT TERM` would restore config but then let the
# script fall through to its normal (0) exit path -- silently discarding the
# interruption and defeating the exit-code gate this script exists to
# provide. Exit 130 (128+SIGINT) makes an interrupted run visibly non-zero.
trap 'restore; exit 130' INT TERM

rm -f logthing.admin.toml
cp tools/loadgen/ci/logthing-baseline.toml logthing.toml

# Force log level to `error` for the duration of the profile. This is NOT
# cosmetic -- it is required for the run to survive at saturating rates.
#
# Every dropped record emits its own tracing::warn! (forwarding/syslog_s3.rs,
# syslog/listener.rs). At RATE=50000 that is ~19,000 warn lines/sec (861,891
# lines observed in a 45s run), and pprof's SIGPROF handler unwinds via
# `backtrace`, which is not async-signal-safe against the allocator and stdout
# locks that tracing holds. Measured directly: level=info segfaults (exit 139)
# reproducibly at 50k with the sampler active; level=error survives and yields
# a representative profile across repeated runs (two confirming runs: 6,656
# samples / delta 940,525, and 6,968 samples / delta 1,192,375 -- sampling has
# normal run-to-run variance, these are not one number).
#
# Consequence to state in any write-up: the resulting profile EXCLUDES logging
# cost. That is desirable for isolating the ingest path, but it means the log
# storm itself -- an unbounded per-drop log with no rate limiting -- is a
# separate finding, not something this profile measures.
LOG_LEVEL="${LOG_LEVEL:-error}"
printf '\n[logging]\nlevel = "%s"\nformat = "pretty"\n' "$LOG_LEVEL" >> logthing.toml

rm -rf /tmp/logthing-perf-local "$OUT"
mkdir -p /tmp/logthing-perf-local

LOGTHING_PROFILE_SECS="$DURATION" \
LOGTHING_PROFILE_DELAY_SECS="$DELAY" \
LOGTHING_PROFILE_HZ="$HZ" \
LOGTHING_PROFILE_DIR="$OUT" \
    "$REPO/target/profiling/logthing" > /tmp/logthing-profile-stdout.log 2>&1 &
SRV_PID=$!

for _ in $(seq 1 30); do
    curl -sf http://127.0.0.1:9090/metrics >/dev/null 2>&1 && break
    sleep 0.5
done
curl -sf http://127.0.0.1:9090/metrics >/dev/null || {
    echo "SERVER DID NOT COME UP"; tail -20 /tmp/logthing-profile-stdout.log; exit 1
}

# Start load immediately; the server waits $DELAY before sampling, so the
# window opens well inside the load period.
"$REPO/target/release/loadgen" syslog-udp --host 127.0.0.1 --port 15514 \
    --target-rate "$RATE" --duration-secs "$((DELAY + DURATION + 10))" | tail -3

sleep 5

META="$OUT/profile-metadata.json"
[ -f "$META" ] || { echo "FAIL: $META not written"; exit 1; }
python3 - "$META" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
print(json.dumps(m, indent=2))
if not m["representative"]:
    sys.exit("FAIL: profile is not representative "
             f"(samples={m['sample_count']}, delta={m['activity_delta']})")
print("OK: representative profile")
PY
# Propagate the check's verdict. Without this the script always exits 0:
# there is no `set -e`, so a failing heredoc is silently followed by the
# echo below, which succeeds and becomes the script's exit status. A caller
# gating on $? would then read an unrepresentative profile as success --
# defeating the entire point of the assertion.
CHECK_RC=$?
if [ "$CHECK_RC" -ne 0 ]; then
    echo "artifacts in $OUT (NOT representative -- do not use for analysis)"
    exit "$CHECK_RC"
fi
echo "artifacts in $OUT"

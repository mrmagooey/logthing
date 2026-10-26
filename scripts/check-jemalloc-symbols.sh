#!/usr/bin/env bash
# Assert that a built logthing binary embeds jemalloc (tikv-jemallocator prefixes every symbol
# with `_rjem_`). Used by .github/workflows/binaries.yml before and after the release build so a
# musl artifact without jemalloc fails the job instead of shipping.
#
# Usage: scripts/check-jemalloc-symbols.sh <binary> [--run]
#   <binary>  path to the built executable (cargo's unstripped output)
#   --run     also start the binary for up to ~5 s in a scratch directory and require the startup
#             log line `allocator=jemalloc` (only for binaries that run on this host)
# Exit: 0 ok, 1 check failed, 2 usage error / missing file.
# Example: scripts/check-jemalloc-symbols.sh target/x86_64-unknown-linux-musl/release/logthing --run
set -euo pipefail

bin="${1:-}"
mode="${2:-}"
if [ -z "$bin" ] || [ ! -f "$bin" ]; then
    echo "usage: $0 <binary> [--run]  (binary not found: '${bin}')" >&2
    exit 2
fi

# grep -c reads all of strings' output (grep -q would SIGPIPE strings and trip pipefail).
count=$(strings -a "$bin" | grep -c '_rjem_' || true)
if [ "$count" -eq 0 ]; then
    echo "FAIL: no _rjem_ (jemalloc) symbols found in $bin" >&2
    exit 1
fi
echo "ok: $bin contains $count _rjem_ strings"

if [ "$mode" = "--run" ]; then
    work=$(mktemp -d)
    trap 'rm -rf "$work"' EXIT
    cat >"$work/logthing.toml" <<'EOF'
bind_address = "127.0.0.1:38475"

[tls]
enabled = false

[metrics]
enabled = false

[syslog]
enabled = false
EOF
    abs=$(readlink -f "$bin")
    # Start in the background and poll (at most ~5 s) for the log line; stop it by PID.
    (cd "$work" && exec "$abs" >out.log 2>&1) &
    pid=$!
    for _ in $(seq 1 50); do
        grep -q 'allocator=' "$work/out.log" 2>/dev/null && break
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
    done
    kill -TERM "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    if ! grep -q 'allocator=jemalloc' "$work/out.log"; then
        echo "FAIL: startup log lacks allocator=jemalloc; output was:" >&2
        cat "$work/out.log" >&2
        exit 1
    fi
    echo "ok: startup log reports allocator=jemalloc"
fi

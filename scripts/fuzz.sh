#!/usr/bin/env bash
# Run cargo-fuzz targets seeded from fuzz/seeds. Needs nightly + cargo-fuzz:
#   rustup toolchain install nightly && cargo install cargo-fuzz --locked
# Usage: scripts/fuzz.sh <target|all> [seconds-per-target, default 60]
# Crashes land in fuzz/artifacts/<target>/. See AGENTS.md "Fuzzing" to triage.
set -euo pipefail
cd "$(dirname "$0")/.."

secs="${2:-60}"
declare -A dict=(
    [syslog]=syslog [wef_event]=xml [wef_envelope]=xml
    [zeek]=json [suricata]=json [hec]=json [otlp]=json
)
all=(ipfix sflow syslog wef_event wef_envelope zeek suricata hec otlp)
if [[ "${1:-}" == "all" ]]; then targets=("${all[@]}"); else targets=("${1:?target or all}"); fi

for t in "${targets[@]}"; do
    mkdir -p "fuzz/corpus/$t"
    args=(-max_total_time="$secs" -timeout=10 -rss_limit_mb=4096)
    [[ -n "${dict[$t]:-}" ]] && args+=(-dict="fuzz/dicts/${dict[$t]}.dict")
    cargo +nightly fuzz run "$t" "fuzz/corpus/$t" "fuzz/seeds/$t" -- "${args[@]}"
done

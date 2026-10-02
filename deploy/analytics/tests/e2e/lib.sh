# Shared helpers for the analytics e2e scripts. Source, don't execute.

# Exit 1 unless the CPU has AVX2 or both TRINO_IMAGE and HUE_IMAGE are overridden.
preflight_cpu() {
  if grep -qw avx2 /proc/cpuinfo; then return 0; fi
  if [ -n "${TRINO_IMAGE:-}" ] && [ -n "${HUE_IMAGE:-}" ]; then
    echo "preflight: CPU lacks AVX2; using overrides TRINO_IMAGE=$TRINO_IMAGE HUE_IMAGE=$HUE_IMAGE" >&2
    echo "preflight: this run does NOT verify the default images" >&2
    return 0
  fi
  echo "preflight: this CPU lacks AVX2/x86-64-v3. trinodb/trino:483 and the stock Hue image" >&2
  echo "preflight: crash on it. Run on modern hardware, or set TRINO_IMAGE and HUE_IMAGE." >&2
  exit 1
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

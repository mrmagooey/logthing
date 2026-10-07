#!/usr/bin/env bash
# End-to-end: Helm chart on minikube -> syslog into logthing -> committer -> Trino (HTTPS + password) sees the rows.
# Requires minikube (docker driver), helm, kubectl and an AVX2-capable CPU (or a TRINO_IMAGE
# override; locally present override images are loaded into the cluster). KEEP_CLUSTER=1 keeps it.
set -euo pipefail
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ANALYTICS=$(cd -- "$HERE/../.." && pwd)
. "$HERE/lib.sh"
preflight_cpu

PROFILE=${MINIKUBE_PROFILE:-lt-analytics-e2e}
NS=analytics
FULL=lt-logthing-analytics
CHART="$ANALYTICS/helm/logthing-analytics"
TRINO_LOCAL_PORT=28443
CA=$(mktemp)
N=40
MARKER="analytics-e2e-$(date +%s)-$$"
PY=${PYTHON:-python3}
# Private kubeconfig: minikube start/delete must never modify the caller's ~/.kube/config.
# KEEP_CLUSTER=1 needs a stable path so a rerun finds the kept cluster's context.
if [ "${KEEP_CLUSTER:-}" = 1 ]; then
  KUBECONFIG=${TMPDIR:-/tmp}/$PROFILE.kubeconfig
  touch "$KUBECONFIG"
else
  KUBECONFIG=$(mktemp)
fi
export KUBECONFIG
K=(kubectl --context "$PROFILE" -n "$NS")
H=(helm --kube-context "$PROFILE")
TRINO_CLI=(trino --server https://localhost:8443 --truststore-path /etc/trino/tls/ca.pem
           --user admin --password)

PF_PID=""
cleanup() {
  [ -z "$PF_PID" ] || kill "$PF_PID" 2>/dev/null || true
  rm -f "$CA"
  if [ "${KEEP_CLUSTER:-}" = 1 ]; then
    echo "KEEP_CLUSTER=1: leaving minikube profile $PROFILE running" >&2
  else
    minikube delete -p "$PROFILE" >/dev/null 2>&1 || true
    rm -f "$KUBECONFIG"
  fi
}
trap cleanup EXIT

dump_logs() {
  "${K[@]}" get pods >&2 || true
  # The component label is on the committer pods (not the Jobs); show the most recent run(s).
  "${K[@]}" logs -l app.kubernetes.io/component=committer --tail 80 --prefix >&2 || true
  "${K[@]}" logs "deploy/$FULL-logthing" --tail 80 >&2 || true
}

echo "== [1/7] minikube profile $PROFILE =="
# start is idempotent on a running profile (status exits non-zero against a fresh private kubeconfig).
minikube start -p "$PROFILE" --cpus 6 --memory 12g --driver docker
# A kept cluster's context is not in this run's private kubeconfig; (re)write it.
minikube update-context -p "$PROFILE" >/dev/null

echo "== [2/7] load local override images =="
for img in "${TRINO_IMAGE:-}"; do
  if [ -n "$img" ] && docker image inspect "$img" >/dev/null 2>&1; then
    # Loading a multi-GB image is slow; skip it when a kept cluster already has it.
    if ! minikube -p "$PROFILE" image ls 2>/dev/null | grep -qxF -e "$img" -e "docker.io/$img" -e "docker.io/library/$img"; then
      minikube -p "$PROFILE" image load "$img"
    fi
  fi
done

echo "== [3/7] helm install =="
SETS=(--set logthing.flushIntervalSecs=5)
[ -z "${TRINO_IMAGE:-}" ] || SETS+=(--set "trino.image=$TRINO_IMAGE")
"${H[@]}" upgrade --install lt "$CHART" --namespace "$NS" --create-namespace --wait --timeout 15m "${SETS[@]}" \
  || { echo "helm install failed" >&2; dump_logs; exit 1; }

echo "== [3b/7] helm upgrade keeps generated credentials (lookup persistence) =="
secret_hash() { "${K[@]}" get secret "$FULL-credentials" -o jsonpath='{.data}' | sha256sum | cut -d' ' -f1; }
BEFORE=$(secret_hash)
"${H[@]}" upgrade lt "$CHART" --namespace "$NS" --reuse-values --wait --timeout 15m \
  || { echo "helm upgrade failed" >&2; dump_logs; exit 1; }
[ "$(secret_hash)" = "$BEFORE" ] || { echo "credentials Secret changed across helm upgrade" >&2; exit 1; }

echo "== [4/7] wait for init jobs =="
# Job names carry the release revision, so select by label.
for c in garage-init lakekeeper-init; do
  "${K[@]}" wait --for=condition=complete job -l "app.kubernetes.io/component=$c" --timeout 10m \
    || { echo "job $c did not complete" >&2; "${K[@]}" logs -l "app.kubernetes.io/component=$c" --tail 80 >&2 || true; exit 1; }
done

echo "== [5/7] send $N syslog messages ($MARKER) =="
SENDER=$(cat <<PYEOF
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
now = time.strftime("%b %e %H:%M:%S")
for i in range($N):
    s.sendto(f"<134>{now} e2ehost analytics-e2e: $MARKER message {i}".encode(), ("$FULL-logthing-udp", 514))
    time.sleep(0.02)
PYEOF
)
"${K[@]}" delete pod sender --ignore-not-found >/dev/null
timeout 300 "${K[@]}" run sender --rm -i --restart=Never --pod-running-timeout=3m \
  --image=python:3.12-slim -- python -c "$SENDER" \
  || { echo "sender failed" >&2; exit 1; }

COUNT_SQL="SELECT count(*) FROM iceberg.logs.syslog WHERE message LIKE '%$MARKER%'"
trino_count() {
  timeout 30 "${K[@]}" exec "deploy/$FULL-trino" -- "${TRINO_CLI[@]}" --output-format TSV --execute "$COUNT_SQL" 2>/dev/null \
    | tr -d '"\r' || true
}

echo "== [6/7] wait (<=300s) for committer to land rows in iceberg.logs.syslog =="
deadline=$(( $(date +%s) + 300 ))
until [ "$(trino_count)" = "$N" ]; do
  if [ "$(date +%s)" -ge "$deadline" ]; then
    echo "timed out after 300s waiting for $N rows in iceberg.logs.syslog" >&2
    dump_logs
    exit 1
  fi
  sleep 5
done
echo "trino: $N"

echo "== [7/7] Trino security through a port-forward: HTTPS + password negatives =="
"${K[@]}" port-forward "svc/$FULL-trino" "$TRINO_LOCAL_PORT:8443" >/dev/null 2>&1 &
PF_PID=$!
"${K[@]}" get secret "$FULL-trino-tls" -o jsonpath='{.data.ca\.pem}' | base64 -d >"$CA"
ADMIN_PW=$("${K[@]}" get secret "$FULL-credentials" -o jsonpath='{.data.trino-admin-password}' | base64 -d)
trino_alive() {
  kill -0 "$PF_PID" 2>/dev/null && curl -s -o /dev/null --cacert "$CA" "https://localhost:$TRINO_LOCAL_PORT/v1/info"
}
wait_until 120 "Trino port-forward" trino_alive \
  || { "${K[@]}" logs "deploy/$FULL-trino" --tail 80 >&2 || true; exit 1; }
trino_security_checks "https://localhost:$TRINO_LOCAL_PORT" "$CA" "$ADMIN_PW" \
  || { "${K[@]}" logs "deploy/$FULL-trino" --tail 80 >&2 || true; exit 1; }
# Topology B: plain-HTTP 8080 is internal to the pod; the Service must expose only 8443.
PORTS=$("${K[@]}" get svc "$FULL-trino" -o jsonpath='{.spec.ports[*].port}')
[ "$PORTS" = 8443 ] || { echo "Trino Service exposes ports '$PORTS', expected only 8443" >&2; exit 1; }
if "${K[@]}" exec "deploy/$FULL-trino" -- env TRINO_PASSWORD=wrong "${TRINO_CLI[@]}" --execute 'SELECT 1' >/dev/null 2>&1; then
  echo "Trino CLI accepted a wrong password" >&2; exit 1
fi

echo "Analytics Helm E2E PASSED"

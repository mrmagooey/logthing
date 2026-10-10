#!/usr/bin/env bash
# Start/stop the test MIT KDC and print the LOGTHING_TEST_KRB5_* exports.
#   scripts/kdc-test-env.sh up    # build, run, copy keytabs to target/kdc-test/, print exports
#   scripts/kdc-test-env.sh down  # remove the container and its volume (keeps the image)
# Usage: eval "$(scripts/kdc-test-env.sh up)"
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/target/kdc-test"
NAME=logthing-test-kdc
IMAGE=logthing-test-kdc:latest

case "${1:-}" in
up)
    docker rm -fv "$NAME" >/dev/null 2>&1 || true
    docker build -q -t "$IMAGE" "$ROOT/tests/e2e/simulation-environment/kdc" >&2
    docker run -d --name "$NAME" -p 127.0.0.1::88 -p 127.0.0.1::88/udp "$IMAGE" >/dev/null
    for _ in $(seq 1 60); do
        [ "$(docker inspect -f '{{.State.Health.Status}}' "$NAME")" = healthy ] && break
        sleep 1
    done
    [ "$(docker inspect -f '{{.State.Health.Status}}' "$NAME")" = healthy ] \
        || { docker logs "$NAME" >&2; echo "KDC did not become healthy" >&2; exit 1; }
    PORT="$(docker port "$NAME" 88/tcp | head -1 | sed 's/.*://')"
    mkdir -p "$OUT"
    for k in logthing clients other; do docker cp "$NAME:/keytabs/$k.keytab" "$OUT/$k.keytab"; done
    chmod 644 "$OUT"/*.keytab # test-only key material
    cat > "$OUT/krb5.conf" <<CONF
[libdefaults]
    default_realm = EXAMPLE.COM
    dns_canonicalize_hostname = false
    rdns = false
    dns_lookup_kdc = false
    dns_lookup_realm = false
    udp_preference_limit = 1

[realms]
    EXAMPLE.COM = {
        kdc = 127.0.0.1:$PORT
    }
CONF
    echo "export LOGTHING_TEST_KRB5_CONFIG=$OUT/krb5.conf" \
        "LOGTHING_TEST_KRB5_SERVER_KEYTAB=$OUT/logthing.keytab" \
        "LOGTHING_TEST_KRB5_CLIENT_KEYTAB=$OUT/clients.keytab" \
        "LOGTHING_TEST_KRB5_SPN=HTTP/logthing.example.com@EXAMPLE.COM" \
        "LOGTHING_TEST_KRB5_HOST=logthing.example.com"
    ;;
down)
    docker rm -fv "$NAME" >/dev/null 2>&1 || true
    ;;
*)
    echo "usage: $0 up|down" >&2
    exit 2
    ;;
esac

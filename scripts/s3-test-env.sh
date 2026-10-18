#!/usr/bin/env bash
# Start/stop a throwaway SeaweedFS S3 server and print the MINIO_* exports the S3 integration
# tests (tests/*_s3_integration.rs, tests/object_lock_integration.rs) read.
#   scripts/s3-test-env.sh up    # run SeaweedFS, create the tests' default buckets, print exports
#   scripts/s3-test-env.sh down  # remove the container and its volume (keeps the image)
# Usage: eval "$(scripts/s3-test-env.sh up)"
# Credentials are the test-only minioadmin/minioadmin pair; the host port is random.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/target/s3-test"
NAME=logthing-test-s3
IMAGE=chrislusf/seaweedfs:4.48
KEY=minioadmin
# Default bucket of each S3 integration test (object_lock_integration creates its own).
BUCKETS="hec-logs ipfix-flows otlp-test sflow-samples suricata-logs syslog-structured-test
    syslog-test wef-events zeek-logs"

case "${1:-}" in
up)
    docker rm -fv "$NAME" >/dev/null 2>&1 || true
    mkdir -p "$OUT"
    cat > "$OUT/s3.json" <<JSON
{"identities":[{"name":"admin","credentials":[{"accessKey":"$KEY","secretKey":"$KEY"}],
"actions":["Admin","Read","Write","List","Tagging"]}]}
JSON
    # The volume flags matter: without them most uploads fail with "no writable volumes".
    docker run -d --name "$NAME" -p 127.0.0.1::8333 -v "$OUT/s3.json:/etc/s3.json:ro" \
        "$IMAGE" server -dir=/data -s3 -s3.config=/etc/s3.json \
        -master.volumeSizeLimitMB=64 -volume.max=500 >/dev/null
    PORT="$(docker port "$NAME" 8333/tcp | head -1 | sed 's/.*://')"
    EP="http://127.0.0.1:$PORT"
    ready=0
    for _ in $(seq 1 60); do
        # Any HTTP answer (even 403) means the S3 gateway is up; curl exits 7/52/56 until then.
        if curl -s -o /dev/null "$EP/"; then ready=1; break; fi
        sleep 1
    done
    [ "$ready" = 1 ] || { docker logs "$NAME" >&2; echo "S3 did not become ready" >&2; exit 1; }
    for b in $BUCKETS; do
        ok=0
        for _ in $(seq 1 30); do # the first PUTs can race volume growth
            code="$(curl -s -o /dev/null -w '%{http_code}' -X PUT --aws-sigv4 \
                "aws:amz:us-east-1:s3" --user "$KEY:$KEY" "$EP/$b")"
            if [ "$code" = 200 ] || [ "$code" = 409 ]; then ok=1; break; fi
            sleep 1
        done
        [ "$ok" = 1 ] || { docker logs "$NAME" >&2; echo "cannot create bucket $b" >&2; exit 1; }
    done
    # SeaweedFS grows volumes per bucket on first write, and the first grow fails ("Not enough
    # data nodes") until the volume server registers with the master -- seconds after the S3
    # port answers. Tests wait only ~3 s for their first write, so do it here: PUT (retried,
    # bounded) then DELETE one small object per bucket.
    deadline=$((SECONDS + 60))
    for b in $BUCKETS; do
        until [ "$(curl -s -o /dev/null -w '%{http_code}' -X PUT --data-binary warmup \
            --aws-sigv4 "aws:amz:us-east-1:s3" --user "$KEY:$KEY" "$EP/$b/.warmup")" = 200 ]; do
            if [ "$SECONDS" -ge "$deadline" ]; then
                docker logs "$NAME" >&2; echo "cannot write to bucket $b" >&2; exit 1
            fi
            sleep 1
        done
        curl -s -o /dev/null -X DELETE --aws-sigv4 "aws:amz:us-east-1:s3" \
            --user "$KEY:$KEY" "$EP/$b/.warmup"
    done
    echo "S3 test server ready at $EP" >&2
    echo "export MINIO_ENDPOINT=$EP MINIO_ACCESS_KEY=$KEY MINIO_SECRET_KEY=$KEY"
    ;;
down)
    docker rm -fv "$NAME" >/dev/null 2>&1 || true
    ;;
*)
    echo "usage: $0 up|down" >&2
    exit 2
    ;;
esac

#!/usr/bin/env python3
"""
Zeek S3 verifier for E2E testing.

Polls MinIO for Parquet objects under zeek/conn/, zeek/dns/, and zeek/unknown/
(the "weird" stream routes to unknown/ because "weird" is not a curated path),
downloads them, and validates schema + row count.
"""

import io
import os
import sys
import time

import boto3
import pyarrow.parquet as pq

MINIO_ENDPOINT = os.environ.get("MINIO_ENDPOINT", "http://minio:9000")
BUCKET = os.environ.get("MINIO_BUCKET", "zeek-logs")
ZEEK_PREFIX = os.environ.get("ZEEK_S3_PREFIX", "zeek/")
TIMEOUT = int(os.environ.get("E2E_TIMEOUT_SECS", "60"))

# Expected prefixes and minimum row counts
EXPECTED_STREAMS = {
    "zeek/conn/": {
        "min_rows": 5,
        "required_columns": ["ts", "uid", "id_orig_h", "id_orig_p",
                              "id_resp_h", "id_resp_p", "proto",
                              "orig_bytes", "conn_state", "_extra"],
    },
    "zeek/dns/": {
        "min_rows": 3,
        "required_columns": ["ts", "uid", "query", "qtype_name",
                              "rcode_name", "_extra"],
    },
    "zeek/weird/": {
        "min_rows": 2,
        "required_columns": ["ts", "uid", "log_path", "ingest_time", "payload"],
    },
}


def make_client():
    session = boto3.session.Session()
    return session.client(
        "s3",
        endpoint_url=MINIO_ENDPOINT,
        aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY"),
    )


def wait_for_prefix(client, prefix, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        resp = client.list_objects_v2(Bucket=BUCKET, Prefix=prefix)
        contents = resp.get("Contents", [])
        if contents:
            key = contents[0]["Key"]
            obj = client.get_object(Bucket=BUCKET, Key=key)
            body = obj["Body"].read()
            if len(body) > 0:
                print(f"Found Parquet object at {key} ({len(body)} bytes)")
                return key, body
        time.sleep(3)
    raise SystemExit(
        f"No Parquet object found under '{prefix}' in bucket '{BUCKET}' within {timeout}s"
    )


def verify_stream(prefix, body, spec):
    table = pq.read_table(io.BytesIO(body))
    actual_columns = set(table.schema.names)
    missing = [c for c in spec["required_columns"] if c not in actual_columns]
    if missing:
        print(f"ERROR [{prefix}]: missing columns: {missing}", file=sys.stderr)
        sys.exit(1)
    if table.num_rows < spec["min_rows"]:
        print(
            f"ERROR [{prefix}]: expected >= {spec['min_rows']} rows, got {table.num_rows}",
            file=sys.stderr,
        )
        sys.exit(1)
    print(
        f"OK [{prefix}]: {table.num_rows} row(s), "
        f"{len(actual_columns)} column(s): {sorted(actual_columns)}"
    )


def main():
    client = make_client()
    for prefix, spec in EXPECTED_STREAMS.items():
        key, body = wait_for_prefix(client, prefix, TIMEOUT)
        verify_stream(prefix, body, spec)
    print("Zeek S3 verifier succeeded")
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(0)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Zeek S3 verifier for E2E testing.

Polls MinIO for Parquet objects under zeek/conn/, zeek/dns/, and zeek/weird/.
Unmodelled Zeek streams keep their own path (e.g. zeek/weird/); only records
with a missing _path field (or a log_path that is empty after sanitisation)
route to zeek/unknown/.
Downloads each object and validates schema and row count.
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


def scan_prefix(client, prefix):
    """List every object under `prefix`, read each Parquet object, and return
    (total_rows, union_of_columns, object_count). Records flush one-per-object
    when flush_threshold_bytes=1, so rows must be summed ACROSS objects."""
    resp = client.list_objects_v2(Bucket=BUCKET, Prefix=prefix)
    contents = resp.get("Contents", [])
    total_rows = 0
    columns = set()
    for item in contents:
        body = client.get_object(Bucket=BUCKET, Key=item["Key"])["Body"].read()
        if not body:
            continue
        table = pq.read_table(io.BytesIO(body))
        total_rows += table.num_rows
        columns |= set(table.schema.names)
    return total_rows, columns, len(contents)


def verify_stream(client, prefix, spec, timeout):
    """Poll until the aggregate row count under `prefix` reaches the minimum,
    then validate the schema columns. Sums rows across all objects."""
    deadline = time.time() + timeout
    total_rows, columns, n = 0, set(), 0
    while time.time() < deadline:
        total_rows, columns, n = scan_prefix(client, prefix)
        if total_rows >= spec["min_rows"]:
            break
        time.sleep(3)

    missing = [c for c in spec["required_columns"] if c not in columns]
    if missing:
        print(
            f"ERROR [{prefix}]: missing columns: {missing} "
            f"(saw {sorted(columns)} across {n} object(s))",
            file=sys.stderr,
        )
        sys.exit(1)
    if total_rows < spec["min_rows"]:
        print(
            f"ERROR [{prefix}]: expected >= {spec['min_rows']} rows, "
            f"got {total_rows} across {n} object(s) within {timeout}s",
            file=sys.stderr,
        )
        sys.exit(1)
    print(
        f"OK [{prefix}]: {total_rows} row(s) across {n} object(s), "
        f"{len(columns)} column(s): {sorted(columns)}"
    )


def main():
    client = make_client()
    for prefix, spec in EXPECTED_STREAMS.items():
        verify_stream(client, prefix, spec, TIMEOUT)
    print("Zeek S3 verifier succeeded")
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(0)


if __name__ == "__main__":
    main()

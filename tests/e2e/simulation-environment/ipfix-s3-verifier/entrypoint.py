#!/usr/bin/env python3
"""
IPFIX S3 verifier for E2E testing.

Polls MinIO for a Parquet object under the IPFIX prefix, downloads it,
and verifies the schema contains the expected columns.
"""

import io
import os
import sys
import time

import boto3
import pyarrow.parquet as pq

MINIO_ENDPOINT = os.environ.get("MINIO_ENDPOINT", "http://minio:9000")
BUCKET = os.environ.get("MINIO_BUCKET", "ipfix-flows")
IPFIX_PREFIX = os.environ.get("IPFIX_S3_PREFIX", "ipfix/")
TIMEOUT = int(os.environ.get("E2E_TIMEOUT_SECS", "60"))
EXPECTED_EVENT_TOTAL = int(os.environ.get("EXPECTED_EVENT_TOTAL", "0"))

REQUIRED_COLUMNS = [
    "observation_domain_id",
    "template_id",
    "protocol_version",
    "exporter",
    "export_time",
    "src_addr",
    "dst_addr",
    "src_port",
    "dst_port",
    "ip_protocol",
    "octet_delta_count",
    "packet_delta_count",
    "flow_start",
    "flow_end",
    "tcp_flags",
    "input_interface",
    "output_interface",
    "extra",
]


def make_client():
    session = boto3.session.Session()
    return session.client(
        "s3",
        endpoint_url=MINIO_ENDPOINT,
        aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY"),
    )


def wait_for_ipfix_parquet(client):
    """Poll for a Parquet object under the IPFIX prefix."""
    deadline = time.time() + TIMEOUT
    while time.time() < deadline:
        resp = client.list_objects_v2(Bucket=BUCKET, Prefix=IPFIX_PREFIX)
        contents = resp.get("Contents", [])
        if contents:
            key = contents[0]["Key"]
            obj = client.get_object(Bucket=BUCKET, Key=key)
            body = obj["Body"].read()
            if len(body) > 0:
                print(f"Found IPFIX Parquet object at {key} ({len(body)} bytes)")
                return key, body
        time.sleep(3)
    raise SystemExit(
        f"No IPFIX Parquet object found under '{IPFIX_PREFIX}' in bucket "
        f"'{BUCKET}' within {TIMEOUT}s"
    )


def verify_parquet(key, body):
    """Read the Parquet bytes and validate schema + content."""
    table = pq.read_table(io.BytesIO(body))
    actual_columns = set(table.schema.names)

    missing = [c for c in REQUIRED_COLUMNS if c not in actual_columns]
    if missing:
        print(f"ERROR: missing columns in IPFIX Parquet: {missing}", file=sys.stderr)
        sys.exit(1)

    if table.num_rows == 0:
        print("ERROR: IPFIX Parquet object has 0 rows", file=sys.stderr)
        sys.exit(1)

    if EXPECTED_EVENT_TOTAL > 0 and table.num_rows < EXPECTED_EVENT_TOTAL:
        print(
            f"ERROR: IPFIX Parquet has {table.num_rows} row(s) but expected "
            f">= {EXPECTED_EVENT_TOTAL}",
            file=sys.stderr,
        )
        sys.exit(1)

    print(
        f"OK: IPFIX Parquet verified at {key}: "
        f"{table.num_rows} row(s) (expected >= {EXPECTED_EVENT_TOTAL}), "
        f"{len(actual_columns)} column(s)"
    )
    print(f"    Columns: {sorted(actual_columns)}")


def main():
    client = make_client()
    key, body = wait_for_ipfix_parquet(client)
    verify_parquet(key, body)
    print("IPFIX S3 verifier succeeded")


if __name__ == "__main__":
    main()

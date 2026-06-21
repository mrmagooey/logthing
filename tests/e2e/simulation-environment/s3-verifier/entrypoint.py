import os
import sys
import time

import boto3
import requests

MINIO_ENDPOINT = os.environ.get("MINIO_ENDPOINT", "http://minio:9000")
BUCKET = os.environ.get("MINIO_BUCKET", "wef-events")
STATS_ENDPOINT = os.environ.get(
    "WEF_STATS_ENDPOINT", "http://logthing:5985/stats/throughput"
)
EXPECTED_TOTAL = int(os.environ.get("EXPECTED_EVENT_TOTAL", "2"))
TIMEOUT = int(os.environ.get("E2E_TIMEOUT_SECS", "120"))


def wait_for_stats():
    deadline = time.time() + TIMEOUT
    while time.time() < deadline:
        try:
            resp = requests.get(STATS_ENDPOINT, timeout=5)
            resp.raise_for_status()
            payload = resp.json()
            total = sum(row.get("total_events", 0) for row in payload)
            if total >= EXPECTED_TOTAL:
                print(f"Throughput stats show total {total}")
                return
        except (requests.RequestException, ValueError):
            pass
        time.sleep(3)
    raise SystemExit("Stats never reached expected total")


def wait_for_object():
    session = boto3.session.Session()
    client = session.client(
        "s3",
        endpoint_url=MINIO_ENDPOINT,
        aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY"),
    )
    deadline = time.time() + TIMEOUT
    while time.time() < deadline:
        resp = client.list_objects_v2(Bucket=BUCKET)
        contents = resp.get("Contents", [])
        if contents:
            key = contents[0]["Key"]
            obj = client.get_object(Bucket=BUCKET, Key=key)
            size = obj["ContentLength"]
            if size > 0:
                print(f"Found S3 object {key} size {size}")
                return
        time.sleep(5)
    raise SystemExit("No S3 objects created in time")


def wait_for_syslog_parquet():
    """Poll for a Parquet object under the syslog/ prefix and validate its schema."""
    session = boto3.session.Session()
    client = session.client(
        "s3",
        endpoint_url=MINIO_ENDPOINT,
        aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY"),
    )

    syslog_prefix = "syslog/"
    deadline = time.time() + 30  # 30-second poll window
    syslog_found = False
    resp = None
    while time.time() < deadline:
        resp = client.list_objects_v2(Bucket=BUCKET, Prefix=syslog_prefix)
        if resp.get("Contents"):
            syslog_found = True
            break
        time.sleep(2)

    if not syslog_found:
        print(
            f"ERROR: No Parquet object found under {syslog_prefix} in {BUCKET}",
            file=sys.stderr,
        )
        sys.exit(1)

    # Verify the first object is readable Parquet with 11 columns
    key = resp["Contents"][0]["Key"]
    obj = client.get_object(Bucket=BUCKET, Key=key)
    import io

    import pyarrow.parquet as pq

    table = pq.read_table(io.BytesIO(obj["Body"].read()))
    assert table.num_columns == 11, f"Expected 11 columns, got {table.num_columns}"
    assert table.num_rows > 0, "Expected at least one row in syslog Parquet"
    print(
        f"OK: syslog Parquet verified: {table.num_rows} row(s) under {syslog_prefix}"
    )


def main():
    wait_for_stats()
    wait_for_object()
    wait_for_syslog_parquet()
    print("S3 verifier succeeded")


if __name__ == "__main__":
    main()

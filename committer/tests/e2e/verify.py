#!/usr/bin/env python3
"""Outermost-interface verifier for the committer e2e test.

Run after run.sh has: started the local stack (MinIO + Postgres + Lakekeeper),
sent N syslog messages through a real logthing process, and run the committer
container once against the resulting descriptor queue. This script reads the
result back exclusively through the Iceberg REST catalog (pyiceberg) and S3
(boto3) -- the same two interfaces any real consumer would use -- never by
importing commit.py or logthing internals directly.

Usage:
    verify.py <marker> <expected_row_count>

Also verifies the hec upgrade path and the otlp table when HEC_MARKER/OTLP_MARKER are set.

Exits non-zero (with an assertion message) on any check failure.
"""

from __future__ import annotations

import json
import os
import sys
import uuid

import boto3
from pyiceberg.catalog.rest import RestCatalog
from pyiceberg.io.pyarrow import PyArrowFileIO

NAMESPACE = "logs"
TABLE = "syslog"

CATALOG_URI = os.environ.get("CATALOG_URI", "http://localhost:8181/catalog")
WAREHOUSE = os.environ.get("WAREHOUSE", "logthing-warehouse")
S3_ENDPOINT = os.environ.get("S3_ENDPOINT", "http://localhost:9000")
S3_ACCESS_KEY = os.environ.get("S3_ACCESS_KEY", "minioadmin")
S3_SECRET_KEY = os.environ.get("S3_SECRET_KEY", "minioadmin")
DATA_BUCKET = os.environ.get("DATA_BUCKET", "logthing-data")
DESC_PREFIX = os.environ.get("DESC_PREFIX", "_iceberg_descriptors/")
DONE_PREFIX = os.environ.get("DONE_PREFIX", "_committed/")


def s3_io_properties() -> dict[str, str]:
    return {
        "s3.endpoint": S3_ENDPOINT,
        "s3.access-key-id": S3_ACCESS_KEY,
        "s3.secret-access-key": S3_SECRET_KEY,
        "s3.region": "us-east-1",
        # Same reasoning as commit.py: pyiceberg property_as_bool() treats
        # the Python bool False as "absent", so booleans go in as strings.
        "s3.force-virtual-addressing": "False",
    }


def catalog() -> RestCatalog:
    return RestCatalog(
        "e2e-verify",
        **{
            "uri": CATALOG_URI,
            "warehouse": WAREHOUSE,
            **s3_io_properties(),
        },
    )


def s3_client():
    return boto3.client(
        "s3",
        endpoint_url=S3_ENDPOINT,
        aws_access_key_id=S3_ACCESS_KEY,
        aws_secret_access_key=S3_SECRET_KEY,
        region_name="us-east-1",
    )


def prefix_object_count(client, prefix: str) -> int:
    paginator = client.get_paginator("list_objects_v2")
    count = 0
    for page in paginator.paginate(Bucket=DATA_BUCKET, Prefix=prefix):
        count += len(page.get("Contents", []))
    return count


def load(cat, name):
    table = cat.load_table((NAMESPACE, name))
    table.io = PyArrowFileIO(properties=s3_io_properties())
    return table


def verify_hec(cat, marker: str) -> None:
    table = load(cat, "hec")
    cols = set(table.schema().column_names)
    assert {"event_uuid", "source", "index", "indexed_fields"} <= cols, cols
    # The table was CREATED from a legacy-shaped file (run.sh seeds one first), so the new
    # columns can only be there because the committer evolved the schema.
    assert len(table.metadata.schemas) >= 2, "expected schema evolution to have created a new schema"
    rows = table.scan().to_arrow().to_pylist()
    legacy = [r for r in rows if "legacy-row" in r["fields"]]
    fresh = [r for r in rows if marker in r["fields"]]
    assert len(legacy) == 1 and len(fresh) == 1, (len(legacy), len(fresh), len(rows))
    assert legacy[0]["event_uuid"] is None, "old rows must read NULL for new columns"
    assert uuid.UUID(fresh[0]["event_uuid"]).version == 7
    assert fresh[0]["source"] == "committer-e2e" and fresh[0]["index"] == "main"
    assert json.loads(fresh[0]["indexed_fields"]) == {"env": "e2e"}
    print(f"OK: hec evolved ({len(table.metadata.schemas)} schemas), legacy row NULL, new row typed")


def verify_otlp(cat, marker: str) -> None:
    names = sorted(t[1] for t in cat.list_tables(NAMESPACE))
    assert "otlp" in names and not [n for n in names if n.startswith("otlp_")], names
    table = load(cat, "otlp")
    day = [f for f in table.spec().fields if f.transform.__class__.__name__ == "DayTransform"]
    assert day and table.schema().find_field(day[0].source_id).name == "partition_time"
    rows = [r for r in table.scan().to_arrow().to_pylist() if r["body"] == marker]
    assert len(rows) == 1, f"expected exactly one OTLP row with the marker, found {len(rows)}"
    r = rows[0]
    assert r["service_name"] == "committer-e2e" and r["severity_number"] == 9
    assert r["severity_text"] == "INFO" and r["scope_name"] == "e2e-lib"
    assert r["trace_id"] == "0af7651916cd43dd8448eb211c80319c"
    assert r["span_id"] == "b7ad6b7169203331" and r["peer_addr"]
    assert r["time"] is not None and uuid.UUID(r["event_uuid"]).version == 7
    assert json.loads(r["attributes"]) == {"http.route": "/e2e"}
    assert json.loads(r["resource_attributes"])["service.name"] == "committer-e2e"
    print(f"OK: otlp table has typed row, tables={names}")


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <marker> <expected_row_count>", file=sys.stderr)
        return 2
    marker = sys.argv[1]
    expected_rows = int(sys.argv[2])

    cat = catalog()
    identifier = (NAMESPACE, TABLE)

    assert cat.table_exists(identifier), f"table {NAMESPACE}.{TABLE} does not exist"
    table = cat.load_table(identifier)
    # A REST catalog hands back tables using FsspecFileIO, which needs the
    # s3fs package (not installed here, and not a dependency of commit.py
    # either) -- force PyArrowFileIO, exactly as commit.py does, so reading
    # this table needs nothing beyond what requirements.txt already installs.
    table.io = PyArrowFileIO(properties=s3_io_properties())

    spec = table.spec()
    day_fields = [f for f in spec.fields if f.transform.__class__.__name__ == "DayTransform"]
    assert day_fields, f"table is not partitioned by day(...): spec={spec}"
    source_name = table.schema().find_field(day_fields[0].source_id).name
    assert source_name == "partition_time", (
        f"day partition source column is {source_name!r}, expected 'partition_time'"
    )

    rows = table.scan().to_arrow()
    assert rows.num_rows == expected_rows, (
        f"expected {expected_rows} rows in {NAMESPACE}.{TABLE}, found {rows.num_rows}"
    )

    messages = rows.column("message").to_pylist()
    assert any(marker in m for m in messages), (
        f"marker {marker!r} not found in any of {len(messages)} committed rows"
    )

    hec_marker = os.environ.get("HEC_MARKER")
    otlp_marker = os.environ.get("OTLP_MARKER")
    if hec_marker:
        verify_hec(cat, hec_marker)
    if otlp_marker:
        verify_otlp(cat, otlp_marker)

    client = s3_client()
    remaining = prefix_object_count(client, DESC_PREFIX)
    assert remaining == 0, f"expected an empty {DESC_PREFIX!r} queue, found {remaining} object(s)"

    done = prefix_object_count(client, DONE_PREFIX)
    assert done > 0, f"expected at least one committed descriptor under {DONE_PREFIX!r}, found 0"

    print(
        f"OK: {NAMESPACE}.{TABLE} has {rows.num_rows} rows, day-partitioned on "
        f"partition_time, marker present, queue drained ({done} done, 0 remaining)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

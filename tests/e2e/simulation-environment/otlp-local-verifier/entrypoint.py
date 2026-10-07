#!/usr/bin/env python3
"""OTLP local-disk verifier for E2E testing.

Reads the Parquet files under OTLP_LOCAL_DIR/otlp/** (shared volume with the logthing
container) and checks the TYPED schema and the per-service partition layout.
"""

import glob
import json
import os
import sys
import time
import uuid

import pyarrow as pa
import pyarrow.parquet as pq

LOCAL_DIR = os.environ.get("OTLP_LOCAL_DIR", "/var/log/otlp-local")
TIMEOUT = int(os.environ.get("E2E_TIMEOUT_SECS", "60"))
EXPECTED_ROWS = 6

REQUIRED_TYPES = {
    "event_uuid": pa.string(),
    "time": pa.timestamp("us", tz="UTC"),
    "observed_time": pa.timestamp("us", tz="UTC"),
    "received_at": pa.timestamp("us", tz="UTC"),
    "severity_number": pa.int32(),
    "severity_text": pa.string(),
    "body": pa.string(),
    "service_name": pa.string(),
    "peer_addr": pa.string(),
    "trace_id": pa.string(),
    "span_id": pa.string(),
    "flags": pa.uint32(),
    "scope_name": pa.string(),
    "scope_version": pa.string(),
    "resource_attributes": pa.string(),
    "attributes": pa.string(),
    "partition_time": pa.timestamp("us", tz="UTC"),
}


def load():
    files = sorted(glob.glob(os.path.join(LOCAL_DIR, "otlp", "**", "*.parquet"), recursive=True))
    tables = [pq.read_table(f) for f in files]
    return files, tables


def fail(msg):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def main():
    deadline = time.time() + TIMEOUT
    files, tables = load()
    while time.time() < deadline and sum(t.num_rows for t in tables) < EXPECTED_ROWS:
        time.sleep(3)
        files, tables = load()
    rows = sum(t.num_rows for t in tables)
    if rows < EXPECTED_ROWS:
        fail(f"expected >= {EXPECTED_ROWS} rows, got {rows} across {len(files)} file(s)")

    dirs = {os.path.relpath(f, os.path.join(LOCAL_DIR, "otlp")).split(os.sep)[0] for f in files}
    for want in ("svc_a", "svc_b", "unknown"):
        if want not in dirs:
            fail(f"missing service partition directory {want!r}; saw {sorted(dirs)}")

    for f, t in zip(files, tables):
        for name, typ in REQUIRED_TYPES.items():
            if name not in t.schema.names:
                fail(f"{f}: missing column {name}")
            if t.schema.field(name).type != typ:
                fail(f"{f}: column {name} is {t.schema.field(name).type}, expected {typ}")
        if "fields" in t.schema.names:
            fail(f"{f}: OTLP must not use the generic HEC schema")
        if t.schema.field("event_uuid").nullable or t.schema.field("partition_time").nullable:
            fail(f"{f}: event_uuid and partition_time must be NOT NULL")

    all_rows = [r for t in tables for r in t.to_pylist()]
    ids = [r["event_uuid"] for r in all_rows]
    if len(set(ids)) != len(ids):
        fail("event_uuid values are not unique")
    if any(uuid.UUID(i).version != 7 for i in ids):
        fail("event_uuid must be UUIDv7")

    by_body = {r["body"]: r for r in all_rows}
    a0 = by_body.get("a-0") or fail("record a-0 missing")
    if (a0["service_name"], a0["severity_number"], a0["severity_text"]) != ("svc-a", 9, "INFO"):
        fail(f"svc-a typed columns wrong: {a0}")
    if a0["trace_id"] != "0af7651916cd43dd8448eb211c80319c" or a0["span_id"] != "b7ad6b7169203331":
        fail(f"trace/span ids wrong: {a0}")
    if a0["scope_name"] != "sim-lib" or a0["scope_version"] != "1.0":
        fail(f"scope columns wrong: {a0}")
    if json.loads(a0["attributes"]) != {"http.route": "/sim"}:
        fail(f"attributes wrong: {a0['attributes']}")
    if json.loads(a0["resource_attributes"]).get("service.name") != "svc-a":
        fail(f"resource_attributes wrong: {a0['resource_attributes']}")
    if not a0["peer_addr"]:
        fail("peer_addr must hold the TCP peer IP")
    b0 = by_body.get("b-0") or fail("record b-0 missing")
    if b0["service_name"] != "Svc B" or b0["severity_number"] != 13:
        fail(f"raw service_name must be kept for 'Svc B': {b0}")
    n = by_body.get("no-resource") or fail("no-resource record missing")
    if n["service_name"] is not None:
        fail(f"no-resource record must have NULL service_name: {n}")
    if "rejected" in by_body:
        fail("a request rejected with 401 must not be persisted")

    print(f"OK: {rows} OTLP rows, partitions {sorted(dirs)}, typed schema verified")
    sys.stdout.flush()
    os._exit(0)


if __name__ == "__main__":
    main()

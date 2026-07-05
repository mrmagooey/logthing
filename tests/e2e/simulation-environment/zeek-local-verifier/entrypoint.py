#!/usr/bin/env python3
"""
Zeek local-disk verifier for E2E testing.

Walks a local directory tree (shared volume with the `logthing` container) for
Parquet objects under zeek/conn/ and zeek/dns/, downloads each, and validates
schema and row count. Mirrors zeek-s3-verifier/entrypoint.py's checks, applied
to the local-disk target instead of MinIO.
"""

import glob
import os
import sys
import time

import pyarrow.parquet as pq

ZEEK_LOCAL_DIR = os.environ.get("ZEEK_LOCAL_DIR", "/var/log/zeek-local")
TIMEOUT = int(os.environ.get("E2E_TIMEOUT_SECS", "60"))

EXPECTED_STREAMS = {
    "zeek/conn": {
        "min_rows": 5,
        "required_columns": ["ts", "uid", "id_orig_h", "id_orig_p",
                              "id_resp_h", "id_resp_p", "proto",
                              "orig_bytes", "conn_state", "_extra"],
    },
    "zeek/dns": {
        "min_rows": 3,
        "required_columns": ["ts", "uid", "query", "qtype_name",
                              "rcode_name", "_extra"],
    },
}


def scan_dir(relative_prefix):
    """Read every .parquet file under ZEEK_LOCAL_DIR/relative_prefix/**,
    return (total_rows, union_of_columns, file_count)."""
    pattern = os.path.join(ZEEK_LOCAL_DIR, relative_prefix, "**", "*.parquet")
    files = glob.glob(pattern, recursive=True)
    total_rows = 0
    columns = set()
    for path in files:
        table = pq.read_table(path)
        total_rows += table.num_rows
        columns |= set(table.schema.names)
    return total_rows, columns, len(files)


def verify_stream(relative_prefix, spec, timeout):
    deadline = time.time() + timeout
    total_rows, columns, n = 0, set(), 0
    while time.time() < deadline:
        total_rows, columns, n = scan_dir(relative_prefix)
        if total_rows >= spec["min_rows"]:
            break
        time.sleep(3)

    missing = [c for c in spec["required_columns"] if c not in columns]
    if missing:
        print(
            f"ERROR [{relative_prefix}]: missing columns: {missing} "
            f"(saw {sorted(columns)} across {n} file(s))",
            file=sys.stderr,
        )
        sys.exit(1)
    if total_rows < spec["min_rows"]:
        print(
            f"ERROR [{relative_prefix}]: expected >= {spec['min_rows']} rows, "
            f"got {total_rows} across {n} file(s) within {timeout}s",
            file=sys.stderr,
        )
        sys.exit(1)
    print(
        f"OK [{relative_prefix}]: {total_rows} row(s) across {n} file(s), "
        f"{len(columns)} column(s): {sorted(columns)}"
    )


def main():
    for relative_prefix, spec in EXPECTED_STREAMS.items():
        verify_stream(relative_prefix, spec, TIMEOUT)
    print("Zeek local-disk verifier succeeded")
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(0)


if __name__ == "__main__":
    main()

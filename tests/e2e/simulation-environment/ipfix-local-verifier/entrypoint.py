#!/usr/bin/env python3
"""
IPFIX local-disk verifier for E2E testing.

Walks a local directory tree (shared volume with the `logthing` container)
for Parquet objects under ipfix/, downloads each, and validates schema and
row count. Mirrors ipfix-s3-verifier/entrypoint.py's checks, applied to the
local-disk target instead of MinIO.
"""

import glob
import os
import sys
import time

import pyarrow.parquet as pq

IPFIX_LOCAL_DIR = os.environ.get("IPFIX_LOCAL_DIR", "/var/log/ipfix-local")
TIMEOUT = int(os.environ.get("E2E_TIMEOUT_SECS", "60"))
MIN_ROWS = int(os.environ.get("EXPECTED_EVENT_TOTAL", "5"))

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


def scan_dir():
    """Read every .parquet file under IPFIX_LOCAL_DIR/ipfix/**,
    return (total_rows, union_of_columns, file_count)."""
    pattern = os.path.join(IPFIX_LOCAL_DIR, "ipfix", "**", "*.parquet")
    files = glob.glob(pattern, recursive=True)
    total_rows = 0
    columns = set()
    for path in files:
        table = pq.read_table(path)
        total_rows += table.num_rows
        columns |= set(table.schema.names)
    return total_rows, columns, len(files)


def main():
    deadline = time.time() + TIMEOUT
    total_rows, columns, n = 0, set(), 0
    while time.time() < deadline:
        total_rows, columns, n = scan_dir()
        if total_rows >= MIN_ROWS:
            break
        time.sleep(3)

    missing = [c for c in REQUIRED_COLUMNS if c not in columns]
    if missing:
        print(
            f"ERROR: missing columns: {missing} (saw {sorted(columns)} across {n} file(s))",
            file=sys.stderr,
        )
        sys.exit(1)
    if total_rows < MIN_ROWS:
        print(
            f"ERROR: expected >= {MIN_ROWS} rows, got {total_rows} across {n} file(s) "
            f"within {TIMEOUT}s",
            file=sys.stderr,
        )
        sys.exit(1)

    print(
        f"OK: {total_rows} row(s) across {n} file(s), {len(columns)} column(s): "
        f"{sorted(columns)}"
    )
    print("IPFIX local-disk verifier succeeded")
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(0)


if __name__ == "__main__":
    main()

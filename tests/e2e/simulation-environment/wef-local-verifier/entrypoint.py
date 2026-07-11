#!/usr/bin/env python3
"""
WEF local-disk verifier for E2E testing.

Walks a local directory tree (shared volume with the `logthing` container)
for Parquet objects under event_type=*/, downloads each, and validates
schema and row count. Mirrors ipfix-local-verifier/entrypoint.py's checks,
applied to WEF's empty-prefix event_type=<id>/year=… layout instead of a
fixed source-name prefix.

Also polls a second shared volume (the `[iceberg.local]` destination
configured alongside WEF's own `[wef.local]` in config/logthing.toml) for
at least one Iceberg descriptor JSON file, and validates its shape. The
descriptor sink is shared across every enabled source in the `logthing`
container (syslog, ipfix, zeek, wef, ...), so this only proves that *some*
source produced a well-formed descriptor — it does not require the
descriptor to specifically describe a WEF-sourced Parquet file.
"""

import glob
import json
import os
import sys
import time

import pyarrow.parquet as pq

WEF_LOCAL_DIR = os.environ.get("WEF_LOCAL_DIR", "/var/log/wef-local")
TIMEOUT = int(os.environ.get("E2E_TIMEOUT_SECS", "60"))
MIN_ROWS = int(os.environ.get("EXPECTED_EVENT_TOTAL", "5"))

ICEBERG_LOCAL_DIR = os.environ.get("ICEBERG_LOCAL_DIR", "/var/log/iceberg-local")

REQUIRED_COLUMNS = [
    "event_id",
    "timestamp",
    "source_host",
    "subscription_id",
    "event_data",
]

REQUIRED_DESCRIPTOR_KEYS = ["source", "file_path", "record_count"]


def scan_dir():
    """Read every .parquet file under WEF_LOCAL_DIR/event_type=*/**,
    return (total_rows, union_of_columns, file_count)."""
    pattern = os.path.join(WEF_LOCAL_DIR, "event_type=*", "**", "*.parquet")
    files = glob.glob(pattern, recursive=True)
    total_rows = 0
    columns = set()
    for path in files:
        table = pq.read_table(path)
        total_rows += table.num_rows
        columns |= set(table.schema.names)
    return total_rows, columns, len(files)


def scan_iceberg_descriptors():
    """Read every .json file under ICEBERG_LOCAL_DIR/**, return the first
    one that parses and has a sane shape, or None if none qualify yet."""
    pattern = os.path.join(ICEBERG_LOCAL_DIR, "**", "*.json")
    files = glob.glob(pattern, recursive=True)
    for path in files:
        try:
            with open(path) as f:
                descriptor = json.load(f)
        except (OSError, json.JSONDecodeError):
            # Descriptor write is rename-into-place, but tolerate a file
            # still being written/renamed at the moment we glob it.
            continue
        missing = [k for k in REQUIRED_DESCRIPTOR_KEYS if k not in descriptor]
        if missing:
            continue
        if (
            not isinstance(descriptor["source"], str)
            or not descriptor["source"]
            or not isinstance(descriptor["file_path"], str)
            or not descriptor["file_path"]
            or not isinstance(descriptor["record_count"], int)
            or descriptor["record_count"] <= 0
        ):
            continue
        return path, descriptor
    return None, None


def main():
    deadline = time.time() + TIMEOUT
    total_rows, columns, n = 0, set(), 0
    descriptor_path, descriptor = None, None
    while time.time() < deadline:
        total_rows, columns, n = scan_dir()
        descriptor_path, descriptor = scan_iceberg_descriptors()
        if total_rows >= MIN_ROWS and descriptor is not None:
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
    if descriptor is None:
        print(
            f"ERROR: no valid Iceberg descriptor JSON found under {ICEBERG_LOCAL_DIR} "
            f"within {TIMEOUT}s (need keys {REQUIRED_DESCRIPTOR_KEYS} with sane values)",
            file=sys.stderr,
        )
        sys.exit(1)

    print(
        f"OK: {total_rows} row(s) across {n} file(s), {len(columns)} column(s): "
        f"{sorted(columns)}"
    )
    print(
        f"OK: Iceberg descriptor at {descriptor_path}: source={descriptor['source']!r} "
        f"file_path={descriptor['file_path']!r} record_count={descriptor['record_count']}"
    )
    print("WEF local-disk verifier succeeded")
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(0)


if __name__ == "__main__":
    main()

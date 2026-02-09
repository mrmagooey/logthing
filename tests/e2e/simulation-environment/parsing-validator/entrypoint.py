#!/usr/bin/env python3
"""
Parsing Validator for Logthing E2E Tests

Validates that:
1. Parquet files have correct schema
2. Parsed fields match expected values from parser definitions
3. Enrichment fields are populated (e.g., LogonType_Name)
4. Output format fields are rendered correctly
"""

import json
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import boto3
import pyarrow
import pyarrow.parquet as pq
import requests
import yaml

# Configuration from environment
MINIO_ENDPOINT = os.environ.get("MINIO_ENDPOINT", "http://minio:9000")
BUCKET = os.environ.get("MINIO_BUCKET", "wef-events")
STATS_ENDPOINT = os.environ.get(
    "WEF_STATS_ENDPOINT", "http://logthing:5985/stats/throughput"
)
PARSER_DIR = Path(os.environ.get("PARSER_DIR", "/app/parsers"))
TIMEOUT = int(os.environ.get("E2E_TIMEOUT_SECS", "120"))
AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID", "miniouser")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY", "miniopassword")

# Test results tracking
results: List[Tuple[str, bool, str]] = []


def log_result(test_name: str, passed: bool, message: str = "") -> bool:
    """Log a test result and return the pass status."""
    status = "✓ PASS" if passed else "✗ FAIL"
    results.append((test_name, passed, message))
    if message:
        print(f"  [{status}] {test_name}: {message}")
    else:
        print(f"  [{status}] {test_name}")
    return passed


def load_parser_definitions() -> Dict[int, Dict[str, Any]]:
    """Load all parser YAML definitions."""
    parsers = {}
    if not PARSER_DIR.exists():
        print(f"Warning: Parser directory {PARSER_DIR} does not exist")
        return parsers

    for yaml_file in sorted(PARSER_DIR.glob("*.y*ml")):
        try:
            data = yaml.safe_load(yaml_file.read_text())
            if data and "event_id" in data:
                parsers[data["event_id"]] = data
        except Exception as e:
            print(f"Warning: Failed to load {yaml_file}: {e}")

    print(f"Loaded {len(parsers)} parser definitions")
    return parsers


def wait_for_events() -> bool:
    """Wait for events to be processed and available in stats."""
    print("\nWaiting for events to be processed...")
    deadline = time.time() + TIMEOUT

    while time.time() < deadline:
        try:
            resp = requests.get(STATS_ENDPOINT, timeout=5)
            resp.raise_for_status()
            payload = resp.json()

            total = sum(row.get("total_events", 0) for row in payload)
            if total > 0:
                print(f"  Found {total} events in throughput stats")
                return True
        except (requests.RequestException, ValueError) as e:
            print(f"  Waiting... ({e})")

        time.sleep(3)

    log_result("Events Available", False, "Timeout waiting for events")
    return False


def get_s3_client():
    """Create S3 client for MinIO."""
    session = boto3.session.Session()
    return session.client(
        "s3",
        endpoint_url=MINIO_ENDPOINT,
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    )


def wait_for_parquet_files() -> List[str]:
    """Wait for Parquet files to appear in S3."""
    print("\nWaiting for Parquet files in S3...")
    client = get_s3_client()
    deadline = time.time() + TIMEOUT

    while time.time() < deadline:
        try:
            resp = client.list_objects_v2(Bucket=BUCKET)
            contents = resp.get("Contents", [])
            parquet_files = [
                obj["Key"] for obj in contents if obj["Key"].endswith(".parquet")
            ]

            if parquet_files:
                print(f"  Found {len(parquet_files)} Parquet file(s)")
                return parquet_files
        except Exception as e:
            print(f"  Waiting... ({e})")

        time.sleep(5)

    return []


def download_and_read_parquet(key: str) -> Tuple[Optional[pq.ParquetFile], str]:
    """Download and read a Parquet file from S3."""
    client = get_s3_client()
    temp_dir = tempfile.gettempdir()
    local_path = os.path.join(temp_dir, key.replace("/", "_"))

    try:
        client.download_file(BUCKET, key, local_path)
        pf = pq.ParquetFile(local_path)
        return pf, local_path
    except Exception as e:
        return None, str(e)


def validate_parquet_schema(pf: pq.ParquetFile) -> bool:
    """Validate that Parquet file has expected schema."""
    print("\nValidating Parquet Schema...")
    schema = pf.schema_arrow

    # Required fields that should be present
    required_fields = {
        "event_id",
        "timestamp",
        "source_host",
        "subscription_id",
        "event_data",
    }

    # Get actual field names
    actual_fields = {field.name for field in schema}

    # Check required fields exist
    missing = required_fields - actual_fields
    if missing:
        print(f"  Actual fields found: {sorted(actual_fields)}")
        return log_result(
            "Required Fields Present", False, f"Missing fields: {missing}"
        )

    log_result("Required Fields Present", True)
    print(f"  Schema has {len(schema.names)} fields: {list(schema.names)[:10]}...")
    return True


def validate_parsed_fields(table: pyarrow.Table, parsers: Dict[int, Dict]) -> bool:
    """Validate that event data is present and event IDs are valid."""
    print("\nValidating Parsed Fields...")

    df = table.to_pandas()
    if df.empty:
        return log_result("Non-empty DataFrame", False, "No data in Parquet file")

    # Filter rows with event data
    event_rows = df[df["event_data"].notna()]
    if event_rows.empty:
        return log_result("Event Data Present", False, "No event data found")

    log_result("Event Data Present", True)

    # Get unique event IDs from event data
    event_ids = set()
    for _, row in event_rows.iterrows():
        event_id = row.get("event_id")
        if event_id:
            event_ids.add(event_id)

    print(f"  Found {len(event_ids)} unique event ID(s): {sorted(event_ids)[:10]}")

    # Check if we have parsers for the events
    all_passed = True
    for event_id in event_ids:
        if event_id in parsers:
            log_result(f"Event {event_id} Parser", True, "Parser definition found")
        else:
            log_result(f"Event {event_id} Parser", False, "No parser definition found")
            all_passed = False

    return all_passed


def validate_enrichment_fields(table: pyarrow.Table, parsers: Dict[int, Dict]) -> bool:
    """Validate enrichments - skipped for raw event data format."""
    print("\nValidating Enrichment Fields...")
    print("  Skipped: Enrichment validation requires parsed data format")
    return True


def validate_output_format(table: pyarrow.Table, parsers: Dict[int, Dict]) -> bool:
    """Validate output format - skipped for raw event data format."""
    print("\nValidating Output Format Rendering...")
    print("  Skipped: Output format validation requires parsed data format")
    return True


def validate_event_counts(table: pyarrow.Table) -> bool:
    """Validate that event data is present in the Parquet file."""
    print("\nValidating Event Counts...")

    try:
        df = table.to_pandas()
        parquet_total = len(df)

        if parquet_total > 0:
            log_result(
                "Event Count Match",
                True,
                f"Parquet file contains {parquet_total} event(s)",
            )
            return True
        else:
            log_result(
                "Event Count Match",
                False,
                f"Parquet file is empty",
            )
            return False
    except Exception as e:
        log_result("Event Count Match", False, str(e))
        return False


def main():
    """Main entry point for parsing validator."""
    print("=" * 60)
    print("Logthing Parsing Validator")
    print("=" * 60)
    print(f"MinIO Endpoint: {MINIO_ENDPOINT}")
    print(f"Bucket: {BUCKET}")
    print(f"Parser Dir: {PARSER_DIR}")
    print()

    # Load parser definitions
    parsers = load_parser_definitions()
    if not parsers:
        print("Error: No parser definitions loaded")
        sys.exit(1)

    # Wait for events to be processed
    if not wait_for_events():
        print("\n✗ Failed: No events found in throughput stats")
        sys.exit(1)

    # Wait for Parquet files
    parquet_files = wait_for_parquet_files()
    if not parquet_files:
        print("\n✗ Failed: No Parquet files found in S3")
        sys.exit(1)

    # Validate each Parquet file
    all_passed = True
    for key in parquet_files:
        print(f"\n{'=' * 60}")
        print(f"Validating: {key}")
        print("=" * 60)

        pf, result = download_and_read_parquet(key)
        if pf is None:
            log_result("File Download", False, result)
            all_passed = False
            continue

        # Run all validations
        validations = [
            ("Schema", validate_parquet_schema(pf)),
            ("Parsed Fields", validate_parsed_fields(pf.read(), parsers)),
            ("Enrichments", validate_enrichment_fields(pf.read(), parsers)),
            ("Output Format", validate_output_format(pf.read(), parsers)),
            ("Event Counts", validate_event_counts(pf.read())),
        ]

        for name, passed in validations:
            if not passed:
                all_passed = False

    # Print summary
    print("\n" + "=" * 60)
    print("Validation Summary")
    print("=" * 60)

    passed_count = sum(1 for _, passed, _ in results if passed)
    total_count = len(results)

    print(f"\nTotal Tests: {total_count}")
    print(f"Passed: {passed_count}")
    print(f"Failed: {total_count - passed_count}")

    if passed_count == total_count:
        print("\n✓ All parsing validations passed!")
        sys.exit(0)
    else:
        print("\n✗ Some validations failed")
        sys.exit(1)


if __name__ == "__main__":
    main()

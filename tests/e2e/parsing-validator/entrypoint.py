#!/usr/bin/env python3
"""
Parsing Validator for WEF Server E2E Tests

Validates that:
1. Parquet files have correct schema
2. Parsed fields match expected values from parser definitions
3. Enrichment fields are populated (e.g., LogonType_Name)
4. Output format fields are rendered correctly
"""

import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import boto3
import pyarrow.parquet as pq
import requests
import yaml

# Configuration from environment
MINIO_ENDPOINT = os.environ.get("MINIO_ENDPOINT", "http://minio:9000")
BUCKET = os.environ.get("MINIO_BUCKET", "wef-events")
STATS_ENDPOINT = os.environ.get(
    "WEF_STATS_ENDPOINT", "http://wef-server:5985/stats/throughput"
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
                obj["Key"]
                for obj in contents
                if obj["Key"].endswith(".parquet")
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
    local_path = f"/tmp/{key.replace('/', '_')}"

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
        "id",
        "received_at",
        "source_host",
        "subscription_id",
        "raw_xml",
        "parsed",
    }

    # Get actual field names
    actual_fields = {field.name for field in schema}

    # Check required fields exist
    missing = required_fields - actual_fields
    if missing:
        return log_result(
            "Required Fields Present", False, f"Missing fields: {missing}"
        )

    log_result("Required Fields Present", True)
    print(f"  Schema has {len(schema.names)} fields: {list(schema.names)[:10]}...")
    return True


def validate_parsed_fields(table: pq.Table, parsers: Dict[int, Dict]) -> bool:
    """Validate that parsed fields match parser definitions."""
    print("\nValidating Parsed Fields...")

    df = table.to_pandas()
    if df.empty:
        return log_result("Non-empty DataFrame", False, "No data in Parquet file")

    # Filter rows with parsed data
    parsed_rows = df[df["parsed"].notna()]
    if parsed_rows.empty:
        return log_result("Parsed Data Present", False, "No parsed events found")

    log_result("Parsed Data Present", True)

    # Get unique event IDs from parsed data
    event_ids = set()
    for _, row in parsed_rows.iterrows():
        parsed = row.get("parsed")
        if isinstance(parsed, dict) and "event_id" in parsed:
            event_ids.add(parsed["event_id"])
        elif isinstance(parsed, str):
            try:
                parsed_dict = json.loads(parsed)
                if "event_id" in parsed_dict:
                    event_ids.add(parsed_dict["event_id"])
            except json.JSONDecodeError:
                pass

    print(f"  Found {len(event_ids)} unique event ID(s): {sorted(event_ids)[:10]}")

    # Validate fields for each event type we have parsers for
    all_passed = True
    for event_id in event_ids:
        if event_id not in parsers:
            log_result(
                f"Event {event_id} Parser", False, "No parser definition found"
            )
            all_passed = False
            continue

        parser = parsers[event_id]
        expected_fields = {f["name"] for f in parser.get("fields", [])}

        # Check parsed data has expected fields
        for _, row in parsed_rows.iterrows():
            parsed = row.get("parsed")
            if isinstance(parsed, str):
                try:
                    parsed = json.loads(parsed)
                except json.JSONDecodeError:
                    continue

            if not isinstance(parsed, dict):
                continue

            actual_parsed_id = parsed.get("event_id")
            if actual_parsed_id == event_id:
                actual_fields = set(parsed.keys())
                # Remove standard fields
                actual_fields -= {"event_id", "provider", "level", "time_created"}

                # Check for missing required fields
                missing = expected_fields - actual_fields
                if missing:
                    log_result(
                        f"Event {event_id} Required Fields",
                        False,
                        f"Missing: {missing}",
                    )
                    all_passed = False
                else:
                    log_result(
                        f"Event {event_id} Required Fields",
                        True,
                        f"All {len(expected_fields)} fields present",
                    )
                break

    return all_passed


def validate_enrichment_fields(table: pq.Table, parsers: Dict[int, Dict]) -> bool:
    """Validate that enrichment fields are populated."""
    print("\nValidating Enrichment Fields...")

    df = table.to_pandas()
    parsed_rows = df[df["parsed"].notna()]

    all_passed = True
    enrichment_found = False

    for event_id, parser in parsers.items():
        enrichments = parser.get("enrichments", [])
        if not enrichments:
            continue

        for _, row in parsed_rows.iterrows():
            parsed = row.get("parsed")
            if isinstance(parsed, str):
                try:
                    parsed = json.loads(parsed)
                except json.JSONDecodeError:
                    continue

            if not isinstance(parsed, dict):
                continue

            if parsed.get("event_id") == event_id:
                for enrichment in enrichments:
                    field = enrichment.get("field", "")
                    enriched_field = f"{field}_Name"

                    if enriched_field in parsed:
                        enrichment_found = True
                        log_result(
                            f"Event {event_id} Enrichment",
                            True,
                            f"{enriched_field} = {parsed[enriched_field]}",
                        )
                    else:
                        log_result(
                            f"Event {event_id} Enrichment",
                            False,
                            f"Missing {enriched_field}",
                        )
                        all_passed = False
                break

    if not enrichment_found and any(p.get("enrichments") for p in parsers.values()):
        log_result(
            "Enrichments Present",
            False,
            "No enrichment fields found in data (expected for events with enrichments)",
        )
        return False

    return all_passed


def validate_output_format(table: pq.Table, parsers: Dict[int, Dict]) -> bool:
    """Validate that output_format template fields can be rendered."""
    print("\nValidating Output Format Rendering...")

    df = table.to_pandas()
    parsed_rows = df[df["parsed"].notna()]

    all_passed = True

    for event_id, parser in parsers.items():
        output_format = parser.get("output_format", "")
        if not output_format:
            continue

        for _, row in parsed_rows.iterrows():
            parsed = row.get("parsed")
            if isinstance(parsed, str):
                try:
                    parsed = json.loads(parsed)
                except json.JSONDecodeError:
                    continue

            if not isinstance(parsed, dict):
                continue

            if parsed.get("event_id") == event_id:
                # Try to identify all template variables in output_format
                import re

                template_vars = set(re.findall(r"\{(\w+)\}", output_format))

                # Check if all template variables are present in parsed data
                missing_vars = template_vars - set(parsed.keys())

                if missing_vars:
                    log_result(
                        f"Event {event_id} Output Format",
                        False,
                        f"Missing template variables: {missing_vars}",
                    )
                    all_passed = False
                else:
                    # Try to render the format
                    try:
                        rendered = output_format.format(**parsed)
                        log_result(
                            f"Event {event_id} Output Format",
                            True,
                            f"Rendered successfully ({len(rendered)} chars)",
                        )
                    except (KeyError, ValueError) as e:
                        log_result(
                            f"Event {event_id} Output Format",
                            False,
                            f"Render failed: {e}",
                        )
                        all_passed = False
                break

    return all_passed


def validate_event_counts(table: pq.Table) -> bool:
    """Validate that event counts match throughput stats."""
    print("\nValidating Event Counts...")

    try:
        resp = requests.get(STATS_ENDPOINT, timeout=5)
        resp.raise_for_status()
        stats = resp.json()
        stats_total = sum(row.get("total_events", 0) for row in stats)

        df = table.to_pandas()
        parquet_total = len(df)

        if parquet_total >= stats_total:
            log_result(
                "Event Count Match",
                True,
                f"Parquet: {parquet_total}, Stats: {stats_total}",
            )
            return True
        else:
            log_result(
                "Event Count Match",
                False,
                f"Parquet ({parquet_total}) < Stats ({stats_total})",
            )
            return False
    except Exception as e:
        log_result("Event Count Match", False, str(e))
        return False


def main():
    """Main entry point for parsing validator."""
    print("=" * 60)
    print("WEF Server Parsing Validator")
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

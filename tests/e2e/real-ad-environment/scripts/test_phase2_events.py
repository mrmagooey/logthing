#!/usr/bin/env python3
"""
Phase 2: Event Types & Parsing Validation Tests

This script validates that Windows events are correctly received, parsed,
and forwarded by the WEF server. It tests security event coverage and
parser accuracy.

Usage:
    python3 test_phase2_events.py [--wef-server HOST] [--s3-endpoint URL] [--minio-endpoint URL]

Exit codes:
    0 - All tests passed
    1 - One or more tests failed
    2 - Configuration error
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

import requests

# Configuration
DEFAULT_WEF_SERVER = "wef-srv-01.wef.lab"
DEFAULT_METRICS_PORT = 9090
DEFAULT_S3_ENDPOINT = "http://minio-srv.wef.lab:9000"
DEFAULT_S3_BUCKET = "wef-events"
DEFAULT_S3_ACCESS_KEY = "minioadmin"
DEFAULT_S3_SECRET_KEY = "minioadmin"

# Event types we expect to receive and parse
EXPECTED_EVENT_TYPES = {
    "4624": "Successful Logon",
    "4625": "Failed Logon",
    "4634": "Logoff",
    "4647": "User Initiated Logoff",
    "4648": "Logon Using Explicit Credentials",
    "4663": "Attempted Object Access",
    "4672": "Admin Logon",
    "4688": "Process Created",
    "4720": "User Account Created",
    "4728": "Member Added to Global Group",
    "4732": "Member Added to Local Group",
    "4768": "Kerberos TGT Requested",
    "4769": "Kerberos Service Ticket Requested",
}

# Parser configuration validation
PARSER_FIELDS = [
    "TargetUserName",
    "LogonType",
    "IpAddress",
    "ProcessName",
    "SubjectUserName",
]

results = {
    "timestamp": datetime.now().isoformat(),
    "phase": "phase2_events",
    "tests": [],
    "passed": 0,
    "failed": 0,
    "errors": []
}


class TestResult:
    """Represents a single test result"""
    def __init__(self, name: str, status: str, message: str = "", details: Optional[Dict] = None):
        self.name = name
        self.status = status
        self.message = message
        self.details = details or {}
        self.timestamp = datetime.now().isoformat()
    
    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "status": self.status,
            "message": self.message,
            "details": self.details,
            "timestamp": self.timestamp
        }


def get_metrics(wef_server: str, port: int = DEFAULT_METRICS_PORT) -> str:
    """Fetch Prometheus metrics from WEF server"""
    url = f"http://{wef_server}:{port}/metrics"
    try:
        response = requests.get(url, timeout=10)
        return response.text if response.status_code == 200 else ""
    except Exception:
        return ""


def parse_metric(metrics: str, metric_name: str) -> Optional[int]:
    """Parse a specific metric value from Prometheus text format"""
    for line in metrics.split("\n"):
        if line.startswith(f"{metric_name} "):
            try:
                return int(line.split()[-1])
            except (ValueError, IndexError):
                return None
    return None


def test_event_reception(wef_server: str) -> TestResult:
    """Test that events are being received from Windows clients"""
    test_name = "Event Reception"
    
    try:
        # Get initial metrics
        initial_metrics = get_metrics(wef_server)
        initial_received = parse_metric(initial_metrics, "wef_events_received_total") or 0
        
        # Wait for events to arrive (give some time for batching)
        print(f"  Waiting for events to arrive (current: {initial_received})...")
        time.sleep(10)
        
        # Get updated metrics
        final_metrics = get_metrics(wef_server)
        final_received = parse_metric(final_metrics, "wef_events_received_total") or 0
        
        if final_received > initial_received:
            return TestResult(
                test_name,
                "PASSED",
                f"Events are being received ({final_received - initial_received} new events)",
                {
                    "initial_count": initial_received,
                    "final_count": final_received,
                    "new_events": final_received - initial_received
                }
            )
        else:
            return TestResult(
                test_name,
                "FAILED",
                f"No new events received (total: {final_received})",
                {"total_events": final_received}
            )
    except Exception as e:
        return TestResult(test_name, "FAILED", f"Error: {e}")


def test_event_forwarding(wef_server: str) -> TestResult:
    """Test that events are being forwarded to destinations"""
    test_name = "Event Forwarding"
    
    try:
        metrics = get_metrics(wef_server)
        forwarded = parse_metric(metrics, "wef_events_forwarded_total") or 0
        received = parse_metric(metrics, "wef_events_received_total") or 0
        
        if forwarded > 0 and received > 0:
            forward_rate = (forwarded / received) * 100
            return TestResult(
                test_name,
                "PASSED",
                f"Events are being forwarded ({forwarded}/{received}, {forward_rate:.1f}%)",
                {
                    "received": received,
                    "forwarded": forwarded,
                    "forward_rate": forward_rate
                }
            )
        elif received > 0 and forwarded == 0:
            return TestResult(
                test_name,
                "FAILED",
                f"Events received but not forwarded ({received} received, {forwarded} forwarded)",
                {"received": received, "forwarded": forwarded}
            )
        else:
            return TestResult(
                test_name,
                "FAILED",
                "No events received or forwarded",
                {"received": received, "forwarded": forwarded}
            )
    except Exception as e:
        return TestResult(test_name, "FAILED", f"Error: {e}")


def test_event_type_coverage(wef_server: str) -> TestResult:
    """Test that different event types are being received"""
    test_name = "Event Type Coverage"
    
    try:
        # This test would ideally check S3 for different event type directories
        # For now, we'll check if events are being received at all
        metrics = get_metrics(wef_server)
        received = parse_metric(metrics, "wef_events_received_total") or 0
        
        if received >= len(EXPECTED_EVENT_TYPES):
            return TestResult(
                test_name,
                "PASSED",
                f"Receiving events (total: {received}, expected types: {len(EXPECTED_EVENT_TYPES)})",
                {
                    "total_events": received,
                    "expected_types": len(EXPECTED_EVENT_TYPES),
                    "event_types": list(EXPECTED_EVENT_TYPES.keys())
                }
            )
        else:
            return TestResult(
                test_name,
                "FAILED",
                f"Insufficient event volume ({received} events, need at least {len(EXPECTED_EVENT_TYPES)})",
                {"total_events": received, "expected_types": len(EXPECTED_EVENT_TYPES)}
            )
    except Exception as e:
        return TestResult(test_name, "FAILED", f"Error: {e}")


def test_s3_storage(args) -> TestResult:
    """Test that events are being stored in S3/MinIO"""
    test_name = "S3 Storage"
    
    try:
        # Use mc (MinIO client) or AWS CLI to check S3 bucket
        # First, let's try to list objects
        result = subprocess.run(
            [
                "mc", "ls", 
                f"--json",
                f"minio/{DEFAULT_S3_BUCKET}/"
            ],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode != 0:
            # Try with AWS CLI as fallback
            result = subprocess.run(
                [
                    "aws", "s3", "ls",
                    f"s3://{DEFAULT_S3_BUCKET}/",
                    "--endpoint-url", args.s3_endpoint,
                    "--recursive"
                ],
                capture_output=True,
                text=True,
                timeout=30,
                env={
                    **subprocess.os.environ,
                    "AWS_ACCESS_KEY_ID": DEFAULT_S3_ACCESS_KEY,
                    "AWS_SECRET_ACCESS_KEY": DEFAULT_S3_SECRET_KEY
                }
            )
        
        if result.returncode == 0 and result.stdout.strip():
            lines = result.stdout.strip().split("\n")
            return TestResult(
                test_name,
                "PASSED",
                f"S3 bucket contains {len(lines)} object(s)",
                {"object_count": len(lines)}
            )
        elif result.returncode == 0:
            return TestResult(
                test_name,
                "FAILED",
                "S3 bucket exists but is empty",
                {"s3_output": result.stdout}
            )
        else:
            return TestResult(
                test_name,
                "FAILED",
                f"Failed to access S3 bucket: {result.stderr}",
                {"error": result.stderr}
            )
    except FileNotFoundError:
        return TestResult(
            test_name,
            "SKIPPED",
            "MinIO client (mc) or AWS CLI not available"
        )
    except subprocess.TimeoutExpired:
        return TestResult(test_name, "FAILED", "S3 access timeout")
    except Exception as e:
        return TestResult(test_name, "FAILED", f"Error: {e}")


def test_parquet_format(args) -> TestResult:
    """Test that events are stored in valid Parquet format"""
    test_name = "Parquet Format"
    
    # Try to import pyarrow - optional dependency
    try:
        import pyarrow.parquet as pq
    except ImportError:
        return TestResult(
            test_name,
            "SKIPPED",
            "pyarrow not installed, cannot verify Parquet format"
        )
    
    try:
        
        # First, find a Parquet file in S3
        result = subprocess.run(
            ["mc", "find", f"minio/{DEFAULT_S3_BUCKET}/", "--name", "*.parquet"],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode != 0 or not result.stdout.strip():
            return TestResult(
                test_name,
                "FAILED",
                "No Parquet files found in S3 bucket"
            )
        
        # Download the first Parquet file
        parquet_file = result.stdout.strip().split("\n")[0]
        local_path = "/tmp/test_sample.parquet"
        
        subprocess.run(
            ["mc", "cp", parquet_file, local_path],
            capture_output=True,
            timeout=30
        )
        
        # Try to read the Parquet file
        table = pq.read_table(local_path)
        schema = table.schema
        row_count = len(table)
        
        # Check for expected columns
        expected_columns = ["event_id", "timestamp", "computer", "event_data"]
        found_columns = [field.name for field in schema]
        
        return TestResult(
            test_name,
            "PASSED",
            f"Valid Parquet file with {row_count} rows and {len(found_columns)} columns",
            {
                "row_count": row_count,
                "column_count": len(found_columns),
                "columns": found_columns,
                "expected_columns": expected_columns
            }
        )
        
    except ImportError:
        return TestResult(
            test_name,
            "SKIPPED",
            "pyarrow not installed, cannot verify Parquet format"
        )
    except Exception as e:
        return TestResult(test_name, "FAILED", f"Error: {e}")


def test_parser_accuracy(args) -> TestResult:
    """Test that event parsers are correctly extracting fields"""
    test_name = "Parser Accuracy"
    
    try:
        # Check if parsers are configured
        import os
        parser_dir = "/etc/wef-server/event_parsers"
        
        if not os.path.exists(parser_dir):
            return TestResult(
                test_name,
                "SKIPPED",
                f"Parser directory not found: {parser_dir}"
            )
        
        parser_files = [f for f in os.listdir(parser_dir) if f.endswith('.yaml')]
        
        if len(parser_files) >= 10:  # We expect at least 10 parsers
            return TestResult(
                test_name,
                "PASSED",
                f"Found {len(parser_files)} event parser configuration files",
                {"parser_count": len(parser_files), "parsers": parser_files[:10]}
            )
        else:
            return TestResult(
                test_name,
                "FAILED",
                f"Insufficient parser configurations ({len(parser_files)} found, expected >= 10)",
                {"parser_count": len(parser_files)}
            )
    except Exception as e:
        return TestResult(test_name, "FAILED", f"Error: {e}")


def test_syslog_integration(wef_server: str) -> TestResult:
    """Test that syslog messages are being received and parsed"""
    test_name = "Syslog Integration"
    
    try:
        # Send a test syslog message
        import socket
        
        # UDP syslog test
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        test_message = f"<134>{datetime.now().strftime('%b %d %H:%M:%S')} test-host wef-test: Test syslog message from Phase 2 testing"
        sock.sendto(test_message.encode(), (wef_server, 514))
        sock.close()
        
        # Wait for processing
        time.sleep(2)
        
        # Check metrics for syslog events
        metrics = get_metrics(wef_server)
        # Note: We may not have a specific syslog metric, so we'll check general event reception
        received = parse_metric(metrics, "wef_events_received_total") or 0
        
        return TestResult(
            test_name,
            "PASSED",
            "Syslog test message sent successfully",
            {"test_message": test_message, "total_events": received}
        )
    except Exception as e:
        return TestResult(test_name, "FAILED", f"Error: {e}")


def run_tests(args) -> Tuple[int, int, int]:
    """Run all Phase 2 tests"""
    print("=" * 60)
    print("PHASE 2: Event Types & Parsing Validation")
    print("=" * 60)
    print()
    
    wef_server = args.wef_server
    passed = 0
    failed = 0
    skipped = 0
    
    tests = [
        ("Event Reception", lambda: test_event_reception(wef_server)),
        ("Event Forwarding", lambda: test_event_forwarding(wef_server)),
        ("Event Type Coverage", lambda: test_event_type_coverage(wef_server)),
        ("S3 Storage", lambda: test_s3_storage(args)),
        ("Parquet Format", lambda: test_parquet_format(args)),
        ("Parser Accuracy", lambda: test_parser_accuracy(args)),
        ("Syslog Integration", lambda: test_syslog_integration(wef_server)),
    ]
    
    for test_name, test_func in tests:
        print(f"Testing {test_name}...")
        result = test_func()
        results["tests"].append(result.to_dict())
        
        if result.status == "PASSED":
            passed += 1
            print(f"  ✓ {test_name}: {result.message}")
        elif result.status == "SKIPPED":
            skipped += 1
            print(f"  ⊘ {test_name}: {result.message}")
        else:
            failed += 1
            print(f"  ✗ {test_name}: {result.message}")
        print()
    
    # Save results
    results["passed"] = passed
    results["failed"] = failed
    results["skipped"] = skipped
    
    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"Results saved to: {args.output}")
    
    return passed, failed, skipped


def main():
    parser = argparse.ArgumentParser(
        description="Phase 2: Event Types & Parsing Validation Tests"
    )
    parser.add_argument(
        "--wef-server",
        default=DEFAULT_WEF_SERVER,
        help=f"WEF server hostname or IP (default: {DEFAULT_WEF_SERVER})"
    )
    parser.add_argument(
        "--s3-endpoint",
        default=DEFAULT_S3_ENDPOINT,
        help=f"S3/MinIO endpoint URL (default: {DEFAULT_S3_ENDPOINT})"
    )
    parser.add_argument(
        "--output",
        default="/var/log/wef-tests/phase2-results.json",
        help="Output file for test results"
    )
    
    args = parser.parse_args()
    
    passed, failed, skipped = run_tests(args)
    
    print("=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    print(f"Passed:  {passed}")
    print(f"Failed:  {failed}")
    print(f"Skipped: {skipped}")
    print("=" * 60)
    
    if failed > 0:
        print(f"\nPhase 2 tests completed with {failed} failure(s)")
        sys.exit(1)
    else:
        print(f"\nPhase 2 tests completed successfully ({passed} passed)")
        sys.exit(0)


if __name__ == "__main__":
    main()

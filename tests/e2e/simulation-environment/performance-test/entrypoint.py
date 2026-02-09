#!/usr/bin/env python3
"""
Performance Test: Ingest events at target rate and measure performance.

This test sends events to the WEF server at configurable throughput and measures
the ingestion performance. Supports both event-count and duration-based testing.
"""

import os
import time
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests

# Configuration
WEF_ENDPOINT = os.environ.get("WEF_ENDPOINT", "http://wef-server:5985")
STATS_ENDPOINT = os.environ.get("WEF_STATS_ENDPOINT", f"{WEF_ENDPOINT}/stats/throughput")
HEALTH_ENDPOINT = f"{WEF_ENDPOINT}/health"
EVENTS_URL = f"{WEF_ENDPOINT}/wsman/events"

# S3 Configuration for verification
S3_ENDPOINT = os.environ.get("S3_ENDPOINT", "http://minio:9000")
S3_BUCKET = os.environ.get("S3_BUCKET", "wef-events")
S3_ACCESS_KEY = os.environ.get("AWS_ACCESS_KEY_ID", "miniouser")
S3_SECRET_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY", "miniopassword")

# Test parameters
TOTAL_EVENTS = int(os.environ.get("PERF_TEST_TOTAL_EVENTS", "0"))  # 0 = use duration
DURATION_SECS = int(os.environ.get("PERF_TEST_DURATION_SECS", "0"))  # 0 = use total events
BATCH_SIZE = int(os.environ.get("PERF_TEST_BATCH_SIZE", "1000"))
TIMEOUT = int(os.environ.get("PERF_TEST_TIMEOUT_SECS", "600"))
TARGET_EPS = int(os.environ.get("PERF_TEST_TARGET_EPS", "0"))  # 0 = no throttling
EVENT_TYPE = os.environ.get("PERF_TEST_EVENT_TYPE", "")  # Empty = random event types
VERIFY_S3 = os.environ.get("PERF_TEST_VERIFY_S3", "false").lower() == "true"


def wait_for_health():
    """Wait for WEF server to be healthy."""
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            resp = requests.get(HEALTH_ENDPOINT, timeout=5)
            if resp.status_code == 200:
                print("WEF server is healthy")
                return True
        except requests.RequestException:
            pass
        time.sleep(2)
    raise SystemExit("WEF server did not become healthy in time")


def build_event_xml(event_id: int, timestamp: str, fixed_event_type: int | None = None) -> str:
    """Build a single event XML."""
    evt_id = fixed_event_type if fixed_event_type else event_id
    return f"""    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <Provider Name="Microsoft-Windows-Security-Auditing">Microsoft-Windows-Security-Auditing</Provider>
        <EventID>{evt_id}</EventID>
        <Level>0</Level>
        <Task>12544</Task>
        <Keywords>0x8020000000000000</Keywords>
        <TimeCreated SystemTime="{timestamp}">{timestamp}</TimeCreated>
        <EventRecordID>{event_id}</EventRecordID>
        <Channel>Security</Channel>
        <Computer>PERF-TEST-HOST</Computer>
      </System>
      <EventData>
        <Data Name="TargetUserName">perf_user_{event_id}</Data>
        <Data Name="TargetDomainName">CONTOSO</Data>
        <Data Name="IpAddress">192.0.2.{event_id % 255}</Data>
        <Data Name="IpPort">{40000 + (event_id % 10000)}</Data>
      </EventData>
    </Event>"""


def build_batch_payload(events_xml: list) -> str:
    """Wrap multiple events in an envelope."""
    inner = "\n".join(events_xml)
    return f"""<?xml version="1.0" encoding="utf-8"?>
<Envelope>
  <Body>
    <Events>
{inner}
    </Events>
  </Body>
</Envelope>
"""


def send_batch(batch_num: int, batch_size: int, fixed_event_type: int | None = None) -> bool:
    """Send a batch of events."""
    timestamp = datetime.now(timezone.utc).isoformat()
    start_event_id = batch_num * batch_size

    events_xml = []
    for i in range(batch_size):
        event_id = (start_event_id + i) % 65535 + 1  # Keep within valid event ID range
        events_xml.append(build_event_xml(event_id, timestamp, fixed_event_type))

    payload = build_batch_payload(events_xml)

    headers = {"Content-Type": "application/soap+xml"}

    try:
        resp = requests.post(
            EVENTS_URL,
            data=payload.encode("utf-8"),
            headers=headers,
            timeout=30
        )
        resp.raise_for_status()
        return True
    except requests.RequestException as e:
        print(f"  Batch {batch_num + 1} failed: {e}")
        return False


def get_stats() -> list:
    """Get current throughput stats from the server."""
    try:
        resp = requests.get(STATS_ENDPOINT, timeout=5)
        resp.raise_for_status()
        return resp.json()
    except (requests.RequestException, json.JSONDecodeError):
        return []


def get_total_events_from_stats(stats: list) -> int:
    """Extract total event count from stats."""
    return sum(row.get("total_events", 0) for row in stats)


def verify_s3_files(expected_event_type: int, min_expected_files: int = 1) -> dict:
    """Verify that parquet files were created in S3."""
    import sys
    sys.stdout.flush()
    print(f"  [DEBUG] verify_s3_files called with event_type={expected_event_type}", flush=True)
    
    try:
        import boto3
        from botocore.client import Config
        
        print(f"  [DEBUG] Connecting to S3 at {S3_ENDPOINT}", flush=True)
        print(f"  [DEBUG] Bucket: {S3_BUCKET}", flush=True)
        print(f"  [DEBUG] Looking for event type: {expected_event_type}", flush=True)
        
        s3_client = boto3.client(
            's3',
            endpoint_url=S3_ENDPOINT,
            aws_access_key_id=S3_ACCESS_KEY,
            aws_secret_access_key=S3_SECRET_KEY,
            config=Config(signature_version='s3v4'),
            region_name='us-east-1'
        )
        
        # Test connection by listing buckets
        try:
            buckets = s3_client.list_buckets()
            print(f"  [DEBUG] Successfully connected to S3. Buckets: {[b['Name'] for b in buckets.get('Buckets', [])]}", flush=True)
        except Exception as e:
            print(f"  [DEBUG] Failed to list buckets: {e}", flush=True)
        
        # List all objects in the bucket
        print(f"  [DEBUG] Listing objects in bucket '{S3_BUCKET}'...", flush=True)
        response = s3_client.list_objects_v2(
            Bucket=S3_BUCKET,
            MaxKeys=1000  # Get more files
        )
        
        print(f"  [DEBUG] Response keys: {response.keys()}", flush=True)
        
        all_files = []
        if 'Contents' in response:
            all_files = response['Contents']
            print(f"  [DEBUG] Found {len(all_files)} total files in bucket", flush=True)
            if all_files:
                print(f"  [DEBUG] Sample files: {[f['Key'] for f in all_files[:5]]}", flush=True)
        else:
            print(f"  [DEBUG] No 'Contents' in response. IsTruncated: {response.get('IsTruncated')}", flush=True)
            print(f"  [DEBUG] Full response (truncated): {str(response)[:500]}", flush=True)
        
        # The actual path pattern is: event_type=XXXX/year=YYYY/month=MM/day=DD/events_XXXX_YYYYMMDD_HHMMSS.parquet
        event_type_pattern = f"event_type={expected_event_type}/"
        print(f"  [DEBUG] Looking for pattern: '{event_type_pattern}'", flush=True)
        
        event_type_files = [f for f in all_files if event_type_pattern in f['Key'] or f['Key'].startswith(f"{event_type_pattern}")]
        print(f"  [DEBUG] Found {len(event_type_files)} files matching pattern", flush=True)
        
        # Also check for parquet files
        if not event_type_files:
            parquet_files = [f for f in all_files if f['Key'].endswith('.parquet')]
            print(f"  [DEBUG] Found {len(parquet_files)} total parquet files", flush=True)
            event_type_files = [f for f in parquet_files if str(expected_event_type) in f['Key']]
            print(f"  [DEBUG] Found {len(event_type_files)} parquet files with event type {expected_event_type}", flush=True)
        
        if not event_type_files:
            return {
                'success': False,
                'error': f'No files found in S3 for event type {expected_event_type}. Total files in bucket: {len(all_files)}',
                'files_found': 0,
                'total_size_mb': 0,
                'all_files': [f['Key'] for f in all_files[:20]]  # First 20 files for debugging
            }
        
        total_size = sum(f['Size'] for f in event_type_files)
        total_size_mb = total_size / (1024 * 1024)
        
        return {
            'success': len(event_type_files) >= min_expected_files,
            'files_found': len(event_type_files),
            'total_size_mb': round(total_size_mb, 2),
            'files': [f['Key'] for f in event_type_files[:5]]  # First 5 files
        }
    except Exception as e:
        import traceback
        return {
            'success': False,
            'error': f"{str(e)}\n{traceback.format_exc()}",
            'files_found': 0,
            'total_size_mb': 0
        }


def run_performance_test():
    """Run the performance test."""
    # Determine test mode
    use_duration = DURATION_SECS > 0
    use_event_count = TOTAL_EVENTS > 0 and not use_duration
    
    if not use_duration and not use_event_count:
        print("Error: Must specify either PERF_TEST_DURATION_SECS or PERF_TEST_TOTAL_EVENTS")
        return 1
    
    fixed_event_type = int(EVENT_TYPE) if EVENT_TYPE else None
    
    print("=" * 70)
    print("PERFORMANCE TEST: Target Rate Event Ingestion")
    print("=" * 70)
    
    if use_duration:
        print(f"Test duration: {DURATION_SECS} seconds")
        print(f"Expected events: ~{DURATION_SECS * TARGET_EPS:,}")
    else:
        print(f"Total events to send: {TOTAL_EVENTS:,}")
        print(f"Number of batches: {TOTAL_EVENTS // BATCH_SIZE}")
    
    print(f"Batch size: {BATCH_SIZE}")
    
    if TARGET_EPS > 0:
        print(f"Target rate: {TARGET_EPS:,} events/second")
    else:
        print("Target rate: Unlimited (no throttling)")
        print("WARNING: Running at maximum throughput - server may be overwhelmed")
    
    if fixed_event_type:
        print(f"Event type: {fixed_event_type} (single type)")
    else:
        print("Event type: Random (multiple types)")
    
    if VERIFY_S3:
        print("S3 verification: Enabled")
    
    print()

    wait_for_health()

    # Get baseline stats
    baseline_stats = get_stats()
    baseline_total = get_total_events_from_stats(baseline_stats)
    print(f"Baseline event count: {baseline_total:,}")
    print()

    # Record start time
    start_time = time.time()
    deadline = start_time + (DURATION_SECS if use_duration else TIMEOUT)
    
    # Send batches with optional rate limiting
    successful_batches = 0
    failed_batches = 0
    batch_num = 0
    expected_interval = BATCH_SIZE / TARGET_EPS if TARGET_EPS > 0 else 0

    print("Sending events...")
    while True:
        # Check if we should stop
        if use_duration:
            if time.time() > deadline:
                print(f"\nDuration completed: {DURATION_SECS} seconds")
                break
        else:
            if batch_num >= (TOTAL_EVENTS // BATCH_SIZE):
                break
            if time.time() > deadline:
                print(f"\nTimeout reached after {TIMEOUT} seconds")
                break

        batch_loop_start = time.time()

        if send_batch(batch_num, BATCH_SIZE, fixed_event_type):
            successful_batches += 1
        else:
            failed_batches += 1

        # Rate limiting: sleep if we're sending too fast
        if expected_interval > 0:
            batch_elapsed = time.time() - batch_loop_start
            if batch_elapsed < expected_interval:
                time.sleep(expected_interval - batch_elapsed)

        # Progress report every 100 batches or 10 seconds
        if (batch_num + 1) % 100 == 0:
            events_sent = (batch_num + 1) * BATCH_SIZE
            elapsed = time.time() - start_time
            current_eps = events_sent / elapsed if elapsed > 0 else 0
            
            if use_duration:
                remaining = max(0, deadline - time.time())
                print(f"  Progress: {events_sent:,} events sent - "
                      f"Current rate: {current_eps:.1f} events/sec - "
                      f"Remaining: {remaining:.0f}s")
            else:
                progress = (events_sent / TOTAL_EVENTS) * 100
                print(f"  Progress: {events_sent:,}/{TOTAL_EVENTS:,} events ({progress:.1f}%) - "
                      f"Current rate: {current_eps:.1f} events/sec")
        
        batch_num += 1

    # Record end time
    end_time = time.time()
    total_elapsed = end_time - start_time

    # Wait a bit for events to be processed and flushed to S3
    print("\nWaiting for event processing to complete...")
    time.sleep(5)
    
    # Additional wait for S3 flush if verification is enabled
    if VERIFY_S3:
        print("Waiting for S3 parquet file flush (parquet files may take time to write)...")
        time.sleep(15)

    # Get final stats
    final_stats = get_stats()
    final_total = get_total_events_from_stats(final_stats)
    events_received = final_total - baseline_total

    # Calculate metrics
    events_sent = successful_batches * BATCH_SIZE
    overall_eps = events_sent / total_elapsed if total_elapsed > 0 else 0
    processing_eps = events_received / total_elapsed if total_elapsed > 0 else 0

    # Results
    print()
    print("=" * 70)
    print("PERFORMANCE TEST RESULTS")
    print("=" * 70)
    print(f"Total time: {total_elapsed:.2f} seconds")
    print(f"Events sent: {events_sent:,}")
    print(f"Events received (by server): {events_received:,}")
    print(f"Successful batches: {successful_batches}")
    print(f"Failed batches: {failed_batches}")
    print()
    print(f"Overall ingestion rate: {overall_eps:.2f} events/second")
    print(f"Server processing rate: {processing_eps:.2f} events/second")
    
    # S3 Verification
    s3_results = None
    if VERIFY_S3 and fixed_event_type:
        print()
        print("=" * 70)
        print("S3 VERIFICATION")
        print("=" * 70)
        s3_results = verify_s3_files(fixed_event_type)
        
        if s3_results['success']:
            print(f"✓ S3 files verified successfully")
            print(f"  Files found: {s3_results['files_found']}")
            print(f"  Total size: {s3_results['total_size_mb']:.2f} MB")
            print(f"  Sample files: {', '.join(s3_results['files'][:3])}")
        else:
            print(f"✗ S3 verification failed")
            print(f"  Error: {s3_results.get('error', 'Unknown error')}")
            print(f"  Files found: {s3_results['files_found']}")
    
    print("=" * 70)

    # Save results to file
    results = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "test_name": "sustained_rate_test" if use_duration else "event_count_test",
        "configuration": {
            "duration_seconds": DURATION_SECS if use_duration else None,
            "total_events_target": TOTAL_EVENTS if use_event_count else None,
            "batch_size": BATCH_SIZE,
            "target_events_per_second": TARGET_EPS,
            "fixed_event_type": fixed_event_type,
            "verify_s3": VERIFY_S3
        },
        "results": {
            "total_time_seconds": round(total_elapsed, 2),
            "events_sent": events_sent,
            "events_received": events_received,
            "successful_batches": successful_batches,
            "failed_batches": failed_batches,
            "events_per_second_overall": round(overall_eps, 2),
            "events_per_second_processed": round(processing_eps, 2)
        },
        "s3_verification": s3_results,
        "server_stats": {
            "baseline_total": baseline_total,
            "final_total": final_total
        }
    }

    results_file = "/tmp/performance_test_results.json"
    with open(results_file, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to: {results_file}")

    # Determine success
    success = True
    
    if use_event_count:
        if events_sent < TOTAL_EVENTS * 0.95:
            success = False
            print(f"\n✗ Performance test failed")
            print(f"  Target: {TOTAL_EVENTS:,} events")
            print(f"  Achieved: {events_sent:,} events ({(events_sent/TOTAL_EVENTS)*100:.1f}%)")
        else:
            print(f"\n✓ Performance test completed successfully")
            print(f"  Target: {TOTAL_EVENTS:,} events")
            print(f"  Achieved: {events_sent:,} events ({(events_sent/TOTAL_EVENTS)*100:.1f}%)")
    else:
        # Duration-based test
        if TARGET_EPS == 0:
            # Unlimited mode - just report achieved rate
            print(f"\n✓ Max throughput test completed")
            print(f"  Duration: {DURATION_SECS} seconds")
            print(f"  Events sent: {events_sent:,}")
            print(f"  Achieved rate: {processing_eps:.0f} events/second")
            # Consider it success if we processed events and no failures
            if failed_batches > 0 or events_received == 0:
                success = False
        else:
            expected_events = DURATION_SECS * TARGET_EPS
            achieved_ratio = events_sent / expected_events if expected_events > 0 else 1.0
            
            if achieved_ratio >= 0.95:
                print(f"\n✓ Performance test completed successfully")
                print(f"  Duration: {DURATION_SECS} seconds")
                print(f"  Events sent: {events_sent:,}")
                print(f"  Target rate maintained: {(achieved_ratio)*100:.1f}%")
            else:
                success = False
                print(f"\n✗ Performance test failed")
                print(f"  Duration: {DURATION_SECS} seconds")
                print(f"  Events sent: {events_sent:,}")
                print(f"  Target rate maintained: {(achieved_ratio)*100:.1f}%")
    
    if VERIFY_S3 and s3_results and not s3_results['success']:
        success = False
    
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(run_performance_test())

#!/usr/bin/env python3
"""
Phase 3: Load & Performance Testing

This script validates the WEF server's performance under high-volume event
generation from multiple Windows clients. Tests include high-throughput
event processing and concurrent connection handling.

Usage:
    python3 test_phase3_performance.py [--wef-server HOST] [--duration MINUTES] [--rate EVENTS_PER_MIN]

Exit codes:
    0 - All tests passed
    1 - One or more tests failed
    2 - Configuration error
"""

import argparse
import json
import subprocess
import sys
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import requests

# Configuration
DEFAULT_WEF_SERVER = "wef-srv-01.wef.lab"
DEFAULT_METRICS_PORT = 9090
DEFAULT_DURATION_MINUTES = 5
DEFAULT_EVENTS_PER_MINUTE = 100
DEFAULT_CONCURRENT_CLIENTS = 4

WINDOWS_CLIENTS = [
    "ws01.wef.lab",
    "ws02.wef.lab",
    "ws03.wef.lab",
    "srv01.wef.lab"
]

# Performance thresholds
THRESHOLDS = {
    "min_events_per_second": 10,
    "max_processing_latency_ms": 5000,
    "max_memory_usage_mb": 2048,
    "max_cpu_percent": 80,
}

results = {
    "timestamp": datetime.now().isoformat(),
    "phase": "phase3_performance",
    "config": {},
    "tests": [],
    "metrics": {},
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
                return int(float(line.split()[-1]))
            except (ValueError, IndexError):
                return None
    return None


def trigger_events_on_client(client: str, event_count: int, duration_seconds: int) -> Dict:
    """Trigger event generation on a Windows client via WinRM/SSH"""
    # This is a placeholder - in real implementation, use WinRM or SSH
    # to run PowerShell scripts on Windows clients
    try:
        # Example using SSH (if OpenSSH is installed on Windows)
        result = subprocess.run(
            [
                "ssh",
                f"administrator@{client}",
                f"powershell.exe -ExecutionPolicy Bypass -File C:\\WEF\\scripts\\Generate-TestEvents.ps1 -EventCount {event_count}"
            ],
            capture_output=True,
            text=True,
            timeout=duration_seconds + 30
        )
        
        return {
            "success": result.returncode == 0,
            "client": client,
            "events_generated": event_count,
            "output": result.stdout,
            "errors": result.stderr if result.stderr else None
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "client": client,
            "error": "Timeout"
        }
    except Exception as e:
        return {
            "success": False,
            "client": client,
            "error": str(e)
        }


def test_high_volume_events(args) -> TestResult:
    """Test high-volume event processing"""
    test_name = "High-Volume Event Processing"
    
    print(f"  Starting high-volume test: {args.rate} events/min for {args.duration} minutes")
    
    try:
        # Get baseline metrics
        initial_metrics = get_metrics(args.wef_server)
        initial_received = parse_metric(initial_metrics, "wef_events_received_total") or 0
        initial_time = time.time()
        
        # Calculate events per client
        total_events = args.rate * args.duration
        events_per_client = total_events // len(WINDOWS_CLIENTS)
        duration_seconds = args.duration * 60
        
        print(f"  Generating ~{events_per_client} events per client...")
        
        # Trigger events on all clients in parallel
        client_results = []
        threads = []
        
        def run_client_test(client):
            result = trigger_events_on_client(client, events_per_client, duration_seconds)
            client_results.append(result)
        
        for client in WINDOWS_CLIENTS:
            thread = threading.Thread(target=run_client_test, args=(client,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join(timeout=duration_seconds + 60)
        
        # Wait a bit for events to be processed
        print("  Waiting for event processing...")
        time.sleep(30)
        
        # Get final metrics
        final_metrics = get_metrics(args.wef_server)
        final_received = parse_metric(final_metrics, "wef_events_received_total") or 0
        final_time = time.time()
        
        # Calculate throughput
        total_received = final_received - initial_received
        elapsed_seconds = final_time - initial_time
        events_per_second = total_received / elapsed_seconds if elapsed_seconds > 0 else 0
        
        # Check results
        success_count = sum(1 for r in client_results if r.get("success"))
        
        return TestResult(
            test_name,
            "PASSED" if events_per_second >= THRESHOLDS["min_events_per_second"] else "FAILED",
            f"Processed {total_received} events in {elapsed_seconds:.1f}s ({events_per_second:.1f} events/sec)",
            {
                "total_events_received": total_received,
                "elapsed_seconds": elapsed_seconds,
                "events_per_second": events_per_second,
                "clients_succeeded": success_count,
                "clients_total": len(WINDOWS_CLIENTS),
                "client_results": client_results
            }
        )
        
    except Exception as e:
        return TestResult(test_name, "FAILED", f"Error: {e}")


def test_concurrent_connections(args) -> TestResult:
    """Test concurrent connection handling"""
    test_name = "Concurrent Connection Handling"
    
    try:
        # Check current active connections/subscriptions
        initial_metrics = get_metrics(args.wef_server)
        initial_subscriptions = parse_metric(initial_metrics, "wef_active_subscriptions") or 0
        
        print(f"  Current active subscriptions: {initial_subscriptions}")
        
        # Expected number of concurrent connections
        expected_connections = len(WINDOWS_CLIENTS)
        
        # Verify all clients are connected
        if initial_subscriptions >= expected_connections:
            return TestResult(
                test_name,
                "PASSED",
                f"Handling {initial_subscriptions} concurrent connection(s) (expected: {expected_connections})",
                {
                    "active_subscriptions": initial_subscriptions,
                    "expected_connections": expected_connections
                }
            )
        else:
            return TestResult(
                test_name,
                "FAILED",
                f"Only {initial_subscriptions} active connection(s), expected {expected_connections}",
                {
                    "active_subscriptions": initial_subscriptions,
                    "expected_connections": expected_connections
                }
            )
            
    except Exception as e:
        return TestResult(test_name, "FAILED", f"Error: {e}")


def test_processing_latency(args) -> TestResult:
    """Test event processing latency"""
    test_name = "Processing Latency"
    
    try:
        # Get metrics over time to estimate latency
        # This is a simplified check - real implementation would track event timestamps
        
        metrics = get_metrics(args.wef_server)
        forwarded = parse_metric(metrics, "wef_events_forwarded_total") or 0
        received = parse_metric(metrics, "wef_events_received_total") or 0
        
        if received > 0:
            # Simple check - if forwarded == received, processing is keeping up
            lag = received - forwarded
            
            if lag < 100:  # Less than 100 events in backlog
                return TestResult(
                    test_name,
                    "PASSED",
                    f"Processing latency acceptable ({lag} events in backlog)",
                    {
                        "events_received": received,
                        "events_forwarded": forwarded,
                        "backlog": lag
                    }
                )
            else:
                return TestResult(
                    test_name,
                    "FAILED",
                    f"Processing latency too high ({lag} events in backlog)",
                    {
                        "events_received": received,
                        "events_forwarded": forwarded,
                        "backlog": lag
                    }
                )
        else:
            return TestResult(test_name, "SKIPPED", "No events received yet")
            
    except Exception as e:
        return TestResult(test_name, "FAILED", f"Error: {e}")


def test_resource_usage(args) -> TestResult:
    """Test resource usage (CPU, memory)"""
    test_name = "Resource Usage"
    
    try:
        # Check system resources using /proc or ps
        # This is a simplified check
        result = subprocess.run(
            ["ps", "aux", "--sort=-%mem"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        # Find WEF server process
        wef_process = None
        for line in result.stdout.split("\n"):
            if "wef-server" in line:
                wef_process = line
                break
        
        if wef_process:
            parts = wef_process.split()
            cpu_percent = float(parts[2]) if len(parts) > 2 else 0
            mem_percent = float(parts[3]) if len(parts) > 3 else 0
            
            # Get total memory
            mem_result = subprocess.run(
                ["free", "-m"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            mem_usage_mb = 0
            for line in mem_result.stdout.split("\n"):
                if line.startswith("Mem:"):
                    total_mem = int(line.split()[1])
                    mem_usage_mb = (mem_percent / 100) * total_mem
                    break
            
            passed = (
                cpu_percent < THRESHOLDS["max_cpu_percent"] and
                mem_usage_mb < THRESHOLDS["max_memory_usage_mb"]
            )
            
            return TestResult(
                test_name,
                "PASSED" if passed else "FAILED",
                f"CPU: {cpu_percent:.1f}%, Memory: {mem_usage_mb:.1f}MB",
                {
                    "cpu_percent": cpu_percent,
                    "memory_percent": mem_percent,
                    "memory_mb": mem_usage_mb
                }
            )
        else:
            return TestResult(test_name, "SKIPPED", "WEF server process not found")
            
    except Exception as e:
        return TestResult(test_name, "FAILED", f"Error: {e}")


def test_batching_performance(args) -> TestResult:
    """Test that batching is working efficiently"""
    test_name = "Batching Performance"
    
    try:
        # Get metrics before and after a test batch
        initial_metrics = get_metrics(args.wef_server)
        initial_received = parse_metric(initial_metrics, "wef_events_received_total") or 0
        
        # Send a burst of events (simulate via syslog)
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        for i in range(100):
            message = f"<134>{datetime.now().strftime('%b %d %H:%M:%S')} test-host wef-test: Batch test message {i}"
            sock.sendto(message.encode(), (args.wef_server, 514))
        
        sock.close()
        
        # Wait for batch processing
        time.sleep(5)
        
        final_metrics = get_metrics(args.wef_server)
        final_received = parse_metric(final_metrics, "wef_events_received_total") or 0
        
        received_count = final_received - initial_received
        
        return TestResult(
            test_name,
            "PASSED" if received_count >= 90 else "FAILED",  # Allow some loss
            f"Received {received_count}/100 batch test messages",
            {"received": received_count, "sent": 100}
        )
        
    except Exception as e:
        return TestResult(test_name, "FAILED", f"Error: {e}")


def run_tests(args) -> Tuple[int, int, int]:
    """Run all Phase 3 tests"""
    print("=" * 60)
    print("PHASE 3: Load & Performance Testing")
    print("=" * 60)
    print()
    print(f"Configuration:")
    print(f"  Duration: {args.duration} minutes")
    print(f"  Rate: {args.rate} events/minute")
    print(f"  Concurrent clients: {len(WINDOWS_CLIENTS)}")
    print()
    
    passed = 0
    failed = 0
    skipped = 0
    
    # Store config in results
    results["config"] = {
        "duration_minutes": args.duration,
        "events_per_minute": args.rate,
        "concurrent_clients": len(WINDOWS_CLIENTS),
        "thresholds": THRESHOLDS
    }
    
    tests = [
        ("Concurrent Connection Handling", lambda: test_concurrent_connections(args)),
        ("Processing Latency", lambda: test_processing_latency(args)),
        ("Resource Usage", lambda: test_resource_usage(args)),
        ("Batching Performance", lambda: test_batching_performance(args)),
        ("High-Volume Event Processing", lambda: test_high_volume_events(args)),
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
    
    # Save final metrics
    final_metrics = get_metrics(args.wef_server)
    results["metrics"] = {
        "events_received": parse_metric(final_metrics, "wef_events_received_total"),
        "events_forwarded": parse_metric(final_metrics, "wef_events_forwarded_total"),
        "active_subscriptions": parse_metric(final_metrics, "wef_active_subscriptions"),
        "total_connections": parse_metric(final_metrics, "wef_connections_total")
    }
    
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
        description="Phase 3: Load & Performance Testing"
    )
    parser.add_argument(
        "--wef-server",
        default=DEFAULT_WEF_SERVER,
        help=f"WEF server hostname or IP (default: {DEFAULT_WEF_SERVER})"
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=DEFAULT_DURATION_MINUTES,
        help=f"Test duration in minutes (default: {DEFAULT_DURATION_MINUTES})"
    )
    parser.add_argument(
        "--rate",
        type=int,
        default=DEFAULT_EVENTS_PER_MINUTE,
        help=f"Events per minute to generate (default: {DEFAULT_EVENTS_PER_MINUTE})"
    )
    parser.add_argument(
        "--output",
        default="/var/log/wef-tests/phase3-results.json",
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
        print(f"\nPhase 3 tests completed with {failed} failure(s)")
        sys.exit(1)
    else:
        print(f"\nPhase 3 tests completed successfully ({passed} passed)")
        sys.exit(0)


if __name__ == "__main__":
    main()

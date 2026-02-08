#!/usr/bin/env python3
"""
Validation and monitoring script for WEF Server Real AD Tests

This script provides continuous monitoring and validation capabilities
for the WEF server during testing. It can be run alongside test suites
to provide real-time metrics and alerts.

Usage:
    python3 validate_metrics.py [--wef-server HOST] [--interval SECONDS] [--duration MINUTES]

Features:
    - Real-time metrics collection
    - Threshold-based alerting
    - Performance trend analysis
    - JSON report generation
"""

import argparse
import json
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional

import requests

# Configuration
DEFAULT_WEF_SERVER = "wef-srv-01.wef.lab"
DEFAULT_METRICS_PORT = 9090
DEFAULT_INTERVAL = 30  # seconds
DEFAULT_DURATION = 10  # minutes (0 = infinite)

# Alert thresholds
ALERT_THRESHOLDS = {
    "max_events_backlog": 500,
    "max_processing_latency_sec": 60,
    "min_events_per_minute": 10,
    "max_memory_percent": 80,
    "max_error_rate": 0.05,  # 5% error rate
}

# Metrics to track
METRICS_TO_TRACK = [
    "wef_connections_total",
    "wef_events_received_total",
    "wef_events_forwarded_total",
    "wef_active_subscriptions",
    "wef_events_dropped_total",
    "wef_errors_total",
]


class MetricsCollector:
    """Collects and analyzes WEF server metrics"""
    
    def __init__(self, wef_server: str, metrics_port: int):
        self.wef_server = wef_server
        self.metrics_port = metrics_port
        self.metrics_url = f"http://{wef_server}:{metrics_port}/metrics"
        self.history: List[Dict] = []
        self.alerts: List[Dict] = []
    
    def fetch_metrics(self) -> Dict[str, float]:
        """Fetch current metrics from WEF server"""
        try:
            response = requests.get(self.metrics_url, timeout=10)
            if response.status_code != 200:
                return {}
            
            metrics = {}
            for line in response.text.split("\n"):
                for metric_name in METRICS_TO_TRACK:
                    if line.startswith(f"{metric_name} "):
                        try:
                            metrics[metric_name] = float(line.split()[-1])
                        except (ValueError, IndexError):
                            pass
            
            return metrics
        except Exception as e:
            print(f"Error fetching metrics: {e}")
            return {}
    
    def collect_sample(self) -> Dict:
        """Collect a single metrics sample with timestamp"""
        sample = {
            "timestamp": datetime.now().isoformat(),
            "metrics": self.fetch_metrics()
        }
        self.history.append(sample)
        return sample
    
    def check_alerts(self, current: Dict, previous: Optional[Dict] = None) -> List[Dict]:
        """Check for alert conditions"""
        new_alerts = []
        
        if not current or "metrics" not in current:
            return new_alerts
        
        metrics = current["metrics"]
        
        # Check event backlog
        received = metrics.get("wef_events_received_total", 0)
        forwarded = metrics.get("wef_events_forwarded_total", 0)
        backlog = received - forwarded
        
        if backlog > ALERT_THRESHOLDS["max_events_backlog"]:
            new_alerts.append({
                "timestamp": current["timestamp"],
                "severity": "WARNING",
                "type": "backlog_high",
                "message": f"Event backlog is high: {backlog} events",
                "value": backlog,
                "threshold": ALERT_THRESHOLDS["max_events_backlog"]
            })
        
        # Check processing rate (if we have previous sample)
        if previous and "metrics" in previous:
            prev_metrics = previous["metrics"]
            time_diff = (
                datetime.fromisoformat(current["timestamp"]) -
                datetime.fromisoformat(previous["timestamp"])
            ).total_seconds()
            
            if time_diff > 0:
                received_diff = received - prev_metrics.get("wef_events_received_total", 0)
                rate_per_minute = (received_diff / time_diff) * 60
                
                if rate_per_minute < ALERT_THRESHOLDS["min_events_per_minute"]:
                    new_alerts.append({
                        "timestamp": current["timestamp"],
                        "severity": "WARNING",
                        "type": "low_event_rate",
                        "message": f"Event rate is low: {rate_per_minute:.1f} events/min",
                        "value": rate_per_minute,
                        "threshold": ALERT_THRESHOLDS["min_events_per_minute"]
                    })
        
        # Check error rate
        errors = metrics.get("wef_errors_total", 0)
        if received > 0:
            error_rate = errors / received
            if error_rate > ALERT_THRESHOLDS["max_error_rate"]:
                new_alerts.append({
                    "timestamp": current["timestamp"],
                    "severity": "ERROR",
                    "type": "high_error_rate",
                    "message": f"Error rate is high: {error_rate:.2%}",
                    "value": error_rate,
                    "threshold": ALERT_THRESHOLDS["max_error_rate"]
                })
        
        self.alerts.extend(new_alerts)
        return new_alerts
    
    def generate_report(self) -> Dict:
        """Generate final report from collected data"""
        if not self.history:
            return {}
        
        # Calculate statistics
        first = self.history[0]
        last = self.history[-1]
        
        duration_sec = 0
        if len(self.history) > 1:
            duration_sec = (
                datetime.fromisoformat(last["timestamp"]) -
                datetime.fromisoformat(first["timestamp"])
            ).total_seconds()
        
        # Calculate throughput
        first_metrics = first.get("metrics", {})
        last_metrics = last.get("metrics", {})
        
        events_received = last_metrics.get("wef_events_received_total", 0) - \
                         first_metrics.get("wef_events_received_total", 0)
        
        events_forwarded = last_metrics.get("wef_events_forwarded_total", 0) - \
                          first_metrics.get("wef_events_forwarded_total", 0)
        
        throughput = events_received / duration_sec if duration_sec > 0 else 0
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "monitoring_duration_seconds": duration_sec,
            "samples_collected": len(self.history),
            "metrics": {
                "events_received_total": events_received,
                "events_forwarded_total": events_forwarded,
                "average_throughput_events_per_sec": throughput,
                "final_active_subscriptions": last_metrics.get("wef_active_subscriptions", 0),
                "final_connections": last_metrics.get("wef_connections_total", 0)
            },
            "alerts": {
                "total": len(self.alerts),
                "by_severity": {
                    "ERROR": len([a for a in self.alerts if a["severity"] == "ERROR"]),
                    "WARNING": len([a for a in self.alerts if a["severity"] == "WARNING"])
                },
                "details": self.alerts
            },
            "raw_data": self.history
        }
        
        return report


def print_status(collector: MetricsCollector, current: Dict):
    """Print current status to console"""
    if not current or "metrics" not in current:
        print("[No metrics available]")
        return
    
    metrics = current["metrics"]
    timestamp = current["timestamp"].split("T")[1].split(".")[0]
    
    received = metrics.get("wef_events_received_total", 0)
    forwarded = metrics.get("wef_events_forwarded_total", 0)
    subscriptions = metrics.get("wef_active_subscriptions", 0)
    connections = metrics.get("wef_connections_total", 0)
    
    print(f"[{timestamp}] Events: {received:,} received, {forwarded:,} forwarded | "
          f"Subs: {subscriptions} | Conn: {connections}")


def main():
    parser = argparse.ArgumentParser(
        description="WEF Server Metrics Validation and Monitoring"
    )
    parser.add_argument(
        "--wef-server",
        default=DEFAULT_WEF_SERVER,
        help=f"WEF server hostname or IP (default: {DEFAULT_WEF_SERVER})"
    )
    parser.add_argument(
        "--metrics-port",
        type=int,
        default=DEFAULT_METRICS_PORT,
        help=f"Metrics port (default: {DEFAULT_METRICS_PORT})"
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=DEFAULT_INTERVAL,
        help=f"Collection interval in seconds (default: {DEFAULT_INTERVAL})"
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=DEFAULT_DURATION,
        help=f"Monitoring duration in minutes, 0=infinite (default: {DEFAULT_DURATION})"
    )
    parser.add_argument(
        "--output",
        default="/var/log/wef-tests/monitoring-report.json",
        help="Output file for monitoring report"
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Quiet mode - only print alerts"
    )
    
    args = parser.parse_args()
    
    collector = MetricsCollector(args.wef_server, args.metrics_port)
    
    print("=" * 60)
    print("WEF Server Metrics Monitor")
    print("=" * 60)
    print(f"Server: {args.wef_server}:{args.metrics_port}")
    print(f"Interval: {args.interval}s")
    print(f"Duration: {args.duration} min" if args.duration > 0 else "Duration: infinite")
    print("=" * 60)
    print()
    
    start_time = time.time()
    max_duration = args.duration * 60 if args.duration > 0 else float('inf')
    previous_sample = None
    
    try:
        while True:
            # Collect sample
            current = collector.collect_sample()
            
            # Check alerts
            alerts = collector.check_alerts(current, previous_sample)
            
            # Print status
            if not args.quiet:
                print_status(collector, current)
            
            # Print alerts
            for alert in alerts:
                severity = "⚠" if alert["severity"] == "WARNING" else "✗"
                print(f"{severity} ALERT: {alert['message']}")
            
            previous_sample = current
            
            # Check duration
            elapsed = time.time() - start_time
            if elapsed >= max_duration:
                break
            
            # Wait for next interval
            time.sleep(args.interval)
            
    except KeyboardInterrupt:
        print("\nMonitoring interrupted by user")
    
    # Generate report
    report = collector.generate_report()
    
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\nReport saved to: {args.output}")
    
    # Print summary
    print("\n" + "=" * 60)
    print("MONITORING SUMMARY")
    print("=" * 60)
    print(f"Duration: {report.get('monitoring_duration_seconds', 0):.1f}s")
    print(f"Samples: {report.get('samples_collected', 0)}")
    print(f"Events received: {report.get('metrics', {}).get('events_received_total', 0):,}")
    print(f"Events forwarded: {report.get('metrics', {}).get('events_forwarded_total', 0):,}")
    print(f"Avg throughput: {report.get('metrics', {}).get('average_throughput_events_per_sec', 0):.1f} events/sec")
    print(f"Alerts: {report.get('alerts', {}).get('total', 0)} total")
    print("=" * 60)
    
    # Exit with error code if there were ERROR alerts
    error_count = report.get('alerts', {}).get('by_severity', {}).get('ERROR', 0)
    sys.exit(1 if error_count > 0 else 0)


if __name__ == "__main__":
    main()

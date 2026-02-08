#!/usr/bin/env python3
"""
Master test runner for WEF Server Real AD Environment Testing

This script orchestrates all three phases of testing:
  - Phase 1: Basic Connectivity & Protocol Validation
  - Phase 2: Event Types & Parsing Validation
  - Phase 3: Load & Performance Testing

Usage:
    ./run-real-ad-tests.sh [--phase {1,2,3,all}] [--wef-server HOST]

Environment Variables:
    WEF_SERVER      - WEF server hostname (default: wef-srv-01.wef.lab)
    S3_ENDPOINT     - S3/MinIO endpoint (default: http://minio-srv.wef.lab:9000)
    TEST_DURATION   - Phase 3 test duration in minutes (default: 5)
    TEST_RATE       - Phase 3 event rate per minute (default: 100)
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime
from typing import Dict, List, Tuple

# Configuration
DEFAULT_WEF_SERVER = os.getenv("WEF_SERVER", "wef-srv-01.wef.lab")
DEFAULT_S3_ENDPOINT = os.getenv("S3_ENDPOINT", "http://minio-srv.wef.lab:9000")
DEFAULT_TEST_DURATION = int(os.getenv("TEST_DURATION", "5"))
DEFAULT_TEST_RATE = int(os.getenv("TEST_RATE", "100"))

TEST_SCRIPTS = {
    1: "scripts/test_phase1_connectivity.py",
    2: "scripts/test_phase2_events.py",
    3: "scripts/test_phase3_performance.py"
}

RESULTS_FILE = "/var/log/wef-tests/master-results.json"


class Colors:
    """Terminal color codes"""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'


def print_header(text: str):
    """Print a formatted header"""
    print()
    print("=" * 70)
    print(f"{Colors.BOLD}{text}{Colors.END}")
    print("=" * 70)
    print()


def print_phase_header(phase: int, title: str):
    """Print phase header"""
    print()
    print(f"{Colors.BLUE}{'='*70}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}PHASE {phase}: {title}{Colors.END}")
    print(f"{Colors.BLUE}{'='*70}{Colors.END}")
    print()


def run_test(script: str, args: argparse.Namespace) -> Tuple[int, str, str]:
    """Run a test script and return exit code, stdout, stderr"""
    cmd = ["python3", script]
    
    if args.wef_server:
        cmd.extend(["--wef-server", args.wef_server])
    
    if args.s3_endpoint and "phase2" in script:
        cmd.extend(["--s3-endpoint", args.s3_endpoint])
    
    if "phase3" in script:
        cmd.extend(["--duration", str(args.duration)])
        cmd.extend(["--rate", str(args.rate)])
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=3600  # 1 hour max
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "Test timed out after 1 hour"
    except Exception as e:
        return 1, "", str(e)


def run_phase(phase: int, args: argparse.Namespace) -> Dict:
    """Run a single test phase"""
    phase_titles = {
        1: "Basic Connectivity & Protocol Validation",
        2: "Event Types & Parsing Validation",
        3: "Load & Performance Testing"
    }
    
    print_phase_header(phase, phase_titles[phase])
    
    script = TEST_SCRIPTS[phase]
    exit_code, stdout, stderr = run_test(script, args)
    
    # Print output
    if stdout:
        print(stdout)
    if stderr:
        print(f"{Colors.YELLOW}Stderr:{Colors.END}")
        print(stderr)
    
    # Determine result
    success = exit_code == 0
    
    return {
        "phase": phase,
        "title": phase_titles[phase],
        "success": success,
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "timestamp": datetime.now().isoformat()
    }


def generate_report(all_results: List[Dict]) -> Dict:
    """Generate final test report"""
    total_phases = len(all_results)
    passed_phases = sum(1 for r in all_results if r["success"])
    failed_phases = total_phases - passed_phases
    
    report = {
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "total_phases": total_phases,
            "passed": passed_phases,
            "failed": failed_phases,
            "success_rate": (passed_phases / total_phases * 100) if total_phases > 0 else 0
        },
        "configuration": {
            "wef_server": DEFAULT_WEF_SERVER,
            "s3_endpoint": DEFAULT_S3_ENDPOINT,
            "test_duration_minutes": DEFAULT_TEST_DURATION,
            "test_rate_per_minute": DEFAULT_TEST_RATE
        },
        "phases": all_results
    }
    
    return report


def print_summary(report: Dict):
    """Print final summary"""
    print()
    print("=" * 70)
    print(f"{Colors.BOLD}FINAL TEST SUMMARY{Colors.END}")
    print("=" * 70)
    print()
    
    summary = report["summary"]
    
    for phase_result in report["phases"]:
        phase = phase_result["phase"]
        title = phase_result["title"]
        success = phase_result["success"]
        
        status = f"{Colors.GREEN}✓ PASSED{Colors.END}" if success else f"{Colors.RED}✗ FAILED{Colors.END}"
        print(f"Phase {phase}: {status} - {title}")
    
    print()
    print(f"Total: {summary['passed']}/{summary['total_phases']} phases passed "
          f"({summary['success_rate']:.1f}%)")
    
    if summary['failed'] > 0:
        print(f"{Colors.RED}{Colors.BOLD}Some tests failed!{Colors.END}")
    else:
        print(f"{Colors.GREEN}{Colors.BOLD}All tests passed!{Colors.END}")
    
    print()


def main():
    parser = argparse.ArgumentParser(
        description="WEF Server Real AD Environment Test Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run all test phases
  ./run-real-ad-tests.sh

  # Run only Phase 1
  ./run-real-ad-tests.sh --phase 1

  # Run Phase 1 and 2
  ./run-real-ad-tests.sh --phase 1,2

  # Run with custom WEF server
  ./run-real-ad-tests.sh --wef-server my-wef-server.lab
        """
    )
    parser.add_argument(
        "--phase",
        default="all",
        help="Which phase(s) to run: 1, 2, 3, 1,2, all (default: all)"
    )
    parser.add_argument(
        "--wef-server",
        default=DEFAULT_WEF_SERVER,
        help=f"WEF server hostname (default: {DEFAULT_WEF_SERVER})"
    )
    parser.add_argument(
        "--s3-endpoint",
        default=DEFAULT_S3_ENDPOINT,
        help=f"S3/MinIO endpoint (default: {DEFAULT_S3_ENDPOINT})"
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=DEFAULT_TEST_DURATION,
        help=f"Phase 3 test duration in minutes (default: {DEFAULT_TEST_DURATION})"
    )
    parser.add_argument(
        "--rate",
        type=int,
        default=DEFAULT_TEST_RATE,
        help=f"Phase 3 event rate per minute (default: {DEFAULT_TEST_RATE})"
    )
    parser.add_argument(
        "--output",
        default=RESULTS_FILE,
        help=f"Output file for results (default: {RESULTS_FILE})"
    )
    
    args = parser.parse_args()
    
    # Determine which phases to run
    if args.phase == "all":
        phases_to_run = [1, 2, 3]
    else:
        try:
            phases_to_run = [int(p.strip()) for p in args.phase.split(",")]
            phases_to_run = [p for p in phases_to_run if p in [1, 2, 3]]
        except ValueError:
            print(f"{Colors.RED}Error: Invalid phase specification '{args.phase}'{Colors.END}")
            sys.exit(2)
    
    if not phases_to_run:
        print(f"{Colors.RED}Error: No valid phases specified{Colors.END}")
        sys.exit(2)
    
    # Print welcome message
    print_header("WEF Server Real AD Environment Test Suite")
    print(f"WEF Server: {args.wef_server}")
    print(f"S3 Endpoint: {args.s3_endpoint}")
    print(f"Phases to run: {', '.join(map(str, phases_to_run))}")
    print()
    
    # Run tests
    all_results = []
    
    for phase in phases_to_run:
        result = run_phase(phase, args)
        all_results.append(result)
        
        # Stop if a phase fails and we're running sequentially
        if not result["success"] and not args.phase == "all":
            print(f"{Colors.YELLOW}Phase {phase} failed. Stopping.{Colors.END}")
            break
    
    # Generate report
    report = generate_report(all_results)
    
    # Save results
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    
    print(f"\nDetailed results saved to: {args.output}")
    
    # Print summary
    print_summary(report)
    
    # Exit with appropriate code
    sys.exit(0 if all(r["success"] for r in all_results) else 1)


if __name__ == "__main__":
    main()

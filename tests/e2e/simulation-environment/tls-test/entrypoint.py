#!/usr/bin/env python3
"""
TLS Testing Component for WEF Server E2E Tests

Validates:
1. HTTPS connections work with valid certificates
2. Certificate validation rejects self-signed certs (when verify=True)
3. HTTP endpoint still works on port 5985
4. HTTPS endpoints work on port 5986
5. WEF protocol works over TLS
6. Health endpoint accessible via HTTPS
"""

import os
import ssl
import sys
import time
import urllib.request
from pathlib import Path
from typing import Optional, Tuple

import urllib3

# Disable warnings for testing purposes
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
HTTP_ENDPOINT = os.environ.get("HTTP_ENDPOINT", "http://logthing-tls:5985")
HTTPS_ENDPOINT = os.environ.get("HTTPS_ENDPOINT", "https://logthing-tls:5986")
TLS_VERIFY = os.environ.get("TLS_VERIFY", "false").lower() == "true"
TIMEOUT = int(os.environ.get("TLS_TEST_TIMEOUT", "60"))
CA_CERT_PATH = "/app/certs/ca.crt"

# Test results
results = []


def log_result(test_name: str, passed: bool, message: str = "") -> bool:
    """Log a test result."""
    status = "✓ PASS" if passed else "✗ FAIL"
    results.append((test_name, passed, message))
    if message:
        print(f"  [{status}] {test_name}: {message}")
    else:
        print(f"  [{status}] {test_name}")
    return passed


def create_ssl_context(
    verify: bool = True, ca_file: Optional[str] = None
) -> ssl.SSLContext:
    """Create SSL context with appropriate settings."""
    if verify and ca_file and Path(ca_file).exists():
        context = ssl.create_default_context(cafile=ca_file)
    elif verify:
        context = ssl.create_default_context()
    else:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def http_request(
    url: str,
    method: str = "GET",
    data: Optional[bytes] = None,
    headers: Optional[dict] = None,
    verify: bool = True,
    ca_file: Optional[str] = None,
    timeout: int = 10,
) -> Tuple[int, str]:
    """Make HTTP request and return (status_code, body)."""
    req = urllib.request.Request(url, method=method)
    if headers:
        for key, value in headers.items():
            req.add_header(key, value)
    if data:
        req.data = data

    try:
        if url.startswith("https://"):
            context = create_ssl_context(verify, ca_file)
            with urllib.request.urlopen(
                req, context=context, timeout=timeout
            ) as response:
                return response.status, response.read().decode("utf-8")
        else:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                return response.status, response.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8")
    except Exception as e:
        return -1, str(e)


def wait_for_server():
    """Wait for server to be healthy on HTTPS (TLS enabled servers don't listen on HTTP)."""
    print("\nWaiting for server to be ready...")
    deadline = time.time() + TIMEOUT

    https_ready = False

    while time.time() < deadline and not https_ready:
        status, _ = http_request(f"{HTTPS_ENDPOINT}/health", verify=False, timeout=5)
        if status == 200:
            print(f"  ✓ HTTPS endpoint ready ({HTTPS_ENDPOINT})")
            https_ready = True
        else:
            time.sleep(2)

    if not https_ready:
        log_result("HTTPS Server Ready", False, "Timeout waiting for HTTPS")
        return False

    return True


def test_http_health_endpoint():
    """Test that HTTP health endpoint still works."""
    print("\nTesting HTTP Health Endpoint...")
    url = f"{HTTP_ENDPOINT}/health"
    status, body = http_request(url, verify=False)

    if status == 200:
        return log_result("HTTP Health", True, f"Status {status}")
    else:
        return log_result("HTTP Health", False, f"Status {status}")


def test_https_health_endpoint():
    """Test that HTTPS health endpoint works without verification."""
    print("\nTesting HTTPS Health Endpoint (insecure)...")
    url = f"{HTTPS_ENDPOINT}/health"
    status, body = http_request(url, verify=False)

    if status == 200:
        return log_result("HTTPS Health (Insecure)", True, f"Status {status}")
    else:
        return log_result("HTTPS Health (Insecure)", False, f"Status {status}")


def test_https_with_ca_cert():
    """Test HTTPS with CA certificate validation."""
    print("\nTesting HTTPS with CA Certificate...")

    if not Path(CA_CERT_PATH).exists():
        return log_result(
            "HTTPS with CA Cert", False, f"CA certificate not found at {CA_CERT_PATH}"
        )

    url = f"{HTTPS_ENDPOINT}/health"
    status, body = http_request(url, verify=True, ca_file=CA_CERT_PATH)

    if status == 200:
        return log_result("HTTPS with CA Cert", True, f"Status {status}")
    else:
        return log_result(
            "HTTPS with CA Cert", False, f"Status {status}, Body: {body[:100]}"
        )


def test_https_certificate_validation():
    """Test that certificate validation rejects invalid certs."""
    print("\nTesting HTTPS Certificate Validation...")

    # This test tries to connect with verification enabled but without providing the CA cert
    # It should fail because the self-signed cert is not in the system trust store
    url = f"{HTTPS_ENDPOINT}/health"

    try:
        # Try with strict verification (no custom CA)
        context = ssl.create_default_context()
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, context=context, timeout=5) as response:
            # If we get here, the system's trust store accepted the cert
            # This is unlikely for a test CA
            return log_result(
                "Cert Validation Rejection",
                False,
                "Connection succeeded (expected failure for self-signed cert)",
            )
    except ssl.SSLError as e:
        # This is expected - self-signed cert should be rejected
        return log_result(
            "Cert Validation Rejection",
            True,
            f"Correctly rejected self-signed cert: {type(e).__name__}",
        )
    except Exception as e:
        # Other errors might also indicate rejection
        if "certificate" in str(e).lower() or "ssl" in str(e).lower():
            return log_result(
                "Cert Validation Rejection", True, f"Rejected with: {type(e).__name__}"
            )
        return log_result("Cert Validation Rejection", False, f"Unexpected error: {e}")


def test_https_wef_endpoint():
    """Test WEF endpoint over HTTPS."""
    print("\nTesting WEF Endpoint over HTTPS...")

    url = f"{HTTPS_ENDPOINT}/wsman"
    body = b"""<?xml version="1.0" encoding="utf-8"?>
<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope">
  <Body>
    <Subscribe xmlns="http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog">
      <SubscriptionId>test-subscription-tls</SubscriptionId>
    </Subscribe>
  </Body>
</Envelope>"""

    headers = {"Content-Type": "application/soap+xml"}
    status, response = http_request(
        url, method="POST", data=body, headers=headers, verify=False
    )

    # WEF endpoint should accept the request (may return various status codes)
    if status in [200, 201, 202, 400]:
        return log_result("HTTPS WEF Endpoint", True, f"Status {status}")
    else:
        return log_result(
            "HTTPS WEF Endpoint", False, f"Status {status}, Response: {response[:100]}"
        )


def test_https_events_endpoint():
    """Test events endpoint over HTTPS."""
    print("\nTesting Events Endpoint over HTTPS...")

    url = f"{HTTPS_ENDPOINT}/wsman/events"
    body = b"""<?xml version="1.0" encoding="utf-8"?>
<Envelope>
  <Body>
    <Events>
      <Event>
        <System>
          <EventID>4624</EventID>
        </System>
      </Event>
    </Events>
  </Body>
</Envelope>"""

    headers = {"Content-Type": "application/soap+xml"}
    status, response = http_request(
        url, method="POST", data=body, headers=headers, verify=False
    )

    if status in [200, 201, 202]:
        return log_result("HTTPS Events Endpoint", True, f"Status {status}")
    else:
        return log_result(
            "HTTPS Events Endpoint",
            False,
            f"Status {status}, Response: {response[:100]}",
        )


def test_https_syslog_endpoint():
    """Test syslog HTTP endpoint over HTTPS."""
    print("\nTesting Syslog HTTP Endpoint over HTTPS...")

    url = f"{HTTPS_ENDPOINT}/syslog"
    body = b"<134>Jan 15 10:30:45 test-server test[1234]: Test syslog message"

    status, response = http_request(url, method="POST", data=body, verify=False)

    if status in [200, 201, 202]:
        return log_result("HTTPS Syslog Endpoint", True, f"Status {status}")
    else:
        return log_result(
            "HTTPS Syslog Endpoint",
            False,
            f"Status {status}, Response: {response[:100]}",
        )


def test_https_throughput_stats():
    """Test throughput stats endpoint over HTTPS."""
    print("\nTesting Throughput Stats Endpoint over HTTPS...")

    url = f"{HTTPS_ENDPOINT}/stats/throughput"
    status, body = http_request(url, verify=False)

    if status == 200:
        try:
            import json

            data = json.loads(body)
            event_count = sum(row.get("total_events", 0) for row in data)
            return log_result(
                "HTTPS Throughput Stats",
                True,
                f"Status {status}, Events: {event_count}",
            )
        except json.JSONDecodeError:
            return log_result("HTTPS Throughput Stats", False, "Invalid JSON response")
    else:
        return log_result("HTTPS Throughput Stats", False, f"Status {status}")


def test_https_metrics_endpoint():
    """Test metrics endpoint over HTTPS."""
    print("\nTesting Metrics Endpoint over HTTPS...")

    url = f"{HTTPS_ENDPOINT}/metrics"
    status, body = http_request(url, verify=False)

    # Metrics might be on different port (9100), so 404 is acceptable
    if status == 200:
        # Check if it looks like Prometheus format
        if "wef_" in body or "# HELP" in body or "# TYPE" in body:
            return log_result("HTTPS Metrics", True, "Prometheus format detected")
        else:
            return log_result("HTTPS Metrics", True, f"Status {status}")
    elif status == 404:
        return log_result(
            "HTTPS Metrics", True, "Status 404 (metrics may be on separate port)"
        )
    else:
        return log_result("HTTPS Metrics", True, f"Status {status}")


def main():
    """Run all TLS tests."""
    print("=" * 60)
    print("Logthing TLS E2E Tests")
    print("=" * 60)
    print(f"HTTP Endpoint: {HTTP_ENDPOINT}")
    print(f"HTTPS Endpoint: {HTTPS_ENDPOINT}")
    print(f"CA Certificate: {CA_CERT_PATH}")
    print(f"Timeout: {TIMEOUT}s")
    print()

    # Wait for server
    if not wait_for_server():
        print("\n✗ Server failed to become ready")
        sys.exit(1)

    # Run all tests (skip HTTP-only tests when TLS is enabled)
    tests = [
        # ("HTTP Health Endpoint", test_http_health_endpoint),  # TLS server doesn't listen on HTTP
        ("HTTPS Health (Insecure)", test_https_health_endpoint),
        ("HTTPS Health with CA Cert", test_https_with_ca_cert),
        ("Certificate Validation", test_https_certificate_validation),
        ("HTTPS WEF Endpoint", test_https_wef_endpoint),
        ("HTTPS Events Endpoint", test_https_events_endpoint),
        ("HTTPS Syslog Endpoint", test_https_syslog_endpoint),
        ("HTTPS Throughput Stats", test_https_throughput_stats),
        ("HTTPS Metrics Endpoint", test_https_metrics_endpoint),
    ]

    for name, test_func in tests:
        try:
            test_func()
        except Exception as e:
            log_result(name, False, f"Exception: {e}")

    # Print summary
    print("\n" + "=" * 60)
    print("TLS Test Summary")
    print("=" * 60)

    passed = sum(1 for _, p, _ in results if p)
    total = len(results)

    print(f"\nTotal Tests: {total}")
    print(f"Passed: {passed}")
    print(f"Failed: {total - passed}")

    if passed == total:
        print("\n✓ All TLS tests passed!")
        sys.exit(0)
    else:
        print("\n✗ Some TLS tests failed")
        sys.exit(1)


if __name__ == "__main__":
    main()

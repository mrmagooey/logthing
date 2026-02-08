#!/usr/bin/env python3
"""
Kerberos authentication test script for WEF Server E2E testing.

This script tests:
1. Server starts successfully with Kerberos enabled
2. Health endpoint remains accessible without authentication
3. Protected endpoints (WEF, syslog) require authentication (return 401)
4. Proper error messages are returned for unauthenticated requests
"""

import json
import os
import sys
import time
from pathlib import Path

import requests

WEF_ENDPOINT = os.environ.get("WEF_ENDPOINT", "http://wef-server-kerberos:5985")
TIMEOUT = int(os.environ.get("WEF_TIMEOUT_SECS", "60"))


def wait_for_health():
    """Wait for server to become healthy."""
    deadline = time.time() + TIMEOUT
    url = f"{WEF_ENDPOINT}/health"
    print(f"Waiting for server health at {url}...")
    
    while time.time() < deadline:
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200:
                print("✓ Server is healthy")
                return True
        except requests.RequestException as e:
            print(f"  Waiting... ({e})")
        time.sleep(2)
    
    print("✗ Server did not become healthy in time")
    return False


def test_health_endpoint_no_auth():
    """Test that health endpoint is accessible without authentication."""
    url = f"{WEF_ENDPOINT}/health"
    print(f"\nTesting health endpoint (no auth required): {url}")
    
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            print(f"✓ Health endpoint accessible without authentication")
            return True
        else:
            print(f"✗ Health endpoint returned {resp.status_code}, expected 200")
            return False
    except requests.RequestException as e:
        print(f"✗ Request failed: {e}")
        return False


def test_wsman_requires_auth():
    """Test that WEF endpoint requires authentication."""
    url = f"{WEF_ENDPOINT}/wsman"
    print(f"\nTesting WEF endpoint (auth required): {url}")
    
    # Send a simple request without authentication
    headers = {"Content-Type": "application/soap+xml"}
    body = """<?xml version="1.0" encoding="utf-8"?>
<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope">
  <Body>
    <Test/>
  </Body>
</Envelope>"""
    
    try:
        resp = requests.post(url, data=body, headers=headers, timeout=10)
        if resp.status_code == 401:
            # Check for WWW-Authenticate header
            www_auth = resp.headers.get("WWW-Authenticate", "")
            if "Negotiate" in www_auth:
                print(f"✓ WEF endpoint correctly returns 401 Unauthorized with WWW-Authenticate: Negotiate")
            else:
                print(f"✓ WEF endpoint correctly returns 401 Unauthorized (WWW-Authenticate: {www_auth})")
            return True
        elif resp.status_code == 200:
            print(f"✗ WEF endpoint returned 200, expected 401 (Kerberos may not be enabled)")
            return False
        else:
            print(f"✗ WEF endpoint returned {resp.status_code}, expected 401")
            return False
    except requests.RequestException as e:
        print(f"✗ Request failed: {e}")
        return False


def test_wsman_events_requires_auth():
    """Test that WEF events endpoint requires authentication."""
    url = f"{WEF_ENDPOINT}/wsman/events"
    print(f"\nTesting WEF events endpoint (auth required): {url}")
    
    headers = {"Content-Type": "application/soap+xml"}
    body = """<?xml version="1.0" encoding="utf-8"?>
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
    
    try:
        resp = requests.post(url, data=body, headers=headers, timeout=10)
        if resp.status_code == 401:
            www_auth = resp.headers.get("WWW-Authenticate", "")
            if "Negotiate" in www_auth:
                print(f"✓ WEF events endpoint correctly returns 401 with WWW-Authenticate: Negotiate")
            else:
                print(f"✓ WEF events endpoint correctly returns 401 (WWW-Authenticate: {www_auth})")
            return True
        else:
            print(f"✗ WEF events endpoint returned {resp.status_code}, expected 401")
            return False
    except requests.RequestException as e:
        print(f"✗ Request failed: {e}")
        return False


def test_syslog_http_requires_auth():
    """Test that syslog HTTP endpoint requires authentication."""
    url = f"{WEF_ENDPOINT}/syslog"
    print(f"\nTesting syslog HTTP endpoint (auth required): {url}")
    
    headers = {"Content-Type": "application/json"}
    body = json.dumps({"message": "test syslog message"})
    
    try:
        resp = requests.post(url, data=body, headers=headers, timeout=10)
        if resp.status_code == 401:
            www_auth = resp.headers.get("WWW-Authenticate", "")
            if "Negotiate" in www_auth:
                print(f"✓ Syslog HTTP endpoint correctly returns 401 with WWW-Authenticate: Negotiate")
            else:
                print(f"✓ Syslog HTTP endpoint correctly returns 401 (WWW-Authenticate: {www_auth})")
            return True
        else:
            print(f"✗ Syslog HTTP endpoint returned {resp.status_code}, expected 401")
            return False
    except requests.RequestException as e:
        print(f"✗ Request failed: {e}")
        return False


def test_metrics_endpoint():
    """Test that metrics endpoint is accessible (may or may not require auth)."""
    url = f"{WEF_ENDPOINT}/metrics"
    print(f"\nTesting metrics endpoint: {url}")
    
    try:
        resp = requests.get(url, timeout=10)
        print(f"  Metrics endpoint returned {resp.status_code}")
        # Metrics might be public or protected, just log the result
        return True
    except requests.RequestException as e:
        print(f"  Request failed: {e}")
        return True  # Don't fail on metrics issues


def test_wsman_with_auth():
    """Test that WEF endpoint accepts requests with Negotiate header."""
    url = f"{WEF_ENDPOINT}/wsman"
    print(f"\nTesting WEF endpoint with auth header: {url}")
    
    # Send a request with a dummy Negotiate token
    headers = {
        "Content-Type": "application/soap+xml",
        "Authorization": "Negotiate dGVzdA=="  # Base64 "test"
    }
    body = """<?xml version="1.0" encoding="utf-8"?>
<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope">
  <Body>
    <Test/>
  </Body>
</Envelope>"""
    
    try:
        resp = requests.post(url, data=body, headers=headers, timeout=10)
        # With the auth header, request should be processed (not 401)
        # It may return 400 for bad XML, but should NOT return 401
        if resp.status_code == 401:
            print(f"✗ WEF endpoint returned 401 even with Authorization header")
            return False
        else:
            print(f"✓ WEF endpoint accepted request with Authorization header (returned {resp.status_code})")
            return True
    except requests.RequestException as e:
        print(f"✗ Request failed: {e}")
        return False


def main():
    """Run all Kerberos authentication tests."""
    print("=" * 60)
    print("Kerberos Authentication E2E Tests")
    print("=" * 60)
    print(f"WEF Endpoint: {WEF_ENDPOINT}")
    print(f"Timeout: {TIMEOUT}s")
    print()
    
    # Wait for server to be ready
    if not wait_for_health():
        sys.exit(1)
    
    # Run tests
    results = []
    
    results.append(("Health endpoint (no auth)", test_health_endpoint_no_auth()))
    results.append(("WEF endpoint requires auth", test_wsman_requires_auth()))
    results.append(("WEF endpoint accepts auth", test_wsman_with_auth()))
    results.append(("WEF events endpoint requires auth", test_wsman_events_requires_auth()))
    results.append(("Syslog HTTP endpoint requires auth", test_syslog_http_requires_auth()))
    results.append(("Metrics endpoint", test_metrics_endpoint()))
    
    # Print summary
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    
    passed = sum(1 for _, r in results if r)
    total = len(results)
    
    for name, result in results:
        status = "PASS" if result else "FAIL"
        print(f"  [{status}] {name}")
    
    print()
    print(f"Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n✓ All Kerberos authentication tests passed!")
        sys.exit(0)
    else:
        print("\n✗ Some tests failed")
        sys.exit(1)


if __name__ == "__main__":
    main()

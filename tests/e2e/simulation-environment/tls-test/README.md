# TLS Test Component

End-to-end test component that validates TLS/HTTPS functionality for Logthing.

## Purpose

Validates that:
1. Logthing correctly serves HTTPS on port 5986 when TLS is enabled
2. HTTP endpoint continues to work on port 5985
3. Certificate validation works correctly
4. All WEF endpoints are accessible over HTTPS

## Test Coverage

### 1. HTTP Health Endpoint
- Verifies HTTP port 5985 still works when TLS is enabled
- Tests `/health` endpoint returns 200

### 2. HTTPS Health (Insecure)
- Verifies HTTPS port 5986 works with `verify=False`
- Tests basic TLS handshake works

### 3. HTTPS Health with CA Certificate
- Verifies HTTPS works when providing the CA certificate
- Tests certificate chain validation

### 4. Certificate Validation
- Verifies that self-signed certificates are rejected when verification is enabled
- Tests proper SSL/TLS error handling

### 5. HTTPS WEF Endpoint
- Tests WEF protocol over HTTPS (`/wsman`)
- Sends subscription request

### 6. HTTPS Events Endpoint
- Tests events ingestion over HTTPS (`/wsman/events`)
- Posts test events

### 7. HTTPS Syslog Endpoint
- Tests syslog HTTP endpoint over HTTPS (`/syslog`)
- Posts syslog messages

### 8. HTTPS Throughput Stats
- Tests stats endpoint over HTTPS (`/stats/throughput`)
- Validates JSON response

### 9. HTTPS Metrics Endpoint
- Tests metrics endpoint over HTTPS (`/metrics`)
- Accepts 404 (metrics may be on separate port)

## Certificates

Test certificates are generated using the `certs/generate-certs.sh` script:

- **ca.crt**: Certificate Authority certificate
- **server.crt/server.key**: Server certificate and key
- **client.crt/client.key**: Client certificate (for future mutual TLS testing)

All certificates are self-signed for testing purposes.

## Usage

### Standalone
```bash
docker compose -f tests/e2e/docker-compose.yml run --rm tls-test
```

### Environment Variables

- `HTTP_ENDPOINT`: HTTP endpoint URL (default: http://logthing-tls:5985)
- `HTTPS_ENDPOINT`: HTTPS endpoint URL (default: https://logthing-tls:5986)
- `TLS_TEST_TIMEOUT`: Timeout in seconds (default: 60)

### In Full E2E Suite
The TLS tests run automatically as part of `tests/e2e/run.sh`:
1. Standard tests (HTTP)
2. **TLS tests** ← NEW
3. Kerberos tests

## Exit Codes

- `0`: All TLS tests passed
- `1`: One or more tests failed

## Example Output

```
============================================================
Logthing TLS E2E Tests
============================================================
HTTP Endpoint: http://logthing-tls:5985
HTTPS Endpoint: https://logthing-tls:5986
CA Certificate: /app/certs/ca.crt
Timeout: 60s

Waiting for server to be ready...
  ✓ HTTP endpoint ready (http://logthing-tls:5985)
  ✓ HTTPS endpoint ready (https://logthing-tls:5986)

Testing HTTP Health Endpoint...
  [✓ PASS] HTTP Health: Status 200

Testing HTTPS Health Endpoint (insecure)...
  [✓ PASS] HTTPS Health (Insecure): Status 200

Testing HTTPS with CA Certificate...
  [✓ PASS] HTTPS Health with CA Cert: Status 200

Testing HTTPS Certificate Validation...
  [✓ PASS] Certificate Validation: Correctly rejected self-signed cert

Testing WEF Endpoint over HTTPS...
  [✓ PASS] HTTPS WEF Endpoint: Status 200

Testing Events Endpoint over HTTPS...
  [✓ PASS] HTTPS Events Endpoint: Status 200

Testing Syslog HTTP Endpoint over HTTPS...
  [✓ PASS] HTTPS Syslog Endpoint: Status 200

Testing Throughput Stats Endpoint over HTTPS...
  [✓ PASS] HTTPS Throughput Stats: Status 200, Events: 50

Testing Metrics Endpoint over HTTPS...
  [✓ PASS] HTTPS Metrics: Prometheus format detected

============================================================
TLS Test Summary
============================================================

Total Tests: 9
Passed: 9
Failed: 0

✓ All TLS tests passed!
```

## Implementation Notes

- Uses Python's standard library (`urllib`) for HTTPS requests
- Creates custom SSL contexts for different verification modes
- Disables urllib3 warnings for test scenarios with self-signed certs
- Supports both certificate validation modes (strict vs. insecure)

# Parsing Validator

End-to-end test component that validates event parsing functionality.

## Purpose

Validates that the WEF server correctly:
1. Parses Windows events according to YAML parser definitions
2. Extracts fields using XPath expressions
3. Applies enrichments (lookup tables)
4. Renders output_format templates
5. Writes correctly structured Parquet files to S3/MinIO

## What It Tests

### 1. Parquet Schema Validation
- Verifies required fields exist (id, received_at, source_host, parsed, etc.)
- Checks schema structure matches expected format

### 2. Parsed Field Validation
- Loads all 48 parser YAML definitions from `config/event_parsers/`
- Validates that events have all required fields defined in parsers
- Checks field presence for each event type (4624, 4625, etc.)

### 3. Enrichment Validation
- Verifies enrichment fields are populated (e.g., `LogonType_Name`)
- Validates lookup table values are applied correctly

### 4. Output Format Validation
- Extracts template variables from `output_format` strings
- Verifies all template variables exist in parsed data
- Attempts to render the format string

### 5. Event Count Validation
- Compares Parquet row count with throughput stats API
- Ensures no events are lost during processing

## Usage

### Standalone
```bash
docker compose -f tests/e2e/docker-compose.yml run --rm parsing-validator
```

### In Full E2E Suite
The validator runs automatically as part of `tests/e2e/run.sh`:
1. Starts MinIO and WEF server
2. Generates events via wef-generator
3. Validates S3 writes via s3-verifier
4. **Validates parsing via parsing-validator** ← NEW
5. Runs Kerberos tests

## Configuration

Environment variables:
- `MINIO_ENDPOINT`: MinIO/S3 endpoint (default: http://minio:9000)
- `MINIO_BUCKET`: S3 bucket name (default: wef-events)
- `WEF_STATS_ENDPOINT`: Throughput stats API URL
- `PARSER_DIR`: Path to parser YAML files
- `E2E_TIMEOUT_SECS`: Timeout for waiting (default: 120)
- `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`: S3 credentials

## Dependencies

- Python 3.11+
- boto3 (S3 client)
- pyarrow (Parquet reading)
- pyyaml (Parser config loading)
- requests (HTTP client)

## Exit Codes

- `0`: All validations passed
- `1`: One or more validations failed

## Example Output

```
============================================================
WEF Server Parsing Validator
============================================================

Loaded 48 parser definitions

Waiting for events to be processed...
  Found 50 events in throughput stats

Waiting for Parquet files in S3...
  Found 1 Parquet file(s)

============================================================
Validating: archive/2024-01-15/events.parquet
============================================================

Validating Parquet Schema...
  [✓ PASS] Required Fields Present
  Schema has 10 fields: ['id', 'received_at', 'source_host', ...]

Validating Parsed Fields...
  [✓ PASS] Parsed Data Present
  Found 48 unique event ID(s): [4624, 4625, 4634, ...]
  [✓ PASS] Event 4624 Required Fields: All 5 fields present
  [✓ PASS] Event 4768 Required Fields: All 4 fields present
  ...

Validating Enrichment Fields...
  [✓ PASS] Event 4624 Enrichment: LogonType_Name = Network
  ...

Validating Output Format Rendering...
  [✓ PASS] Event 4624 Output Format: Rendered successfully (87 chars)
  ...

Validating Event Counts...
  [✓ PASS] Event Count Match: Parquet: 50, Stats: 50

============================================================
Validation Summary
============================================================

Total Tests: 245
Passed: 245
Failed: 0

✓ All parsing validations passed!
```

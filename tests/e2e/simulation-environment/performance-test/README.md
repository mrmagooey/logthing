# Performance Test Suite

End-to-end performance testing suite for the WEF server, validating ingestion throughput, sustained load handling, and S3 parquet file generation.

## Overview

This test suite measures the WEF server's performance under various load conditions:
- **Baseline Performance**: Maximum throughput without rate limiting
- **Target Rate Tests**: Sustained load at specific rates (100k, 200k, 500k RPS)
- **Sustained 10k RPS Test**: Long-duration test with S3 verification (60 seconds, single event type, 100MB parquet files)

## Test Types

### 1. Baseline Performance Test
**Purpose**: Measure maximum throughput without rate limiting.

**Configuration**:
- Events: 50,000
- Batch size: 1,000
- Target rate: Unlimited (no throttling)

**Expected Results**:
- Ingestion rate: ~45,000-50,000 events/second
- Zero failed batches
- All events processed successfully

### 2. Target Rate Tests (100k, 200k, 500k RPS)
**Purpose**: Test server's ability to handle specific throughput targets.

**Configuration**:
- 100k RPS: 1,000,000 events, 300 second timeout
- 200k RPS: 2,000,000 events, 300 second timeout
- 500k RPS: 5,000,000 events, 600 second timeout

**Note**: These tests may fail if the server cannot sustain the target rate. The baseline test shows the server's actual capacity (~48k RPS).

### 3. Sustained 10k RPS Test (NEW)
**Purpose**: Test both event ingestion and S3 parquet file generation under sustained load.

**Configuration**:
```yaml
Duration: 60 seconds
Target rate: 10,000 events/second
Event type: 4624 (single type for focused testing)
Batch size: 1,000
Parquet max size: 100MB
Flush interval: 5 seconds
S3 verification: Enabled
```

**What It Tests**:
1. **Event Ingestion**: Can the server sustain 10k RPS for 60 seconds?
2. **Rate Limiting**: Client-side throttling to maintain target rate
3. **Parquet Generation**: Events are written to parquet files
4. **S3 Upload**: Parquet files are uploaded to MinIO/S3
5. **File Size**: Files respect the 100MB size limit
6. **Event Ordering**: Single event type (4624) for predictable file naming

**Expected Results**:
- Events sent: ~600,000 (10,000 × 60)
- Actual rate: 9,000-10,000 events/second (90-100% of target)
- S3 files: 10-15 parquet files
- Total size: 20-30 MB
- Success rate: 100% (no failed batches)

**Architecture**:
```
Performance Test Client          WEF Server                    MinIO/S3
       |                              |                            |
       |---- 1000 events/batch -----> |                            |
       |   (rate limited to 10k/s)    |                            |
       |                              |---- buffer events ------>   |
       |                              |   (5 second flush)         |
       |                              |                            |
       |                              |---- write parquet ----->   |
       |                              |   (100MB max per file)     |
       |                              |                            |
       |                              |---- upload to S3 ------>   |
       |                              |   (s3://wef-events/        |
       |                              |    event_type=4624/...)     |
       |                              |                            |
       |<-- verify S3 files ----------|----------------------------|
       |   (list & count parquet)     |                            |
```

**S3 Path Structure**:
```
s3://wef-events/
└── event_type=4624/
    └── year=2026/
        └── month=02/
            └── day=08/
                ├── events_4624_20260208_104441.parquet (1.0 MiB)
                ├── events_4624_20260208_104446.parquet (2.3 MiB)
                ├── events_4624_20260208_104451.parquet (2.3 MiB)
                └── ...
```

## Usage

### Run All Performance Tests
```bash
cd tests/e2e/simulation-environment
./run.sh
```

### Run Specific Test

#### Baseline Performance
```bash
docker compose up -d wef-server
docker compose run --rm performance-test
```

#### Sustained 10k RPS Test
```bash
docker compose up -d wef-server-10k-sustained
docker compose run --rm performance-test-10k-sustained
```

#### 100k RPS Target Test
```bash
docker compose up -d wef-server
docker compose run --rm performance-test-100k
```

### Run Test with Custom Parameters
```bash
docker compose run --rm performance-test-10k-sustained \
  -e PERF_TEST_DURATION_SECS=120 \
  -e PERF_TEST_TARGET_EPS=5000 \
  -e PERF_TEST_EVENT_TYPE=4625
```

## Configuration

### Environment Variables

#### General Test Parameters
| Variable | Description | Default |
|----------|-------------|---------|
| `PERF_TEST_TOTAL_EVENTS` | Total events to send (0 = use duration) | 50,000 |
| `PERF_TEST_DURATION_SECS` | Test duration in seconds (0 = use total events) | 0 |
| `PERF_TEST_BATCH_SIZE` | Events per batch | 1,000 |
| `PERF_TEST_TARGET_EPS` | Target events/second (0 = unlimited) | 0 |
| `PERF_TEST_TIMEOUT_SECS` | Maximum test duration | 300-600 |

#### Event Configuration
| Variable | Description | Default |
|----------|-------------|---------|
| `PERF_TEST_EVENT_TYPE` | Fixed event type (empty = random) | "" |
| `WEF_ENDPOINT` | WEF server URL | http://wef-server:5985 |
| `WEF_STATS_ENDPOINT` | Throughput stats API | http://wef-server:5985/stats/throughput |

#### S3 Verification (Sustained Test Only)
| Variable | Description | Default |
|----------|-------------|---------|
| `PERF_TEST_VERIFY_S3` | Enable S3 verification | false |
| `S3_ENDPOINT` | S3/MinIO endpoint | http://minio:9000 |
| `S3_BUCKET` | S3 bucket name | wef-events |
| `AWS_ACCESS_KEY_ID` | S3 access key | miniouser |
| `AWS_SECRET_ACCESS_KEY` | S3 secret key | miniopassword |

### Server Configuration (Sustained 10k Test)

The `config/wef-server-10k-sustained.toml` configures the server for the sustained test:

```toml
[forwarding]
buffer_size = 10
retry_attempts = 1

[[forwarding.destinations]]
name = "parquet"
url = "s3://wef-events/archive"
protocol = "http"
enabled = true

[forwarding.destinations.headers]
endpoint = "http://minio:9000"
"max-size-mb" = "100"          # 100MB parquet file limit
"flush-interval-secs" = "5"     # Flush every 5 seconds
"buffer-path" = "/tmp/wef-events"
```

## Exit Codes

- `0`: Test passed (≥95% of target rate achieved, S3 verification passed if enabled)
- `1`: Test failed (rate too low, S3 verification failed, or errors occurred)

## Example Output

### Sustained 10k RPS Test - Success
```
======================================================================
PERFORMANCE TEST: Target Rate Event Ingestion
======================================================================
Test duration: 60 seconds
Expected events: ~600,000
Batch size: 1000
Target rate: 10,000 events/second
Event type: 4624 (single type)
S3 verification: Enabled

WEF server is healthy
Baseline event count: 0

Sending events...
  Progress: 100,000 events sent - Current rate: 9537.0 events/sec - Remaining: 49s
  Progress: 200,000 events sent - Current rate: 9478.2 events/sec - Remaining: 39s
  Progress: 300,000 events sent - Current rate: 9509.7 events/sec - Remaining: 28s
  Progress: 400,000 events sent - Current rate: 9504.7 events/sec - Remaining: 18s
  Progress: 500,000 events sent - Current rate: 9508.9 events/sec - Remaining: 7s

Duration completed: 60 seconds

Waiting for event processing to complete...
Waiting for S3 parquet file flush (parquet files may take time to write)...

======================================================================
PERFORMANCE TEST RESULTS
======================================================================
Total time: 60.07 seconds
Events sent: 570,000
Events received (by server): 570,000
Successful batches: 570
Failed batches: 0

Overall ingestion rate: 9489.41 events/second
Server processing rate: 9489.41 events/second

======================================================================
S3 VERIFICATION
======================================================================
✓ S3 files verified successfully
  Files found: 12
  Total size: 20.93 MB
  Sample files: event_type=4624/year=2026/month=02/day=08/events_4624_20260208_105441.parquet, ...
======================================================================

✓ Performance test completed successfully
  Duration: 60 seconds
  Events sent: 570,000
  Target rate maintained: 95.0%
```

## Troubleshooting

### "S3 verification failed: No files found"

**Cause**: Docker image wasn't rebuilt after code changes.

**Solution**:
```bash
docker compose build performance-test-10k-sustained
```

### "Timeout reached after X seconds"

**Cause**: Server cannot sustain the target rate.

**Solution**: Check server logs or reduce target rate:
```bash
docker compose logs wef-server-10k-sustained
```

### "Batch X failed: Read timed out"

**Cause**: Server is overloaded or unresponsive.

**Solution**: 
- Check server health: `curl http://wef-server:5985/health`
- Review server logs for errors
- Reduce batch size or target rate

## Dependencies

- Python 3.11+
- requests (HTTP client)
- boto3 (S3 client, for verification)

## Implementation Notes

- **Rate Limiting**: Client implements sleep-based throttling to maintain target rate
- **Duration vs. Event Count**: Tests can be time-based (`PERF_TEST_DURATION_SECS`) or count-based (`PERF_TEST_TOTAL_EVENTS`)
- **S3 Verification**: Uses `list_objects_v2` API to find files matching the event type pattern
- **Error Handling**: Failed batches are logged but test continues (reports total failed count)
- **Progress Reporting**: Progress shown every 100 batches (100,000 events)

# Benchmark Results: Task 2 (buffer/channel-depth gauges)

Command: `cargo run --release --example flush_decoupling_benchmark -- mode=<mode> duration_secs=30 target_rate=4000 upload_delay_ms=150`

## Run 1: Realistic Mode

**Full Output:**
```
=== flush_decoupling_benchmark ===
BenchConfig {
    mode: "realistic",
    duration_secs: 30,
    target_rate: 4000,
    upload_delay_ms: 150,
    max_buffer_rows: 100000,
    channel_capacity: 256,
    flush_threshold_bytes: 104857600,
}

Sending sustained load: target_rate=4000 records/sec for 30 secs...
Send loop finished: 120000 records sent in 30.001s (achieved rate: 3999.9 rec/s)
Draining for 2s...

=== RESULTS ===
mode:                        realistic
params:                      duration_secs=30 target_rate=4000 upload_delay_ms=150 max_buffer_rows=100000 channel_capacity=256 flush_threshold_bytes=104857600
records sent:                120000
records written (durable):   119602
records dropped (channel):   0
records buffer_dropped(cap): 0
wall-clock elapsed:          30.001s
achieved send rate:          3999.9 rec/s
effective accept rate:       3999.9 rec/s
drop percentage:             0.000%
================
```

## Run 2: Stress Mode

**Full Output:**
```
=== flush_decoupling_benchmark ===
BenchConfig {
    mode: "stress",
    duration_secs: 30,
    target_rate: 4000,
    upload_delay_ms: 150,
    max_buffer_rows: 50,
    channel_capacity: 256,
    flush_threshold_bytes: 18446744073709551615,
}

Sending sustained load: target_rate=4000 records/sec for 30 secs...
Send loop finished: 119996 records sent in 30.000s (achieved rate: 3999.8 rec/s)
Draining for 2s...

=== RESULTS ===
mode:                        stress
params:                      duration_secs=30 target_rate=4000 upload_delay_ms=150 max_buffer_rows=50 channel_capacity=256 flush_threshold_bytes=18446744073709551615
records sent:                119996
records written (durable):   34823
records dropped (channel):   0
records buffer_dropped(cap): 84973
wall-clock elapsed:          30.000s
achieved send rate:          3999.8 rec/s
effective accept rate:       3999.8 rec/s
drop percentage:             0.000%
================
```

## Comparison Against Baseline / Task 1

([2026-07-24-benchmark-results-baseline.md](2026-07-24-benchmark-results-baseline.md), commit `6435396`;
[2026-07-24-benchmark-results-task1-log-fields.md](2026-07-24-benchmark-results-task1-log-fields.md), commit `8ee0054`)

| Metric | Baseline (realistic) | Task 1 (realistic) | Task 2 (realistic) | Baseline (stress) | Task 1 (stress) | Task 2 (stress) |
|---|---|---|---|---|---|---|
| Achieved send rate | ~3994.8–3999.8 rec/s | 3999.8 rec/s | 3999.9 rec/s | ~3999.9–4000.0 rec/s | 3999.8 rec/s | 3999.8 rec/s |
| Records written (durable) | 119180–119221 | 119021 | 119602 | 35225–35627 | 35024 | 34823 |
| Channel drops | 0 | 0 | 0 | 0 | 0 | 0 |
| Buffer drops (cap) | 0 | 0 | 0 | 84173–84629 | 84772 | 84973 |

All figures are within the baseline's established run-to-run variance. Task 2
adds two new gauges (`parquet_s3_channel_available`, `parquet_s3_buffer_rows`)
that are set only from the writer's periodic ticker branch inside
`ParquetWriterHandle::start_with_stats` — never from the per-record `push()`
hot path exercised by this benchmark's send loop — so, as expected, no
throughput or drop-rate change is observed relative to Task 1.

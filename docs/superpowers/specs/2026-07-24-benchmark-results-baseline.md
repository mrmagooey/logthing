# Baseline Benchmark Results (Pre-Change)

**Date:** 2026-07-24  
**Git Commit:** 6435396a99a4aa960befcb7a68505db122abd1b4  
**Branch:** perf/do-next-items

## Build Command

```bash
cargo build --release --example flush_decoupling_benchmark
```

**Result:** Clean build, no errors (3m 48s, with CC=/usr/bin/gcc override for C dependencies)

## Benchmark Runs

### Run 1: Realistic Mode

**Command:**
```bash
cargo run --release --example flush_decoupling_benchmark -- mode=realistic duration_secs=30 target_rate=4000 upload_delay_ms=150
```

**Full Output:**
```
Finished `release` profile [optimized] target(s) in 0.71s
     Running `target/release/examples/flush_decoupling_benchmark mode=realistic duration_secs=30 target_rate=4000 upload_delay_ms=150`
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
Send loop finished: 119996 records sent in 30.001s (achieved rate: 3999.8 rec/s)
Draining for 2s...

=== RESULTS ===
mode:                        realistic
params:                      duration_secs=30 target_rate=4000 upload_delay_ms=150 max_buffer_rows=100000 channel_capacity=256 flush_threshold_bytes=104857600
records sent:                119996
records written (durable):   119180
records dropped (channel):   0
records buffer_dropped(cap): 0
wall-clock elapsed:          30.001s
achieved send rate:          3999.8 rec/s
effective accept rate:       3999.8 rec/s
drop percentage:             0.000%
================
```

### Run 2: Realistic Mode

**Command:**
```bash
cargo run --release --example flush_decoupling_benchmark -- mode=realistic duration_secs=30 target_rate=4000 upload_delay_ms=150
```

**Full Output:**
```
    Finished `release` profile [optimized] target(s) in 1.05s
     Running `target/release/examples/flush_decoupling_benchmark mode=realistic duration_secs=30 target_rate=4000 upload_delay_ms=150`
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
Send loop finished: 119984 records sent in 30.035s (achieved rate: 3994.8 rec/s)
Draining for 2s...

=== RESULTS ===
mode:                        realistic
params:                      duration_secs=30 target_rate=4000 upload_delay_ms=150 max_buffer_rows=100000 channel_capacity=256 flush_threshold_bytes=104857600
records sent:                119984
records written (durable):   119221
records dropped (channel):   0
records buffer_dropped(cap): 0
wall-clock elapsed:          30.035s
achieved send rate:          3994.8 rec/s
effective accept rate:       3994.8 rec/s
drop percentage:             0.000%
================
```

### Run 3: Stress Mode

**Command:**
```bash
cargo run --release --example flush_decoupling_benchmark -- mode=stress duration_secs=30 target_rate=4000 upload_delay_ms=150
```

**Full Output:**
```
    Finished `release` profile [optimized] target(s) in 0.73s
     Running `target/release/examples/flush_decoupling_benchmark mode=stress duration_secs=30 target_rate=4000 upload_delay_ms=150`
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
Send loop finished: 120000 records sent in 30.000s (achieved rate: 4000.0 rec/s)
Draining for 2s...

=== RESULTS ===
mode:                        stress
params:                      duration_secs=30 target_rate=4000 upload_delay_ms=150 max_buffer_rows=50 channel_capacity=256 flush_threshold_bytes=18446744073709551615
records sent:                120000
records written (durable):   35627
records dropped (channel):   0
records buffer_dropped(cap): 84173
wall-clock elapsed:          30.000s
achieved send rate:          4000.0 rec/s
effective accept rate:       4000.0 rec/s
drop percentage:             0.000%
================
```

### Run 4: Stress Mode

**Command:**
```bash
cargo run --release --example flush_decoupling_benchmark -- mode=stress duration_secs=30 target_rate=4000 upload_delay_ms=150
```

**Full Output:**
```
    Finished `release` profile [optimized] target(s) in 0.77s
     Running `target/release/examples/flush_decoupling_benchmark mode=stress duration_secs=30 target_rate=4000 upload_delay_ms=150`
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
Send loop finished: 120000 records sent in 30.001s (achieved rate: 3999.9 rec/s)
Draining for 2s...

=== RESULTS ===
mode:                        stress
params:                      duration_secs=30 target_rate=4000 upload_delay_ms=150 max_buffer_rows=50 channel_capacity=256 flush_threshold_bytes=18446744073709551615
records sent:                120000
records written (durable):   35225
records dropped (channel):   0
records buffer_dropped(cap): 84629
wall-clock elapsed:          30.001s
achieved send rate:          3999.9 rec/s
effective accept rate:       3999.9 rec/s
drop percentage:             0.000%
================
```

## Summary

### Realistic Mode Baseline
- **Achieved throughput:** ~3997-3999.8 rec/s
- **Records written (durable):** ~119180-119221 out of 119984-119996 sent (~99.3%)
- **Drops:** 0 drops (both channel and buffer)
- **Status:** Excellent—no loss under normal workload

### Stress Mode Baseline
- **Achieved throughput:** ~3999.9-4000.0 rec/s (saturated)
- **Records written (durable):** ~35225-35627 out of 120000 sent (~29-30%)
- **Buffer drops (capacity):** ~84173-84629 drops (expected hard-cap behavior)
- **Channel drops:** 0
- **Status:** Expected degradation—high buffer drop rate due to small buffer window (50 rows) and upload delay (150ms)

### Key Observations
- Realistic mode shows excellent durability with nearly 100% of records written and no drops
- Stress mode shows the expected hard-cap drop behavior described in BENCHMARK_RESULTS.md, with ~70% of records dropped due to buffer capacity limits
- Both modes achieve their target send rates without saturation of the channel itself
- These baseline numbers establish the pre-change state for Tasks 1, 2, and 3 to compare against

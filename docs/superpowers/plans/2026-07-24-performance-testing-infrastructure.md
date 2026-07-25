# Performance-Testing Infrastructure Implementation Plan (item 2.6)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the two outstanding pieces of `logthing`'s performance-testing tier that
`docs/superpowers/specs/2026-07-24-performance-improvements-plan.md` §2.6 deferred: baseline
`criterion` regression-tracking benchmarks for the 6 `ParquetSink` adapters that don't have one
yet, and the concrete first deliverable of the `tools/loadgen` crate (the `syslog-udp`
subcommand, end-to-end, with a real baseline run and a methodology write-up template) — per
`docs/superpowers/specs/2026-07-05-performance-testing-strategy-design.md` §9's own explicit
recommendation not to build all 7 format generators before proving the pattern once.

**Architecture:** Two independent workstreams, neither touching production code:

- **A. Criterion baselines** — six new `benches/*.rs` files (harness = `false`, one per
  `ParquetSink` adapter: suricata, sflow, ipfix, syslog, generic/HEC, WEF), each calling the
  adapter's real, already-public `to_record_batch` through the same `ParquetSink` trait the
  existing `benches/zeek_conn_batch_amortization.rs` uses. These become the "before" numbers any
  future amortized-builder work on these adapters (the `2026-07-24-record-batch-amortization`
  pattern, applied so far only to Zeek's `conn` mapper) will need to prove it worked.
- **B. `tools/loadgen`** — a new Rust workspace member crate, added as a `[workspace]` member of
  the root `Cargo.toml` (with `default-members = ["."]` so plain `cargo build`/`cargo test` at
  the repo root is unaffected), with exactly one working subcommand: `syslog-udp`. It encodes
  real RFC3164 wire bytes matching `src/syslog/mod.rs`'s actual parser, paces sends at a target
  rate using the same tick-batching pattern already established by
  `examples/flush_decoupling_benchmark.rs`, and toggles between a raw free-text payload and a
  CEF payload (via `--structured`) to exercise `src/syslog/payload/mod.rs`'s sub-parser
  dispatch chain. A new manually-triggered `.github/workflows/performance.yml` (mirroring
  `binaries.yml`'s `workflow_dispatch` pattern) runs both the criterion suite and a `loadgen
  syslog-udp` baseline run against a real `logthing` instance, capturing metrics via
  `:9090/metrics`.

The other 6 `loadgen` format subcommands (ipfix, zeek, suricata, sflow, hec, otlp) are
**explicitly deferred** — described in their own section below, not planned at implementation
detail, per the design doc's own "prove the pattern once, then mechanical repetition" philosophy
(§9).

**Tech Stack:** Rust 2024, `criterion` 0.5 (already a dev-dependency), `arrow`/`arrow-array`
53.0, `tokio` 1.35 (`UdpSocket`, already used by `src/sflow/listener.rs` and
`src/ipfix/listener.rs`), `clap` 4 (derive API, new to `tools/loadgen` only — already present
transitively via `criterion`'s own dependency on `clap` 4.6.4 per `Cargo.lock`, so no new major
version is being introduced to the dependency graph).

**Full design rationale:** `docs/superpowers/specs/2026-07-05-performance-testing-strategy-design.md`
in full (read it before starting — this plan assumes its decisions, it does not re-litigate
them) and `docs/superpowers/specs/2026-07-24-performance-improvements-plan.md` §0 and §2.6
(status check confirming `LocalDiskSink` is wired for all 7 sources today, and recommending the
criterion-before-loadgen sequencing this plan follows).

---

## Global Constraints

Copied verbatim (or near-verbatim, with citations) from the two source documents — binding for
every task below.

- **Metric names (exact), from the design doc §3/§4/§9 and confirmed live in the codebase:**
  `syslog_messages_received`, `syslog_parse_errors`, `syslog_oversized_lines`,
  `syslog_tcp_connections_rejected`, `syslog_payload_parsed{type}` (counter, incremented by
  `src/syslog/payload/mod.rs::dispatch`), `parquet_s3_records_written{source,target}`,
  `parquet_s3_uploads{source,target}`, `parquet_s3_upload_errors{source,target}`,
  `parquet_s3_dropped{source,target}` (channel-full, `try_send`), `parquet_s3_buffer_dropped{source,target}`
  (hard-cap, `drop_oldest_to_cap`), `parquet_s3_partitions_capped{source,target}`. All served,
  unauthenticated, at `:9090/metrics` (`MetricsConfig::port`, default `9090`, confirmed
  `default_metrics_port() -> 9090` in `src/config/mod.rs`, enabled by default). `/stats.json`
  (admin server, requires auth) is a secondary, optional sanity check only — do not make CI
  automation depend on it (see Task 10's scope note).
- **Default ports:** syslog `udp_port=514` / `tcp_port=601` (`default_syslog_udp_port`,
  `default_syslog_tcp_port`, `src/config/mod.rs`). **CI-only deviation:** binding to `514`
  requires a privileged port and GitHub-hosted `ubuntu-latest` runners execute the job as a
  non-root `runner` user — the CI baseline job in Task 10 overrides `udp_port` to a non-privileged
  port (`15514`) via its config file; this does not change the subcommand's own default, which
  stays `514` to match `SyslogConfig`'s real default for local/manual runs.
- **`BufferedWriterConfig` defaults** (generic writer, design doc §7 point 5, confirmed in
  `src/forwarding/buffered_writer.rs`): `max_buffer_rows=100_000`, `flush_threshold_bytes=128 MiB`
  (`134_217_728`), `flush_interval_secs=900`, `channel_capacity=8_192`. **Syslog's own
  `SyslogLocalConfig`/`SyslogS3Config` defaults differ** (`src/config/mod.rs`):
  `max_buffer_rows=10_000` (`default_syslog_s3_max_rows`), `flush_interval_secs=900`
  (`default_syslog_s3_flush_interval_secs`), `channel_capacity=4_096`
  (`default_syslog_s3_channel_capacity`) — no independent `flush_threshold_bytes` override for
  syslog specifically, it uses the generic default. Cite whichever set is actually in effect
  when writing up results; do not conflate the two.
- **"Local disk not MinIO" methodology decision (design doc §6), verbatim reasoning:** "The whole
  point of separating ingestion-path perf from the sink is stated directly in the existing
  S3-outage tests... the buffering/flush/cap machinery is deliberately decoupled from upload
  success/failure via `try_send` + hard caps... A performance test that always writes to MinIO
  conflates 'how fast can this format be ingested and buffered' with 'how fast is this MinIO
  container, this Docker network hop, this AWS SDK client' — variables the ingestion path
  doesn't control." Every task in this plan uses `LocalDiskSink`, never MinIO/S3, for the
  baseline run. MinIO is reserved for a separate, narrower "S3 path doesn't fall over" sanity
  pass — **not** built by this plan (design doc §6's own scoping; still future work).
- **The `LocalDiskSink`-wiring blocker the design doc names is already resolved.** Its §2/§6
  state `LocalDiskSink` was only wired for Zeek at the time it was written. Per
  `2026-07-24-performance-improvements-plan.md` §0, this is now done for all 7 sources —
  confirmed directly: `grep -rn "fn.*_local_start\b" src/forwarding/*.rs` finds
  `hec_local_start`, `wef_local_start`, `syslog_local_start`, `ipfix_local_start`,
  `sflow_local_start`, `zeek_local_start`, `suricata_local_start`. **No task in this plan does
  any `.local` wiring work** — it is a prerequisite that is already satisfied.
- **Comparability methodology (design doc §7), binding for any future write-up building on this
  plan's baseline:** (1) group formats by architecture, not alphabetically; (2) report both
  "ingest accept rate" and "durable write rate" (`parquet_s3_records_written`), not one number;
  (3) normalize by payload bytes as well as record count where record size varies; (4) treat HEC
  vs OTLP as the built-in "control" comparison (same writer path, different decode cost); (5)
  **"Never compare absolute numbers across a run that changed `flush_threshold_bytes`/
  `max_buffer_rows`/`channel_capacity`"** — pin these to the same values (or explicitly document
  the deltas) across any results being compared. This rule applies to every future loadgen run
  built on top of this plan's `syslog-udp` baseline.
- **Where this lives (design doc §8):** a new, separately-invoked tier, not part of the
  unit/integration/e2e three-tier model and not run on every push by default (the loadgen suite;
  see Task 12 for the criterion cadence decision specifically, which this plan resolves
  differently from the design doc's original assumption — see Task 7).
- **Concrete first deliverable (design doc §9), the literal scope boundary for workstream B:**
  scaffold `tools/loadgen` with exactly one subcommand, `syslog-udp`; flags `--host`, `--port`
  (default 514), `--target-rate`, `--duration` (this plan uses `--duration-secs` for clap-derive
  clarity — noted as a naming deviation, see Task 9), `--structured`; a baseline run capturing
  `syslog_messages_received`/`syslog_parse_errors`/`syslog_oversized_lines`,
  `parquet_s3_records_written{source="syslog"}`/`parquet_s3_dropped{source="syslog"}` via
  `:9090/metrics`, and RSS/CPU sampled externally; then a methodology write-up "as the template
  the other 6 formats' generators follow." The other 6 subcommands are then "mechanical
  repetition of a proven pattern" — **explicitly not built by this plan** (see the Deferred
  section below).

---

## Workstream A: Criterion Baseline Benchmarks

### Task 1: Criterion benchmark — `SuricataSink::to_record_batch`

**Files:**
- Create: `benches/suricata_envelope_to_record_batch.rs`
- Modify: `Cargo.toml` (add `[[bench]]` entry)

**Interfaces:**
- Consumes: `logthing::forwarding::buffered_writer::ParquetSink` (existing trait, already `pub`),
  `logthing::forwarding::suricata_s3::SuricataSink` (existing, `pub struct SuricataSink;`,
  `type Record = SuricataRecord`), `logthing::suricata::SuricataRecord` (existing, fields
  `event_type: String`, `fields: serde_json::Value`, `received_at: DateTime<Utc>`),
  `logthing::suricata::schema::envelope_schema()` (existing `pub fn`, returns `Arc<Schema>`).
- Produces: a runnable `cargo bench --bench suricata_envelope_to_record_batch` baseline, no
  production code changes.

Verified against `src/forwarding/suricata_s3.rs:67-96` (the `impl ParquetSink for SuricataSink`
block: `to_record_batch` calls `map_envelope(record)` directly, unconditionally) and
`src/suricata/schema.rs:1-61` (`envelope_schema()`/`map_envelope()`, both `pub fn`). Suricata
uses one fixed envelope schema for every event type — no per-partition schema branching, unlike
sFlow (Task 2) — so this benchmark needs only one fixture, not two.

- [ ] **Step 1: Write the benchmark file**

Create `benches/suricata_envelope_to_record_batch.rs`:

```rust
//! Criterion micro-benchmark: baseline cost of `SuricataSink::to_record_batch`
//! (`map_envelope`) -- one call per ingested Suricata EVE JSON record. This is
//! the "before" measurement for any future amortized-builder work on the
//! Suricata adapter (see
//! `docs/superpowers/specs/2026-07-24-record-batch-amortization-design.md`
//! for the pattern already applied to Zeek's "conn" mapper), and a
//! regression-tracking baseline in its own right.
//!
//! Run with: `cargo bench --bench suricata_envelope_to_record_batch`

use chrono::Utc;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use logthing::forwarding::buffered_writer::ParquetSink;
use logthing::forwarding::suricata_s3::SuricataSink;
use logthing::suricata::SuricataRecord;
use logthing::suricata::schema::envelope_schema;
use std::hint::black_box;

fn make_alert_record() -> SuricataRecord {
    SuricataRecord {
        event_type: "alert".to_string(),
        fields: serde_json::json!({
            "event_type": "alert",
            "src_ip": "192.168.1.100",
            "dest_ip": "1.2.3.4",
            "src_port": 51820,
            "dest_port": 443,
            "proto": "TCP",
            "alert": {
                "signature": "ET POLICY Suspicious User-Agent",
                "category": "Attempted Information Leak",
                "severity": 2
            }
        }),
        received_at: Utc::now(),
    }
}

fn bench_suricata_envelope_construction(c: &mut Criterion) {
    let schema = envelope_schema();
    let sink = SuricataSink;
    let record = make_alert_record();

    let mut group = c.benchmark_group("suricata_envelope_record_construction");
    group.throughput(Throughput::Elements(1));
    group.bench_function("per_record_fresh_builders", |b| {
        b.iter(|| {
            let batch = sink
                .to_record_batch(black_box(&record), black_box(&schema))
                .unwrap();
            black_box(batch);
        });
    });
    group.finish();
}

criterion_group!(benches, bench_suricata_envelope_construction);
criterion_main!(benches);
```

- [ ] **Step 2: Register the bench target in `Cargo.toml`**

In `Cargo.toml`, immediately after the existing:

```toml
[[bench]]
name = "zeek_conn_batch_amortization"
harness = false
```

add:

```toml

[[bench]]
name = "suricata_envelope_to_record_batch"
harness = false
```

- [ ] **Step 3: Compile-check and run once**

Run: `CC=/usr/bin/gcc CXX=/usr/bin/g++ cargo bench --bench suricata_envelope_to_record_batch`
(the `CC`/`CXX` override is required in this dev environment because `~/.local/bin/cc` shims to
`zig cc`, which the `cc` crate's clang-style `--target=` flag confuses — see the
`build-cc-toolchain` project memory; not needed on a clean CI runner with a real system `gcc`).

Expected: compiles clean, prints one `suricata_envelope_record_construction/per_record_fresh_builders`
result with a `time:`/`thrpt:` line, no panics.

- [ ] **Step 4: Commit**

```bash
git add benches/suricata_envelope_to_record_batch.rs Cargo.toml
git commit -m "bench(suricata): add baseline to_record_batch criterion benchmark"
```

---

### Task 2: Criterion benchmark — `SflowSink::to_record_batch` (flow + counter)

**Files:**
- Create: `benches/sflow_to_record_batch.rs`
- Modify: `Cargo.toml`

**Interfaces:**
- Consumes: `ParquetSink`, `logthing::forwarding::sflow_s3::SflowSink` (`type Record =
  SflowRecord`, `schema(Option<&str>)` branches on partition — `Some("counter")` →
  `COUNTER_SCHEMA`, else → `FLOW_SCHEMA`, both private `LazyLock` statics — use the trait's own
  `sink.schema(partition)` method, not a private free function), `logthing::sflow::{SampleType,
  SflowRecord}` (existing, `SflowRecord` has 21 fields, see below).

Verified against `src/forwarding/sflow_s3.rs:1-160` and `src/sflow/mod.rs:1-53`. Unlike Suricata,
sFlow's `to_record_batch` dispatches on `record.sample_type` to one of two entirely separate
builder sets (`flow_to_record_batch`/`counter_to_record_batch`) writing to two different
schemas — this benchmark measures both, as two separate `bench_function` calls in the same
group, matching the existing `to_record_batch_flow_produces_correct_values`/
`to_record_batch_counter_produces_correct_values` test-naming convention already in
`src/forwarding/sflow_s3.rs`'s own test module.

- [ ] **Step 1: Write the benchmark file**

Create `benches/sflow_to_record_batch.rs`:

```rust
//! Criterion micro-benchmark: baseline cost of `SflowSink::to_record_batch`
//! for both sample kinds. Flow samples and counter samples use entirely
//! separate builder sets and separate partitions/schemas (see
//! `src/forwarding/sflow_s3.rs`'s `flow_to_record_batch`/
//! `counter_to_record_batch`), so both are benchmarked independently.
//!
//! Run with: `cargo bench --bench sflow_to_record_batch`

use chrono::Utc;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use logthing::forwarding::buffered_writer::ParquetSink;
use logthing::forwarding::sflow_s3::SflowSink;
use logthing::sflow::{SampleType, SflowRecord};
use std::hint::black_box;
use std::net::IpAddr;

fn make_flow_record() -> SflowRecord {
    SflowRecord {
        sample_type: SampleType::Flow,
        exporter: "10.0.0.1".parse::<IpAddr>().unwrap(),
        received_at: Utc::now(),
        src_addr: Some("10.1.2.3".parse().unwrap()),
        dst_addr: Some("10.4.5.6".parse().unwrap()),
        src_port: Some(51820),
        dst_port: Some(443),
        ip_protocol: Some(6),
        sampling_rate: Some(1000),
        input_ifindex: Some(1),
        output_ifindex: Some(2),
        if_index: None,
        if_type: None,
        if_speed: None,
        if_direction: None,
        if_in_octets: None,
        if_out_octets: None,
        if_in_ucast_pkts: None,
        if_out_ucast_pkts: None,
        if_in_errors: None,
        if_out_errors: None,
        extra: serde_json::json!([]),
    }
}

fn make_counter_record() -> SflowRecord {
    SflowRecord {
        sample_type: SampleType::Counter,
        exporter: "10.0.0.1".parse::<IpAddr>().unwrap(),
        received_at: Utc::now(),
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        ip_protocol: None,
        sampling_rate: None,
        input_ifindex: None,
        output_ifindex: None,
        if_index: Some(1),
        if_type: Some(6),
        if_speed: Some(1_000_000_000),
        if_direction: Some(1),
        if_in_octets: Some(123_456_789),
        if_out_octets: Some(987_654_321),
        if_in_ucast_pkts: Some(100_000),
        if_out_ucast_pkts: Some(90_000),
        if_in_errors: Some(0),
        if_out_errors: Some(0),
        extra: serde_json::json!([]),
    }
}

fn bench_sflow_record_construction(c: &mut Criterion) {
    let sink = SflowSink;
    let flow_schema = sink.schema(Some("flow"));
    let counter_schema = sink.schema(Some("counter"));
    let flow_record = make_flow_record();
    let counter_record = make_counter_record();

    let mut group = c.benchmark_group("sflow_record_construction");
    group.throughput(Throughput::Elements(1));

    group.bench_function("flow_sample", |b| {
        b.iter(|| {
            let batch = sink
                .to_record_batch(black_box(&flow_record), black_box(&flow_schema))
                .unwrap();
            black_box(batch);
        });
    });

    group.bench_function("counter_sample", |b| {
        b.iter(|| {
            let batch = sink
                .to_record_batch(black_box(&counter_record), black_box(&counter_schema))
                .unwrap();
            black_box(batch);
        });
    });

    group.finish();
}

criterion_group!(benches, bench_sflow_record_construction);
criterion_main!(benches);
```

- [ ] **Step 2: Register the bench target in `Cargo.toml`**

Add, after Task 1's entry:

```toml

[[bench]]
name = "sflow_to_record_batch"
harness = false
```

- [ ] **Step 3: Compile-check and run once**

Run: `CC=/usr/bin/gcc CXX=/usr/bin/g++ cargo bench --bench sflow_to_record_batch`
Expected: two results, `sflow_record_construction/flow_sample` and
`sflow_record_construction/counter_sample`.

- [ ] **Step 4: Commit**

```bash
git add benches/sflow_to_record_batch.rs Cargo.toml
git commit -m "bench(sflow): add baseline to_record_batch criterion benchmark"
```

---

### Task 3: Criterion benchmark — `IpfixSink::to_record_batch`

**Files:**
- Create: `benches/ipfix_flow_batch_to_record_batch.rs`
- Modify: `Cargo.toml`

**Interfaces:**
- Consumes: `ParquetSink`, `logthing::forwarding::ipfix_s3::IpfixSink` (`type Record =
  Vec<FlowRecord>` — **not** a single record; matches `IpfixHandler::handle_flows`'s batch API,
  `src/forwarding/ipfix_s3.rs:202-230`), `logthing::ipfix::FlowRecord` (17 fields, see below),
  `sink.schema(None)` (delegates to `flow_record_schema()`, a `pub fn`, usable directly too).

**Important shape difference from every other adapter in this plan:** because `IpfixSink::Record`
is already `Vec<FlowRecord>`, `to_record_batch` already loops over every flow in the vec with one
shared `FlowRecordBuilders` instance, appending each and finishing once
(`src/forwarding/ipfix_s3.rs:219-229`, delegating to `append_flow_record`/`finish_batch` at
`ipfix_s3.rs:114-192`) — i.e., IPFIX already does the amortized-builder pattern §2.1 of the
performance-improvements plan wants for the other 6 adapters, just scoped to "one IPFIX
datagram's worth of flows" rather than across pushes. This benchmark measures that per-datagram
cost at two representative batch sizes.

- [ ] **Step 1: Write the benchmark file**

Create `benches/ipfix_flow_batch_to_record_batch.rs`:

```rust
//! Criterion micro-benchmark: baseline cost of `IpfixSink::to_record_batch`.
//! Unlike the other `ParquetSink` adapters, IPFIX's `Record` type is
//! `Vec<FlowRecord>` (one push = one datagram's worth of flows, matching
//! `IpfixHandler::handle_flows`'s batch API) -- so `to_record_batch` already
//! amortizes builder allocation across every flow in one datagram. This
//! benchmark measures that per-datagram cost at two representative batch
//! sizes: a single-flow datagram and a 10-flow datagram.
//!
//! Run with: `cargo bench --bench ipfix_flow_batch_to_record_batch`

use chrono::Utc;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use logthing::forwarding::buffered_writer::ParquetSink;
use logthing::forwarding::ipfix_s3::IpfixSink;
use logthing::ipfix::FlowRecord;
use std::hint::black_box;
use std::net::IpAddr;

fn make_flow_record(i: usize) -> FlowRecord {
    FlowRecord {
        observation_domain_id: 1,
        template_id: 256,
        protocol_version: 10,
        exporter: "192.0.2.1".parse::<IpAddr>().unwrap(),
        export_time: Utc::now(),
        src_addr: Some(format!("10.0.{}.{}", i / 256, i % 256).parse().unwrap()),
        dst_addr: Some("10.1.0.1".parse().unwrap()),
        src_port: Some(1024 + (i as u16 % 1000)),
        dst_port: Some(443),
        ip_protocol: Some(6),
        octet_delta_count: Some(1500 + i as u64),
        packet_delta_count: Some(10 + i as u64),
        flow_start: Some(Utc::now()),
        flow_end: Some(Utc::now()),
        tcp_flags: Some(0x18),
        input_interface: Some(1),
        output_interface: Some(2),
        extra: serde_json::json!({"ie136": "0x00", "ie137": i}),
    }
}

fn bench_ipfix_batch_construction(c: &mut Criterion) {
    let sink = IpfixSink;
    let schema = sink.schema(None);

    let mut group = c.benchmark_group("ipfix_flow_batch_construction");

    for batch_size in [1usize, 10] {
        let flows: Vec<FlowRecord> = (0..batch_size).map(make_flow_record).collect();
        group.throughput(Throughput::Elements(batch_size as u64));
        group.bench_function(format!("datagram_of_{batch_size}_flows"), |b| {
            b.iter(|| {
                let batch = sink
                    .to_record_batch(black_box(&flows), black_box(&schema))
                    .unwrap();
                black_box(batch);
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_ipfix_batch_construction);
criterion_main!(benches);
```

- [ ] **Step 2: Register the bench target in `Cargo.toml`**

Add:

```toml

[[bench]]
name = "ipfix_flow_batch_to_record_batch"
harness = false
```

- [ ] **Step 3: Compile-check and run once**

Run: `CC=/usr/bin/gcc CXX=/usr/bin/g++ cargo bench --bench ipfix_flow_batch_to_record_batch`
Expected: two results, `datagram_of_1_flows` and `datagram_of_10_flows`, with `thrpt:` in
elements/sec scaling roughly linearly (proving the shared-builder amortization is already
working for this adapter).

- [ ] **Step 4: Commit**

```bash
git add benches/ipfix_flow_batch_to_record_batch.rs Cargo.toml
git commit -m "bench(ipfix): add baseline to_record_batch criterion benchmark"
```

---

### Task 4: Criterion benchmark — `SyslogSink::to_record_batch`

**Files:**
- Create: `benches/syslog_message_to_record_batch.rs`
- Modify: `Cargo.toml`

**Interfaces:**
- Consumes: `ParquetSink`, `logthing::forwarding::syslog_s3::SyslogSink` (`type Record =
  SyslogMessage`, `to_record_batch` delegates unconditionally to the `pub fn
  syslog_message_to_batch`, `src/forwarding/syslog_s3.rs:50-87`/`139-146`),
  `logthing::syslog::{SyslogMessage, SyslogProtocol}` (existing).

- [ ] **Step 1: Write the benchmark file**

Create `benches/syslog_message_to_record_batch.rs`:

```rust
//! Criterion micro-benchmark: baseline cost of `SyslogSink::to_record_batch`
//! (`syslog_message_to_batch`) -- one call per ingested syslog message.
//!
//! Run with: `cargo bench --bench syslog_message_to_record_batch`

use chrono::Utc;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use logthing::forwarding::buffered_writer::ParquetSink;
use logthing::forwarding::syslog_s3::SyslogSink;
use logthing::syslog::{SyslogMessage, SyslogProtocol};
use std::hint::black_box;

fn make_rfc5424_message() -> SyslogMessage {
    SyslogMessage {
        priority: 34,
        severity: 2,
        facility: 4,
        timestamp: Some(Utc::now()),
        hostname: Some("mymachine.example.com".to_string()),
        app_name: Some("su".to_string()),
        proc_id: Some("2001".to_string()),
        msg_id: Some("ID47".to_string()),
        message: "'su root' failed for lonvick on /dev/pts/8".to_string(),
        structured_data: None,
        protocol: SyslogProtocol::Rfc5424,
    }
}

fn bench_syslog_message_construction(c: &mut Criterion) {
    let sink = SyslogSink;
    let schema = sink.schema(None);
    let message = make_rfc5424_message();

    let mut group = c.benchmark_group("syslog_message_construction");
    group.throughput(Throughput::Elements(1));
    group.bench_function("per_record_fresh_arrays", |b| {
        b.iter(|| {
            let batch = sink
                .to_record_batch(black_box(&message), black_box(&schema))
                .unwrap();
            black_box(batch);
        });
    });
    group.finish();
}

criterion_group!(benches, bench_syslog_message_construction);
criterion_main!(benches);
```

- [ ] **Step 2: Register the bench target in `Cargo.toml`**

Add:

```toml

[[bench]]
name = "syslog_message_to_record_batch"
harness = false
```

- [ ] **Step 3: Compile-check and run once**

Run: `CC=/usr/bin/gcc CXX=/usr/bin/g++ cargo bench --bench syslog_message_to_record_batch`

- [ ] **Step 4: Commit**

```bash
git add benches/syslog_message_to_record_batch.rs Cargo.toml
git commit -m "bench(syslog): add baseline to_record_batch criterion benchmark"
```

---

### Task 5: Criterion benchmark — `GenericSink::to_record_batch` (HEC/OTLP shared path)

**Files:**
- Create: `benches/generic_hec_to_record_batch.rs`
- Modify: `Cargo.toml`

**Interfaces:**
- Consumes: `ParquetSink`, `logthing::forwarding::generic_s3::GenericSink` (`type Record =
  GenericRecord`, `src/forwarding/generic_s3.rs:43-104`; `schema()` delegates to a *private*
  `generic_schema()` free function — use `sink.schema(None)` via the trait, not the private fn),
  `logthing::ingest::GenericRecord` (`src/ingest/mod.rs:24-36`, fields `sourcetype: String`,
  `host: Option<String>`, `time: Option<DateTime<Utc>>`, `fields: serde_json::Value`,
  `received_at: DateTime<Utc>`).

This is the writer-path cost HEC and OTLP share (`src/server/otlp.rs`'s `map_otlp_request`
converts an OTLP request into `GenericRecord`s before they reach this exact sink) — per the
design doc §3/§7 point 4, any future OTLP-specific benchmark's delta from this one isolates
protobuf-decode cost, not writer-path cost. This benchmark captures the shared baseline both
would build on.

- [ ] **Step 1: Write the benchmark file**

Create `benches/generic_hec_to_record_batch.rs`:

```rust
//! Criterion micro-benchmark: baseline cost of `GenericSink::to_record_batch`
//! -- the shared writer path for both HEC and OTLP ingest (OTLP maps to
//! `GenericRecord` via `map_otlp_request` before reaching this sink; see
//! `docs/superpowers/specs/2026-07-05-performance-testing-strategy-design.md`
//! §3/§7 point 4 for why HEC vs OTLP is this codebase's built-in "control"
//! comparison -- this benchmark measures the writer-path cost they share).
//!
//! Run with: `cargo bench --bench generic_hec_to_record_batch`

use chrono::Utc;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use logthing::forwarding::buffered_writer::ParquetSink;
use logthing::forwarding::generic_s3::GenericSink;
use logthing::ingest::GenericRecord;
use std::hint::black_box;

fn make_hec_record() -> GenericRecord {
    GenericRecord {
        sourcetype: "access_log".to_string(),
        host: Some("web-01".to_string()),
        time: Some(Utc::now()),
        fields: serde_json::json!({
            "method": "GET",
            "path": "/api/v1/widgets",
            "status": 200,
            "bytes": 1834,
            "user_agent": "curl/8.4.0"
        }),
        received_at: Utc::now(),
    }
}

fn bench_generic_record_construction(c: &mut Criterion) {
    let sink = GenericSink;
    let schema = sink.schema(None);
    let record = make_hec_record();

    let mut group = c.benchmark_group("generic_hec_record_construction");
    group.throughput(Throughput::Elements(1));
    group.bench_function("per_record_fresh_arrays", |b| {
        b.iter(|| {
            let batch = sink
                .to_record_batch(black_box(&record), black_box(&schema))
                .unwrap();
            black_box(batch);
        });
    });
    group.finish();
}

criterion_group!(benches, bench_generic_record_construction);
criterion_main!(benches);
```

- [ ] **Step 2: Register the bench target in `Cargo.toml`**

Add:

```toml

[[bench]]
name = "generic_hec_to_record_batch"
harness = false
```

- [ ] **Step 3: Compile-check and run once**

Run: `CC=/usr/bin/gcc CXX=/usr/bin/g++ cargo bench --bench generic_hec_to_record_batch`

- [ ] **Step 4: Commit**

```bash
git add benches/generic_hec_to_record_batch.rs Cargo.toml
git commit -m "bench(hec): add baseline to_record_batch criterion benchmark (shared HEC/OTLP path)"
```

---

### Task 6: Criterion benchmark — `WefSink::to_record_batch`

**Files:**
- Create: `benches/wef_to_record_batch.rs`
- Modify: `Cargo.toml`

**Interfaces:**
- Consumes: `ParquetSink`, `logthing::forwarding::parquet_s3::WefSink` (`type Record =
  Arc<WindowsEvent>`, `src/forwarding/parquet_s3.rs:37-90`), `logthing::models::{EventLevel,
  ParsedEvent, WindowsEvent}` (`src/models/mod.rs`, all `pub`).

`WefSink::to_record_batch` returns `Err` (skip) for events with `parsed: None` — the benchmark
fixture must have `parsed: Some(..)` or every iteration would just measure the error path.

- [ ] **Step 1: Write the benchmark file**

Create `benches/wef_to_record_batch.rs`:

```rust
//! Criterion micro-benchmark: baseline cost of `WefSink::to_record_batch`.
//!
//! Run with: `cargo bench --bench wef_to_record_batch`

use chrono::Utc;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use logthing::forwarding::buffered_writer::ParquetSink;
use logthing::forwarding::parquet_s3::WefSink;
use logthing::models::{EventLevel, ParsedEvent, WindowsEvent};
use std::hint::black_box;
use std::sync::Arc;
use uuid::Uuid;

fn make_wef_event() -> Arc<WindowsEvent> {
    Arc::new(WindowsEvent {
        id: Uuid::new_v4(),
        received_at: Utc::now(),
        source_host: "workstation01.example.com".to_string(),
        subscription_id: Some("sub-001".to_string()),
        raw_xml: "<Event><System><EventID>4624</EventID></System></Event>".to_string(),
        parsed: Some(ParsedEvent {
            provider: "Microsoft-Windows-Security-Auditing".to_string(),
            event_id: 4624,
            level: EventLevel::Information,
            task: 12544,
            opcode: 0,
            keywords: 0x8020000000000000,
            time_created: Utc::now(),
            event_record_id: 123456,
            process_id: Some(544),
            thread_id: Some(892),
            channel: "Security".to_string(),
            computer: "workstation01.example.com".to_string(),
            security_user_id: Some("S-1-5-21-1234-5678-9012-1001".to_string()),
            message: Some("An account was successfully logged on.".to_string()),
            data: Some(serde_json::json!({"TargetUserName": "jdoe", "LogonType": 3})),
        }),
    })
}

fn bench_wef_record_construction(c: &mut Criterion) {
    let sink = WefSink;
    let schema = sink.schema(None);
    let event = make_wef_event();

    let mut group = c.benchmark_group("wef_record_construction");
    group.throughput(Throughput::Elements(1));
    group.bench_function("per_record_fresh_arrays", |b| {
        b.iter(|| {
            let batch = sink
                .to_record_batch(black_box(&event), black_box(&schema))
                .unwrap();
            black_box(batch);
        });
    });
    group.finish();
}

criterion_group!(benches, bench_wef_record_construction);
criterion_main!(benches);
```

- [ ] **Step 2: Register the bench target in `Cargo.toml`**

Add:

```toml

[[bench]]
name = "wef_to_record_batch"
harness = false
```

- [ ] **Step 3: Compile-check and run once**

Run: `CC=/usr/bin/gcc CXX=/usr/bin/g++ cargo bench --bench wef_to_record_batch`

- [ ] **Step 4: Commit**

```bash
git add benches/wef_to_record_batch.rs Cargo.toml
git commit -m "bench(wef): add baseline to_record_batch criterion benchmark"
```

---

### Task 7: Decide and wire criterion's CI cadence

**Files:**
- Modify: `.github/workflows/rust.yml` (compile-check step only — see decision below)
- Modify: `.github/workflows/performance.yml` (created in Task 12; this task's "full sampled
  run" step lands there)

**Interfaces:**
- Consumes: all 7 `[[bench]]` targets (the existing Zeek one plus Tasks 1-6's six new ones).
- Produces: a `cargo bench --no-run` step in the per-push job; a `cargo bench` (full run) step
  in the manually-triggered workflow.

**Decision, with evidence (per this plan's instruction to verify, not assume, that criterion is
"cheap enough to run on every push"):**

The design doc §8 speculates criterion is "cheap enough to run on every push" as an optional
sibling tier, reasoning from criterion's *execution* cost alone (µs-scale in-process function
calls). That reasoning is only half the picture for **this** repository specifically, because
`.github/workflows/rust.yml` has **no dependency caching** (no `Swatinem/rust-cache` or
`actions/cache` step) — every push already pays a full, uncached compile of the entire
dependency tree (`aws-sdk-s3`, `aws-lc-sys`/`aws-lc-rs`, `parquet`, `rustls`, `tokio`, `axum`,
etc.) for `cargo build` and again, in a different profile, for `cargo test`. `cargo bench`
requires yet another optimized-profile compile of that same dependency tree (criterion's `bench`
profile is not artifact-compatible with `cargo test`'s or `cargo build`'s profile directories),
which is not shared with either existing step.

Measured directly in this planning session (`CC=/usr/bin/gcc cargo bench --bench
zeek_conn_batch_amortization`, uncached, on this dev environment): the cold compile of the full
dependency tree for the `bench` profile took **several minutes** (still mid-compile of
`aws-sdk-s3`/`logthing` itself at the 90-second mark), and the *execution* phase for the existing
benchmark's 4 benchmark functions (1 per-record + 3 batch sizes, criterion's default 3s warm-up +
5s measurement each) took **~33 seconds on its own**. Extrapolating to all 7 `[[bench]]` targets
after this plan (roughly 10-12 benchmark functions total across Tasks 1-6, plus the existing 4),
a full sampled run's *execution* phase alone would add **roughly 2-3 minutes** to every push —
on top of a compile that, uncached, is not shared with the job's existing build/test steps.

**Decision: do not add a full `cargo bench` (sampled run) to `rust.yml`'s per-push job.**
Instead:

1. Add a **compile-only** `cargo bench --no-run` step to the existing `rust.yml` `build` job,
   immediately after the existing `Run tests` step. This step still requires its own
   `bench`-profile compile of the dependency tree (the caching gap above still applies to it),
   but it catches API/signature drift in the benchmark files themselves (e.g. a future
   `ParquetSink` trait signature change breaking `black_box(&record)` call sites) on every push,
   which is the main "regression-tracking-eligible" value the design doc's §8 was actually after
   for a per-push tier — without paying the sampled-execution cost.
2. Run the **full sampled** `cargo bench` (all 7 targets, real timing numbers) only inside the
   new manually-triggered `.github/workflows/performance.yml` (Task 12), alongside the loadgen
   baseline run.
3. **Revisit this decision** if/when `rust.yml` gains dependency caching (e.g.
   `Swatinem/rust-cache`) — with a cached dependency tree, the marginal cost of a full sampled
   `cargo bench` on every push would drop close to the ~2-3 minute execution-only figure above,
   which is a much easier case to make "cheap enough." That caching work is not part of this
   plan — it is a pre-existing gap in `rust.yml`, out of this plan's scope, noted here only
   because it is the reason this plan's cadence decision differs from the design doc's original
   assumption.

- [ ] **Step 1: Add the compile-only step to `rust.yml`**

In `.github/workflows/rust.yml`, inside the `build` job, immediately after the existing:

```yaml
    - name: Run tests
      run: cargo test --verbose
```

add:

```yaml

    - name: Compile-check criterion benchmarks (no execution)
      # Full sampled criterion runs are deliberately NOT run on every push --
      # see docs/superpowers/plans/2026-07-24-performance-testing-infrastructure.md
      # Task 7 for the measured-cost justification. This step only proves the
      # benchmark files still compile against the current ParquetSink trait
      # surface; actual timing runs live in the manually-triggered
      # performance.yml workflow.
      run: cargo bench --no-run --verbose
```

- [ ] **Step 2: Verify locally**

Run: `CC=/usr/bin/gcc CXX=/usr/bin/g++ cargo bench --no-run --verbose`
Expected: builds all 7 bench targets, executes none of them (no `Benchmarking ...` output), exits
0.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/rust.yml
git commit -m "ci: compile-check criterion benchmarks on every push, run them fully only on demand"
```

(The full-sampled-run wiring into `performance.yml` is Task 12, Step 3 — it depends on that
workflow file existing first.)

---

## Workstream B: `tools/loadgen` — Concrete First Deliverable

### Task 8: Scaffold the `tools/loadgen` crate

**Files:**
- Modify: `Cargo.toml` (add `[workspace]` with `tools/loadgen` as a member)
- Create: `tools/loadgen/Cargo.toml`
- Create: `tools/loadgen/src/main.rs`

**Interfaces:**
- Consumes: `logthing` as a path dependency (`{ path = "../.." }`) — the same "crate is both a
  library and a binary" fact `AGENTS.md` §6 already documents is what makes this possible without
  re-implementing wire-format encoders.
- Produces: `cargo run -p loadgen -- <subcommand>` runnable from the repo root; `Cli`/`Command`
  clap-derive scaffolding that Task 9 plugs `SyslogUdp` into.

**Why a workspace member (not a fully standalone sibling crate with its own `Cargo.lock`):** the
design doc §5's own runnable example (`cargo run -p loadgen -- syslog-udp ...`) uses `-p`, which
selects among workspace members — so this plan makes `tools/loadgen` a real workspace member,
with `default-members = ["."]` added specifically so that plain `cargo build`/`cargo test`/`cargo
clippy --all-targets` invocations at the repo root (exactly what `rust.yml` runs on every push)
continue to build/test **only** the `logthing` package, not `loadgen` too. Without
`default-members`, adding a `[workspace]` block would silently make every existing CI step build
`loadgen` as well, adding cost and a new failure surface to every push — that would be a scope
violation of this plan (loadgen is explicitly a manually-triggered concern, not a per-push one).

- [ ] **Step 1: Add `[workspace]` to the root `Cargo.toml`**

In `Cargo.toml`, immediately after the `[package]` block (before `[features]`), add:

```toml

[workspace]
members = ["tools/loadgen"]
# Plain `cargo build`/`cargo test`/`cargo clippy` at the repo root (what
# rust.yml runs on every push) must keep building/testing ONLY the logthing
# package -- tools/loadgen is a manually-invoked concern
# (docs/superpowers/plans/2026-07-24-performance-testing-infrastructure.md),
# not a per-push one.
default-members = ["."]
```

- [ ] **Step 2: Create `tools/loadgen/Cargo.toml`**

Create `tools/loadgen/Cargo.toml`:

```toml
[package]
name = "loadgen"
version = "0.1.0"
edition = "2024"
publish = false

[dependencies]
logthing = { path = "../.." }
tokio = { version = "1.35", features = ["full"] }
clap = { version = "4", features = ["derive"] }
chrono = { version = "0.4", features = ["serde"] }
anyhow = "1.0"
```

- [ ] **Step 3: Create `tools/loadgen/src/main.rs`**

Create `tools/loadgen/src/main.rs`:

```rust
//! `loadgen` -- wire-format load generator for a live `logthing` instance.
//!
//! Concrete first deliverable: exactly one subcommand, `syslog-udp` (see
//! `src/syslog_udp.rs`). The other 6 formats (ipfix, zeek, suricata, sflow,
//! hec, otlp) are deliberately not implemented yet -- see
//! `docs/superpowers/plans/2026-07-24-performance-testing-infrastructure.md`'s
//! "Deferred" section for what each would need.

mod syslog_udp;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "loadgen", about = "logthing wire-format load generator")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Send syslog messages over UDP at a paced rate.
    SyslogUdp(syslog_udp::SyslogUdpArgs),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::SyslogUdp(args) => syslog_udp::run(args).await,
    }
}
```

- [ ] **Step 4: Verify the workspace builds and the scaffold runs (will fail to find
      `syslog_udp` module until Task 9 — expected)**

Run: `CC=/usr/bin/gcc CXX=/usr/bin/g++ cargo build -p loadgen 2>&1 | tail -20`
Expected at this point: a compile error (`syslog_udp` module has no `SyslogUdpArgs`/`run` yet —
Task 9 creates that file). This is expected; do not treat it as a Task 8 failure. If the error is
instead about the workspace/path-dependency resolution itself (e.g. `logthing` not found), fix
that before proceeding to Task 9.

Also run, to confirm the `default-members` guard works: `CC=/usr/bin/gcc CXX=/usr/bin/g++ cargo
build 2>&1 | grep -c "Compiling loadgen"` — expected: `0` (plain `cargo build` at the repo root
must NOT attempt to compile `loadgen`).

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml tools/loadgen/Cargo.toml tools/loadgen/src/main.rs
git commit -m "feat(loadgen): scaffold tools/loadgen workspace crate (unwired subcommand)"
```

(This commit will not build in isolation — `syslog_udp` module is empty. That is acceptable for
an interim commit in this plan's sequencing since Task 9 lands immediately after; if the
implementer's workflow requires every commit to build standalone, merge Task 8 and Task 9's Step
1 into one commit instead.)

---

### Task 9: Implement the `syslog-udp` subcommand

**Files:**
- Create: `tools/loadgen/src/syslog_udp.rs`

**Interfaces:**
- Consumes: `tokio::net::UdpSocket` (same crate/API already used by
  `src/sflow/listener.rs`/`src/ipfix/listener.rs` — no new UDP crate introduced), the pacing
  pattern already established by `examples/flush_decoupling_benchmark.rs` (1ms-tick,
  N-per-tick batching — reused here rather than reinvented).
- Produces: `SyslogUdpArgs` (clap `Args`), `pub async fn run(args: SyslogUdpArgs) ->
  anyhow::Result<()>` — wired into `main.rs`'s `Command::SyslogUdp` arm from Task 8.

**Wire-format correctness (verified against `src/syslog/mod.rs`'s real parser, not assumed):**
the RFC3164 regex logthing's UDP listener matches every datagram against is `^<(\d{1,3})>
([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*?)$` (`RFC3164_RE`) followed by
`RFC3164_TAG_RE` = `^([^:\[]+)(?:\[(\d+)\])?:\s*(.*)$` applied to everything after the hostname.
Two consequences that shape this implementation:
1. **No trailing newline.** `.` does not match `\n` in the `regex` crate by default (no
   `(?s)` flag is set), so a trailing `\n` would make the whole `$`-anchored match fail. Each UDP
   datagram is exactly the message bytes, nothing appended — matches how
   `src/syslog/listener.rs`'s UDP arm treats one `recv_from` as one message already (no
   line-delimiter framing, unlike its TCP arm).
2. **`--structured` must produce a message body starting with `CEF:`.** `src/syslog/payload/
   cef.rs::try_parse` checks `msg.message.starts_with("CEF:")`, where `msg.message` is
   whatever comes after `tag[pid]: ` (or `tag: `) is stripped by `RFC3164_TAG_RE`. So the
   structured payload's wire text is `<PRI>TIMESTAMP HOSTNAME loadgen: CEF:0|...`, not just a
   bare `CEF:0|...` line — the `loadgen: ` tag prefix is required for the parser to isolate the
   CEF body into `message` at all.

- [ ] **Step 1: Write `tools/loadgen/src/syslog_udp.rs`**

Create `tools/loadgen/src/syslog_udp.rs`:

```rust
//! `loadgen syslog-udp` -- paced UDP syslog load generator.
//!
//! Encodes messages matching the two wire shapes `logthing`'s syslog parser
//! (`logthing::syslog::SyslogMessage::parse`, RFC3164 branch) actually
//! accepts:
//! - Raw (`--structured` off, default): a plain RFC3164 line with a free-text
//!   message body -- exercises header parsing only.
//! - Structured (`--structured` on): the RFC3164 message body is a CEF
//!   payload (`CEF:0|...`), which additionally exercises
//!   `logthing::syslog::payload::dispatch`'s sub-parser try-chain when the
//!   server has `parse_payloads=true` -- see
//!   `docs/superpowers/specs/2026-07-05-performance-testing-strategy-design.md`
//!   §3's note on this being the meaningfully heavier cost path.
//!
//! Each UDP datagram is exactly one message, with NO trailing newline: the
//! `regex` crate's `.` does not match `\n` by default, so a trailing
//! newline would make `logthing`'s `$`-anchored RFC3164 regex fail to
//! match the whole datagram.

use anyhow::Context;
use chrono::{Datelike, Timelike, Utc};
use clap::Args;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::MissedTickBehavior;

#[derive(Args, Debug)]
pub struct SyslogUdpArgs {
    /// Target host to send UDP syslog datagrams to.
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,

    /// Target UDP port. Matches `SyslogConfig`'s real default
    /// (`default_syslog_udp_port() -> 514`); override for a CI run bound to
    /// a non-privileged port.
    #[arg(long, default_value_t = 514)]
    pub port: u16,

    /// Target sustained rate, in records/sec. 0 means "unbounded" (send as
    /// fast as the socket will accept, no pacing).
    #[arg(long, default_value_t = 10_000)]
    pub target_rate: u64,

    /// How long to send for, in seconds.
    #[arg(long, default_value_t = 60)]
    pub duration_secs: u64,

    /// Send CEF-payload messages (exercises the `parse_payloads` sub-parser
    /// chain) instead of plain free-text RFC3164 messages.
    #[arg(long, default_value_t = false)]
    pub structured: bool,
}

pub async fn run(args: SyslogUdpArgs) -> anyhow::Result<()> {
    let target: SocketAddr = format!("{}:{}", args.host, args.port)
        .parse()
        .with_context(|| format!("invalid target address {}:{}", args.host, args.port))?;

    // Bind an ephemeral local UDP socket, then `connect` it to fix the peer
    // so sends use `send` instead of `send_to` -- one syscall's worth of
    // argument marshalling less per datagram at high rates. The server side
    // still sees each of these as an independent `recv_from` datagram
    // (UDP has no real "connection"), matching its existing listener
    // behavior exactly.
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .context("bind local UDP socket")?;
    socket
        .connect(target)
        .await
        .context("connect UDP socket to target")?;

    println!(
        "loadgen syslog-udp: sending to {target} at target_rate={} rec/s for {}s (structured={})",
        args.target_rate, args.duration_secs, args.structured
    );

    let duration = Duration::from_secs(args.duration_secs);
    let start = Instant::now();
    let mut sent: u64 = 0;

    if args.target_rate == 0 {
        // Unbounded: send as fast as the socket will accept.
        while start.elapsed() < duration {
            let msg = build_message(sent, args.structured);
            socket
                .send(msg.as_bytes())
                .await
                .context("send UDP datagram")?;
            sent += 1;
        }
    } else {
        // Paced: same 1ms-tick, N-per-tick pattern already established by
        // examples/flush_decoupling_benchmark.rs for TCP pacing -- ticks
        // faster than practical per-record timer resolution would allow,
        // batching multiple sends per tick instead of chasing unrealistic
        // per-record timer precision.
        let per_tick_interval = Duration::from_micros(1000);
        let mut records_per_tick =
            (args.target_rate as f64 * per_tick_interval.as_secs_f64()).round() as u64;
        if records_per_tick < 1 {
            records_per_tick = 1;
        }
        let mut ticker = tokio::time::interval(per_tick_interval);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Burst);

        'send_loop: loop {
            if start.elapsed() >= duration {
                break;
            }
            ticker.tick().await;
            for _ in 0..records_per_tick {
                if start.elapsed() >= duration {
                    break 'send_loop;
                }
                let msg = build_message(sent, args.structured);
                socket
                    .send(msg.as_bytes())
                    .await
                    .context("send UDP datagram")?;
                sent += 1;
            }
        }
    }

    let elapsed = start.elapsed();
    println!(
        "loadgen syslog-udp: sent {sent} datagrams in {:.3}s (achieved rate: {:.1} rec/s)",
        elapsed.as_secs_f64(),
        sent as f64 / elapsed.as_secs_f64()
    );

    Ok(())
}

/// Build one syslog message. No trailing newline (see module doc comment).
fn build_message(n: u64, structured: bool) -> String {
    let now = Utc::now();
    // RFC3164 timestamp: "Mon D HH:MM:SS" (day is NOT zero-padded --
    // RFC3164_TS_RE in logthing::syslog accepts 1-2 digit days either way).
    let timestamp = format!(
        "{} {} {:02}:{:02}:{:02}",
        month_abbrev(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    );
    let hostname = "loadgen-host";
    let pri = 134; // facility=16 (local0) * 8 + severity=6 (informational)

    if structured {
        format!(
            "<{pri}>{timestamp} {hostname} loadgen: CEF:0|Loadgen|SyntheticFirewall|1.0|100|\
             Synthetic Blocked Connection|5|src=10.0.{}.{} dst=10.1.0.1 spt={} dpt=443 cnt={n}",
            (n / 256) % 256,
            n % 256,
            1024 + (n % 60_000),
        )
    } else {
        format!(
            "<{pri}>{timestamp} {hostname} loadgen[{}]: synthetic load-test message #{n}",
            std::process::id(),
        )
    }
}

fn month_abbrev(m: u32) -> &'static str {
    const NAMES: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    NAMES[(m as usize).saturating_sub(1).min(11)]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression guard against silent wire-format drift: build a message
    /// with logthing's OWN `SyslogMessage::parse` (not a hand-rolled
    /// regex copy) and assert it round-trips. This is the cheapest possible
    /// proof that this subcommand's bytes are real, parser-accepted syslog.
    #[test]
    fn raw_message_parses_as_rfc3164() {
        let msg = build_message(42, false);
        let parsed = logthing::syslog::SyslogMessage::parse(&msg)
            .expect("raw loadgen message must parse as RFC3164");
        assert_eq!(parsed.hostname.as_deref(), Some("loadgen-host"));
        assert!(parsed.message.contains("synthetic load-test message #42"));
    }

    #[test]
    fn structured_message_parses_and_message_field_starts_with_cef() {
        let msg = build_message(7, true);
        let parsed = logthing::syslog::SyslogMessage::parse(&msg)
            .expect("structured loadgen message must parse as RFC3164");
        assert!(
            parsed.message.starts_with("CEF:"),
            "message field must start with CEF: for the cef sub-parser to match, got: {}",
            parsed.message
        );
    }
}
```

- [ ] **Step 2: Build and run the new unit tests**

Run: `CC=/usr/bin/gcc CXX=/usr/bin/g++ cargo test -p loadgen`
Expected: both `raw_message_parses_as_rfc3164` and
`structured_message_parses_and_message_field_starts_with_cef` pass — this is the load-bearing
proof that the wire bytes this subcommand sends are real, `logthing`-parser-accepted syslog, not
just plausible-looking text.

- [ ] **Step 3: Manual smoke test against a real, ephemeral UDP listener**

Run, in one terminal: `CC=/usr/bin/gcc CXX=/usr/bin/g++ cargo run -p loadgen -- syslog-udp --host
127.0.0.1 --port 15514 --target-rate 100 --duration-secs 3`
Run, in another terminal, before starting the first (any of `nc -u -l 15514`, or a throwaway
`socat -u UDP-RECVFROM:15514,fork -`, works to eyeball raw bytes arriving): confirm ~300 lines
arrive over 3 seconds and each looks like `<134>Jul 24 13:05:07 loadgen-host loadgen[1234]:
synthetic load-test message #N`.

- [ ] **Step 4: Commit**

```bash
git add tools/loadgen/src/syslog_udp.rs
git commit -m "feat(loadgen): implement syslog-udp subcommand (paced UDP sender)"
```

---

### Task 10: Baseline run against a real `logthing` instance

**Files:**
- Create: `tools/loadgen/ci/logthing-baseline.toml` (config file for the baseline run —
  local disk, not MinIO, per the Global Constraints)
- Create (after running): `docs/performance/2026-07-24-syslog-udp-baseline-results.md` (filled
  in with real captured numbers from Step 4 below — this step cannot be completed by writing
  this plan alone; it requires actually running the load and reading real metrics)

**Interfaces:**
- Consumes: `loadgen syslog-udp` (Task 9), a `logthing` binary built with `[profile.profiling]`
  (existing, unchanged — `Cargo.toml`'s `inherits = "release"`, `debug = true`), `:9090/metrics`
  (existing, `MetricsConfig`, enabled by default).
- Produces: `docs/performance/2026-07-24-syslog-udp-baseline-results.md`, the first real data
  point future format subcommands' results will be compared against (per the Global Constraints'
  "never compare across differing flush-threshold configs" rule — this doc must state the exact
  config used).

- [ ] **Step 1: Write the baseline config file**

Create `tools/loadgen/ci/logthing-baseline.toml`:

```toml
# Config for tools/loadgen's syslog-udp baseline run. Local disk, not MinIO,
# per docs/superpowers/specs/2026-07-05-performance-testing-strategy-design.md
# §6 -- isolates ingestion/buffering-path throughput from S3/network/Docker
# variables the design doc explicitly calls out as not what this measures.
#
# udp_port is 15514, NOT the real default 514: binding <1024 requires root,
# and this file is also used by the CI job in Task 12, whose runner does not
# have that privilege.
bind_address = "0.0.0.0:5985"

[tls]
enabled = false

[metrics]
enabled = true
port = 9090

[syslog]
enabled = true
udp_port = 15514
tcp_port = 15601
parse_payloads = true

[syslog.local]
directory = "/tmp/logthing-perf-local"
```

- [ ] **Step 2: Build `logthing` (profiling profile) and `loadgen` (release)**

Run:
```bash
CC=/usr/bin/gcc CXX=/usr/bin/g++ cargo build --profile profiling
CC=/usr/bin/gcc CXX=/usr/bin/g++ cargo build -p loadgen --release
```
Expected: `target/profiling/logthing` and `target/release/loadgen` both exist.

- [ ] **Step 3: Start `logthing` against the baseline config**

Run, from the repo root:
```bash
rm -rf /tmp/logthing-perf-local && mkdir -p /tmp/logthing-perf-local
cp tools/loadgen/ci/logthing-baseline.toml ./logthing.toml
./target/profiling/logthing &
echo $! > /tmp/logthing-baseline.pid
sleep 2
curl -sf http://127.0.0.1:9090/metrics > /dev/null || { echo "logthing did not come up"; exit 1; }
```
(`logthing.toml` at the repo root is a git-ignored/throwaway file for this manual run — do not
commit it. If a real `logthing.toml` already exists at the repo root for other purposes, copy it
aside first and restore it after this step.)

- [ ] **Step 4: Capture pre-run metrics, run the load, capture post-run metrics**

Run:
```bash
curl -s http://127.0.0.1:9090/metrics > /tmp/metrics-before.txt

./target/release/loadgen syslog-udp \
    --host 127.0.0.1 --port 15514 \
    --target-rate 10000 --duration-secs 60

sleep 3  # drain: let buffered writes flush before snapshotting
curl -s http://127.0.0.1:9090/metrics > /tmp/metrics-after.txt

ps -o pid,rss,pcpu,etime -p "$(cat /tmp/logthing-baseline.pid)" > /tmp/resource-usage.txt
```

Repeat once more at `--target-rate 50000` and once at `--target-rate 0` (unbounded), saving each
run's before/after metrics snapshots separately (`metrics-before-10k.txt`,
`metrics-after-10k.txt`, etc.) — the design doc §9's own sweep recommendation
(`--target-rate <sweep: 10k, 50k, 100k, unbounded>`); this plan uses 10k/50k/unbounded as a
reduced 3-point sweep rather than the full 4-point one, noted explicitly as a scope reduction
below.

- [ ] **Step 5: Stop `logthing`, restore any pre-existing `logthing.toml`**

```bash
kill "$(cat /tmp/logthing-baseline.pid)"
rm -f ./logthing.toml  # or restore the original if one was copied aside in Step 3
```

- [ ] **Step 6: Diff metrics and write the results doc**

For each of the three runs, diff `metrics-after-*.txt` against `metrics-before-*.txt` for the
counters named in the Global Constraints (`syslog_messages_received`, `syslog_parse_errors`,
`syslog_oversized_lines`, `parquet_s3_records_written{source="syslog",target="local"}`,
`parquet_s3_dropped{source="syslog",target="local"}`). Create
`docs/performance/2026-07-24-syslog-udp-baseline-results.md` containing:
- The exact commands run (Steps 2-4, verbatim) and the git commit hash this baseline was captured
  against.
- The config in effect (link to `tools/loadgen/ci/logthing-baseline.toml`, and explicitly restate
  the buffer-policy values from that config per the "never compare across differing
  flush-threshold configs" rule: `max_buffer_rows=10_000` (syslog's own default, not the generic
  100k), `flush_interval_secs=900`, `channel_capacity=4_096`, `flush_threshold_bytes=128 MiB`
  (generic default, no syslog-specific override)).
- The three runs' before/after metric deltas, `ps`-sampled RSS/CPU, and the achieved send rate
  `loadgen` itself reports.
- An honest read of the result: does `syslog_parse_errors` stay at 0 (proving the wire bytes are
  well-formed, corroborating Task 9's unit tests)? Does `parquet_s3_dropped` stay at 0 at 10k/sec
  (below the syslog `channel_capacity=4_096`'s likely absorption point) and what happens at
  unbounded? Do not overstate — if a run's numbers look like noise rather than a clear signal,
  say so.

- [ ] **Step 7: Commit**

```bash
git add tools/loadgen/ci/logthing-baseline.toml docs/performance/2026-07-24-syslog-udp-baseline-results.md
git commit -m "perf(loadgen): capture syslog-udp baseline run against local-disk LocalDiskSink"
```

**Scope note (explicit deviation from the design doc §9's literal 4-point sweep):** this task
specifies a 3-point sweep (10k / 50k / unbounded) instead of the design doc's stated
10k/50k/100k/unbounded. This is a reasonable reduction for a first-deliverable baseline (the gap
between 50k and 100k is unlikely to reveal a qualitatively different regime than 50k-vs-unbounded
already does) but is flagged here as a deviation rather than silently dropped — add a 100k run
too if the implementer's environment can sustain it and wants the literal 4-point sweep.

---

### Task 11: Methodology write-up template

**Files:**
- Create: `docs/performance/methodology-template.md`

**Interfaces:**
- Consumes: nothing (a template, not code).
- Produces: the document Task 10's results doc follows, and — per the design doc §9 Step 4 — "the
  template the other 6 formats' generators follow" once they're eventually implemented (see the
  Deferred section below).

- [ ] **Step 1: Write the template**

Create `docs/performance/methodology-template.md`:

```markdown
# `loadgen <subcommand>` Baseline Methodology Template

Copy this file to `docs/performance/<date>-<format>-baseline-results.md` when capturing a new
baseline run, and fill in every section. Do not omit a section — write "not applicable, because
X" rather than deleting it, so future readers can tell "not measured" from "measured as zero."

## 1. What was run

- **Format / subcommand:** e.g. `loadgen syslog-udp`
- **Git commit hash** (of `logthing`, at the time of the run):
- **`logthing` build profile:** `[profile.profiling]` (default for perf runs — real optimized
  code, `debug=true` for later `perf`/flamegraph correlation if needed)
- **Persistence target:** `LocalDiskSink` (default per
  `docs/superpowers/specs/2026-07-05-performance-testing-strategy-design.md` §6 — do not use
  MinIO/S3 for throughput/latency/drop-rate numbers; MinIO is reserved for a separate, narrower
  sanity pass)
- **Exact config file used** (paste the whole file, or link to it if checked in)
- **Buffer-policy values in effect** (per the "never compare across differing flush-threshold
  configs" rule — restate these explicitly every time, even if unchanged from a prior run):
  `max_buffer_rows`, `flush_threshold_bytes`, `flush_interval_secs`, `channel_capacity`
- **Exact commands run** (verbatim, including every flag)

## 2. Goals & metrics captured

Per the design doc §4 — for each rate point in the sweep, capture:

| Metric | Source | Value (before) | Value (after) | Delta / rate |
|---|---|---:|---:|---:|
| Ingest accept rate | `<format>_messages_received` or equivalent, `:9090/metrics` | | | |
| Durable write rate | `parquet_s3_records_written{source,target}` | | | |
| Channel-full drops | `parquet_s3_dropped{source,target}` | | | |
| Hard-cap drops | `parquet_s3_buffer_dropped{source,target}` | | | |
| Partition-cap hits | `parquet_s3_partitions_capped{source,target}` | | | |
| Parse/decode errors | format-specific, e.g. `syslog_parse_errors` | | | |

- **Ingest→flush latency:** not directly instrumented server-side (per design doc §4 point 3) —
  either measured externally (sequence-number-in-record, diffed against Parquet-file read-back
  timestamp) or explicitly marked "not measured this run."
- **Resource usage:** RSS/CPU sampled via `ps -o pid,rss,pcpu,etime -p <pid>` (or `cargo
  flamegraph --profile profiling` for CPU-by-function, if a flamegraph was captured).

## 3. Comparability notes

Per the design doc §7 — if this run is being compared against another format's baseline:
- Same architecture group? (single-partition non-JSON / high-cardinality JSON-line /
  HTTP-JSON shared-writer-path / UDP binary low-cardinality)
- Same buffer-policy config? If not, say so explicitly rather than presenting a bare
  records/sec comparison.
- Both "accept rate" and "durable write rate" reported, not just one?
- Normalized by bytes as well as record count, if record sizes differ meaningfully?

## 4. Results

(Table or prose, one row/paragraph per rate point in the sweep.)

## 5. Honest read

State plainly whether the result shows a clear signal or is within noise/measurement error. Do
not round up a marginal or ambiguous result into a confident claim.
```

- [ ] **Step 2: Commit**

```bash
git add docs/performance/methodology-template.md
git commit -m "docs(perf): add methodology write-up template for loadgen baseline runs"
```

---

### Task 12: Manually-triggered `.github/workflows/performance.yml`

**Files:**
- Create: `.github/workflows/performance.yml`

**Interfaces:**
- Consumes: all 7 `[[bench]]` targets (Task 7's full-sampled-run decision lands here), `loadgen
  syslog-udp` (Task 9), `tools/loadgen/ci/logthing-baseline.toml` (Task 10).
- Produces: a `workflow_dispatch`-triggered CI workflow, mirroring `.github/workflows/binaries.yml`'s
  existing `workflow_dispatch` pattern (the only other workflow with one) exactly, per the design
  doc §8's explicit instruction.

- [ ] **Step 1: Read `binaries.yml` for the pattern being mirrored**

Already confirmed in this plan's own research: `binaries.yml` uses a bare `workflow_dispatch:`
(no inputs) under `on:`, `permissions: contents: write` (not needed here — this workflow doesn't
create releases), `runs-on: ubuntu-latest`, `dtolnay/rust-toolchain@stable` for the toolchain
step. This task reuses the toolchain-install pattern, adds `workflow_dispatch` inputs (unlike
`binaries.yml`, which has none) because a perf run has meaningful per-invocation parameters
(target rate, duration) that a release build does not.

- [ ] **Step 2: Write `.github/workflows/performance.yml`**

Create `.github/workflows/performance.yml`:

```yaml
name: Performance

# Manually-triggered performance-testing tier, deliberately separate from
# rust.yml's per-push job -- see
# docs/superpowers/specs/2026-07-05-performance-testing-strategy-design.md §8
# and docs/superpowers/plans/2026-07-24-performance-testing-infrastructure.md
# Task 7/12: sustained load runs and full-sampled criterion benchmarks cost
# minutes, not seconds, and measure throughput/latency/resource-usage, not
# pass/fail correctness -- a different signal than what runs on every push.
# Mirrors binaries.yml's workflow_dispatch pattern (the only other workflow
# with one).
on:
  workflow_dispatch:
    inputs:
      target_rate:
        description: 'loadgen syslog-udp target rate (records/sec, 0 = unbounded)'
        required: false
        default: '10000'
      duration_secs:
        description: 'loadgen syslog-udp run duration (seconds)'
        required: false
        default: '60'

env:
  CC: /usr/bin/gcc
  CXX: /usr/bin/g++

jobs:
  criterion:
    name: Criterion benchmarks (full sampled run)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install stable Rust toolchain
        uses: dtolnay/rust-toolchain@stable

      - name: Run all criterion benchmarks
        run: cargo bench

  syslog-udp-baseline:
    name: loadgen syslog-udp baseline run
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install stable Rust toolchain
        uses: dtolnay/rust-toolchain@stable

      - name: Build logthing (profiling profile)
        run: cargo build --profile profiling

      - name: Build loadgen (release)
        run: cargo build -p loadgen --release

      - name: Start logthing against the baseline config
        run: |
          mkdir -p /tmp/logthing-perf-local
          cp tools/loadgen/ci/logthing-baseline.toml ./logthing.toml
          ./target/profiling/logthing &
          echo $! > logthing.pid
          for i in $(seq 1 20); do
            curl -sf http://127.0.0.1:9090/metrics > /dev/null && break
            sleep 0.5
          done
          curl -sf http://127.0.0.1:9090/metrics > /dev/null || { echo "logthing did not come up"; exit 1; }

      - name: Capture pre-run metrics
        run: curl -s http://127.0.0.1:9090/metrics > metrics-before.txt

      - name: Run loadgen syslog-udp
        run: |
          ./target/release/loadgen syslog-udp \
            --host 127.0.0.1 --port 15514 \
            --target-rate ${{ github.event.inputs.target_rate }} \
            --duration-secs ${{ github.event.inputs.duration_secs }}

      - name: Drain and capture post-run metrics
        run: |
          sleep 3
          curl -s http://127.0.0.1:9090/metrics > metrics-after.txt

      - name: Sample resource usage
        run: ps -o pid,rss,pcpu,etime -p "$(cat logthing.pid)" > resource-usage.txt

      - name: Stop logthing
        if: always()
        run: kill "$(cat logthing.pid)" || true

      - name: Upload results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: syslog-udp-baseline-results
          path: |
            metrics-before.txt
            metrics-after.txt
            resource-usage.txt
```

- [ ] **Step 3: Validate the workflow syntax**

Run (if `actionlint` or a similar local validator is available; otherwise skip to Step 4 and let
a `workflow_dispatch` dry-run on GitHub be the validation): `actionlint .github/workflows/performance.yml`

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/performance.yml
git commit -m "ci: add manually-triggered performance.yml (criterion full run + loadgen syslog-udp baseline)"
```

- [ ] **Step 5: (Post-merge, not part of this plan's local verification) Trigger a real
      `workflow_dispatch` run on GitHub and confirm both jobs succeed.** This step requires a
      pushed branch and repository UI/CLI access this plan's authoring session does not have —
      note it as the final acceptance check for whoever merges this work.

---

## Deferred: the Remaining 6 `loadgen` Format Subcommands

Per the design doc §9's own explicit instruction — "don't build all 7 format generators before
learning anything... adding [the remaining] subcommands to the same `loadgen` binary is
mechanical repetition of a proven pattern" — this plan does **not** implement code-level detail
for `ipfix`, `zeek`, `suricata`, `sflow`, `hec`, or `otlp`. What follows is what each would need,
matching the design doc §3's format-inventory table, so a future session has a running start.

- **`loadgen ipfix`** — UDP, default port `4739` (`IpfixConfig::udp_port`). Needs a real IPFIX v10
  template-then-data datagram encoder — unlike syslog-udp's plain-text lines, this is binary
  TLV-encoded with a stateful template negotiation step (send a Template Set once, then Data Sets
  referencing that template ID). `tests/e2e/simulation-environment/ipfix-generator/entrypoint.py`
  is cited by the design doc §2 as a *reference* for the byte layout (hand-built via raw
  `socket`/`struct` in Python) — port that layout to Rust rather than re-deriving it from the
  IPFIX RFC from scratch. Single partition (`max_partitions=1`), so this is a good
  apples-to-apples pairing against `syslog-udp` for the "single-partition, non-JSON" comparison
  group (design doc §7 point 1). Cost profile: template-cache-lookup-dominated per the design
  doc's cost table — a `--template-churn-rate` flag (how often to send a new/changed template) is
  likely worth adding, since the design doc §4/`2026-07-24-performance-improvements-plan.md` §4
  both flag IPFIX template-cache cost as unmeasured and worth a dedicated stress case.
- **`loadgen zeek`** — TCP NDJSON, default port `47760` (`ZeekConfig::tcp_port`). Needs a
  persistent TCP connection (unlike UDP's connectionless sends) and one JSON line per record with
  a `_path` field driving `logthing`'s 256-way partition registry (`DEFAULT_MAX_ZEEK_PARTITIONS`).
  A `--partition-cardinality` flag (per design doc §5's shared-flags list) is important here
  specifically — this is the format the design doc §4 point 5 names as the one to deliberately
  stress `_overflow`/partition-cap behavior on, by generating more distinct `_path` values than
  256. `examples/flush_decoupling_benchmark.rs` already contains a working, reusable pattern for
  "open a real TCP connection to a real `ZeekListener`, paced NDJSON line writes" — that pacing
  loop (not the whole example, just its TCP-connect + ticker-paced `write_all` loop) is the
  closest existing prior art for this subcommand's core loop, more so than `syslog-udp`'s
  UDP-specific one.
- **`loadgen suricata`** — TCP EVE JSON, default port `47761` (`SuricataConfig::tcp_port`). Same
  TCP/NDJSON shape as `zeek`, partitioned by `event_type` instead of `_path`, same 256-partition
  cap (`DEFAULT_MAX_SURICATA_PARTITIONS`). Once `zeek` exists, this is close to a copy with a
  different field-name generator — the design doc §7 point 1 groups these two together as the
  "fairest high-cardinality comparison" specifically because they share this shape.
  `sanitize_event_type` (`src/forwarding/suricata_s3.rs`) is worth reading before choosing
  synthetic `event_type` values, so generated partitions match real sanitization behavior.
- **`loadgen sflow`** — UDP, default port `6343` (`SflowConfig::udp_port`). Binary sFlow v5
  encoding (flow samples and counter samples are structurally different — see Task 2's benchmark
  fixtures above for the field shapes each needs), but *not* high-cardinality (fixed 2-partition
  "flow"/"counter" split) — the design doc §7 point 1 calls this out as the deliberate "UDP,
  low-cardinality" contrast point against IPFIX (UDP, also low-cardinality but binary-TLV rather
  than binary-fixed-format) and against Zeek/Suricata (high-cardinality but TCP). A `--sample-mix`
  flag (ratio of flow vs. counter samples sent) would be a natural addition, since real sFlow
  deployments send both continuously at different rates.
- **`loadgen hec`** — HTTP, routes `/services/collector/event`, `/services/collector/raw`,
  `/ingest` on the main listener (default `bind_address` `0.0.0.0:5985`, gated by
  `HecConfig.enabled`). Needs an HTTP client (the design doc §5 reasoning against Python for UDP
  floods does not apply here — HTTP request/response is not syscall-bound the same way, but a
  Rust client is still preferable for consistency with the rest of `loadgen`; `reqwest` is
  already a `logthing` dependency and reusable). Partition key is `sourcetype`
  (`max_sourcetype_partitions`, default 64, **operator-configurable** — unlike Zeek/Suricata's
  hardcoded 256, this makes HEC the more *realistic* partition-cardinality stress case per design
  doc §4 point 5, not just an abuse test). A `--cardinality-sweep` flag generating N distinct
  `sourcetype` values is the natural stress axis here.
- **`loadgen otlp`** — HTTP, route `/v1/logs` (feature-gated by the `otlp` Cargo feature, on by
  default; `OtlpConfig.enabled`). Needs the `opentelemetry-proto`/`prost`-generated protobuf
  message types (already a `logthing` dependency, feature `otlp`) to build real
  `ExportLogsServiceRequest` bodies — this is meaningfully more setup than any other subcommand
  since it requires understanding the OTLP logs protobuf schema, not just a flat record shape.
  **This is the one subcommand where building `hec` first is a hard prerequisite, not just
  convenient sequencing**: per design doc §7 point 4, HEC and OTLP share `GenericSink`'s exact
  writer path (`map_otlp_request` converts OTLP → `GenericRecord` before either reaches the sink
  Task 5's benchmark covers) — running both against the same buffer-policy config is what makes
  their throughput delta a clean isolation of protobuf-decode cost specifically. Building `otlp`
  without `hec` already having a baseline would waste that built-in control comparison.

None of the above is scoped to task/step granularity — per the design doc's own philosophy, that
scoping should happen once `syslog-udp`'s pattern (Tasks 8-11) has actually run once and proven
itself, not speculatively now.

---

## Self-Review Notes

- **Spec coverage — design doc (`2026-07-05-performance-testing-strategy-design.md`) sections
  mapped:**
  - §2 ("what exists today") — the `LocalDiskSink`-wiring blocker it names is confirmed resolved
    in the Global Constraints (no task re-does it); its MinIO/docker-compose and
    `[profile.profiling]` assets are reused as-is in Task 10/12, not rebuilt.
  - §3 (format inventory / cost profiles) — directly cited in the Deferred section's per-format
    breakdown and in Task 9's `--structured` flag rationale (the `parse_payloads` cost delta).
  - §4 (goals & metrics) — every named metric appears verbatim in the Global Constraints and
    Task 10/11's capture steps; the "ingest→flush latency: not directly instrumented, measure
    externally or mark not-measured" point is carried into Task 11's template §2 explicitly.
  - §5 (load-generation approach: Rust not Python, not criterion alone) — is the premise of
    Workstream B entirely; the "criterion should be a separate follow-on tier" half of §5 is
    Workstream A.
  - §6 (local disk vs MinIO) — Global Constraints + Task 10's config file are both explicit that
    MinIO is out of scope for this plan's baseline; not silently dropped, called out as
    still-future work.
  - §7 (comparability methodology) — reproduced verbatim in the Global Constraints and again in
    Task 11's template §3, since it's binding for every future run built on this plan's baseline,
    not just this plan's own Task 10 run.
  - §8 (where this lives) — Task 7's CI-cadence decision directly engages with and revises this
    section's "cheap enough to run on every push" claim, with cited evidence for the revision;
    Task 12 mirrors its `workflow_dispatch`/separate-workflow recommendation exactly.
  - §9 (concrete first deliverable) — Tasks 8-11 implement its 4 numbered steps directly; the
    "then the other 6 are mechanical repetition" closing line is why the Deferred section exists
    instead of 6 more implementation tasks.
- **Spec coverage — improvements plan (`2026-07-24-performance-improvements-plan.md`) §2.6:**
  its "criterion first, before scoping §2.1's redesign" sequencing note is Workstream A's whole
  rationale; its "full `tools/loadgen` crate... not blocking anything, proceed independently"
  note is why Workstream B is planned as a fully separate, parallel-doable set of tasks rather
  than gated behind Workstream A.
- **Placeholder scan:** every task's benchmark/CLI/config/workflow file above is complete,
  compilable-as-written code — no `// TODO`, no "similar to Task N" standing in for real content,
  no "add appropriate error handling" hand-waves. The one place this plan cannot produce real
  content is Task 10's results doc body (Step 6) — that requires actually running a live load
  test, which is outside what a plan-writing session can do; the task gives the exact commands
  and the exact document structure (via Task 11's template) so the numbers are the only missing
  piece, not the methodology.
- **Type/name consistency:** `SuricataSink`/`SflowSink`/`IpfixSink`/`SyslogSink`/`GenericSink`/
  `WefSink` and their `Record` associated types (`SuricataRecord`, `SflowRecord`,
  `Vec<FlowRecord>`, `SyslogMessage`, `GenericRecord`, `Arc<WindowsEvent>`) are used identically
  in each of Tasks 1-6 and match what was verified directly in each adapter's source file (cited
  inline in each task's Interfaces block) — none were guessed. `SyslogUdpArgs`/`run` (Task 9) is
  the exact shape `main.rs`'s `Command::SyslogUdp` arm (Task 8) expects. `logthing-baseline.toml`
  (Task 10) and `performance.yml` (Task 12) agree on port `15514` and the `/tmp/logthing-perf-local`
  directory.
- **Accuracy check on the 6 sinks' actual signatures (per the task brief's explicit ask to verify,
  not guess):** all 6 were read in full before writing their benchmark fixtures. One genuine
  surprise worth flagging: `IpfixSink::Record` is `Vec<FlowRecord>`, not a single `FlowRecord` —
  unlike every other adapter in this plan. This is called out explicitly in Task 3 rather than
  silently normalized away, because it means IPFIX's `to_record_batch` already does the
  amortized-builder pattern (per-datagram) that §2.1 of the improvements plan wants for the other
  adapters — a fact worth knowing before anyone scopes §2.1's redesign using this plan's
  benchmarks as "before" numbers. `GenericSink::schema()`/`WefSink::schema()` delegate to
  *private* free functions (`generic_schema()` has no `pub` equivalent) — the benchmarks call
  `sink.schema(None)` via the trait instead of assuming a public free function exists, verified
  per-file rather than copy-pasted from the Zeek bench's `conn_schema()` pattern.
- **CI-cadence decision is evidence-based, not assumed:** Task 7 cites a real, measured compile
  and execution time from this planning session's own environment (several minutes cold-compile,
  ~33s execution for the existing bench's 4 functions) rather than accepting the design doc §8's
  "cheap enough to run on every push" claim at face value — and explains precisely why this
  repo's specific CI setup (no dependency caching in `rust.yml`) changes that calculus, with a
  concrete condition (`rust-cache` added) under which the decision should be revisited.

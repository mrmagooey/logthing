# IPFIX → S3 Persistence (Phase 4) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or
> superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`)
> syntax for tracking.

**Goal:** Implement `IpfixS3Writer` and `IpfixS3Handler` so that decoded `FlowRecord` batches are
buffered, encoded to Parquet (fixed common-fields schema), and uploaded to S3 via `S3Sink` under an
IPFIX-specific key prefix, with per-source config, bounded-channel backpressure, and full metrics.

**Architecture:** `IpfixS3Handler` receives `Vec<FlowRecord>` from the IPFIX listener via the
`IpfixHandler` trait and sends them into a bounded `tokio::sync::mpsc` channel owned by a
background `IpfixS3Writer` task; the writer accumulates records in an in-memory buffer, encodes
them to Parquet using a fixed Arrow `Schema` when a size or time threshold is crossed, and calls
`S3Sink::upload` with an `ipfix/year=Y/month=M/day=D/<uuid>.parquet` key. The `IpfixS3Config`
block mirrors the syslog S3 config introduced in Phase 3 and is absent-means-disabled for backward
compatibility.

**Tech Stack:** `arrow`/`arrow-array`/`arrow-schema` 53.x, `parquet` 53.x (ArrowWriter + ZSTD
compression), `tokio::sync::mpsc` (bounded channel), `metrics` 0.22 crate, `anyhow`/`thiserror`,
`chrono` 0.4, `serde_json` (for the `extra` column), `async-trait` 0.1, `uuid` 1.x.

## Global Constraints

- Rust edition 2024; max line width 100 columns; 4-space indentation.
- `cargo fmt` and `cargo clippy -- -D warnings` must pass after every task.
- Error handling: `anyhow::Result` in library code; `thiserror`-derived types for domain errors
  where callers need to match on variant.
- All tests live in `#[cfg(test)]` modules inside the source file they test, except integration
  tests in `src/forwarding/ipfix_s3.rs` (can use `#[tokio::test]` in `#[cfg(test)]`).
- Metrics via the `metrics` crate (`metrics::counter!`, `metrics::gauge!`); no direct Prometheus
  calls.
- Bounded channels: on overflow, drop the batch and increment `ipfix_s3_dropped`; never block the
  listener.
- Backward-compatible config: absent `[ipfix.s3]` section → no S3 persistence; existing behaviour
  unchanged.
- Fixed common-fields schema is mandated. Per-template dynamic schemas are explicitly out of scope.
- Conventional commits (`feat:`, `fix:`, `refactor:`, `test:`, `chore:`).
- **DEPENDS ON:** Phase 1 `FlowRecord` and `IpfixHandler` (in `src/ipfix/`); Phase 2 `S3Sink` (in
  `src/forwarding/s3_sink.rs`). Treat these as fixed contracts. Minor name differences (e.g.
  `ipfix::mod` vs `ipfix::types`) must be reconciled against the real Phase 1/2 output before
  starting implementation.

---

## Task 1 — FlowRecord → Arrow Schema and Row Mapping

**Files:**
- Create: `src/forwarding/ipfix_s3.rs` (schema + row-mapping sections only)

**Interfaces:**

Produces (in `src/forwarding/ipfix_s3.rs`):
```rust
/// Build the fixed Arrow Schema for FlowRecord. Called once at writer construction.
pub fn flow_record_schema() -> Arc<Schema>;

/// Append one FlowRecord to the provided mutable column builders.
/// Returns Err if a builder type mismatch is detected (logic error, not attacker input).
pub fn append_flow_record(builders: &mut FlowRecordBuilders, record: &FlowRecord)
    -> anyhow::Result<()>;

/// Consume builders and produce a RecordBatch.
pub fn finish_batch(builders: FlowRecordBuilders, schema: Arc<Schema>)
    -> anyhow::Result<RecordBatch>;

/// Mutable column builders for one Parquet row group.
pub struct FlowRecordBuilders { /* private fields */ }
impl FlowRecordBuilders {
    pub fn new() -> Self;
    pub fn len(&self) -> usize;   // number of rows appended so far
    pub fn is_empty(&self) -> bool;
}
```

Consumes: `FlowRecord` (from `crate::ipfix`); `Arc<Schema>`, `RecordBatch` from `arrow`.

**Column layout (exact Arrow types):**

| Column name | Arrow type | Nullable | Notes |
|---|---|---|---|
| `observation_domain_id` | `UInt32` | false | always present |
| `template_id` | `UInt16` | false | always present |
| `protocol_version` | `UInt8` | false | always present |
| `exporter` | `Utf8` | false | `IpAddr::to_string()` |
| `export_time` | `Utf8` | false | `DateTime<Utc>::to_rfc3339()` |
| `src_addr` | `Utf8` | true | `Option<IpAddr>` |
| `dst_addr` | `Utf8` | true | `Option<IpAddr>` |
| `src_port` | `UInt16` | true | |
| `dst_port` | `UInt16` | true | |
| `ip_protocol` | `UInt8` | true | |
| `octet_delta_count` | `UInt64` | true | |
| `packet_delta_count` | `UInt64` | true | |
| `flow_start` | `Utf8` | true | rfc3339 or null |
| `flow_end` | `Utf8` | true | rfc3339 or null |
| `tcp_flags` | `UInt8` | true | |
| `input_interface` | `UInt32` | true | |
| `output_interface` | `UInt32` | true | |
| `extra` | `Utf8` | false | `serde_json::to_string(&record.extra)` |

**TDD Steps:**

- [ ] **1.1 — Failing test: schema shape**
  Write a `#[test]` called `schema_has_correct_fields_and_types` in a `#[cfg(test)]` block inside
  `src/forwarding/ipfix_s3.rs`. The file contains only the test (and the minimal imports needed to
  compile it). The test calls `flow_record_schema()` (which does not exist yet), collects field
  names and nullability, and asserts all 18 columns above are present with correct types and
  nullability.
  ```
  cargo test -p logthing forwarding::ipfix_s3::tests::schema_has_correct_fields_and_types 2>&1 | head -20
  ```
  Expected: compile error (`flow_record_schema` not found). Commit message: `test(ipfix-s3): add
  failing schema shape test`.

- [ ] **1.2 — Implement `flow_record_schema()`**
  Add `FlowRecordBuilders`, `flow_record_schema()`, `append_flow_record()`, and `finish_batch()` to
  `src/forwarding/ipfix_s3.rs`. Use `arrow::array` builder types:
  - Non-nullable scalars: `UInt32Builder`, `UInt16Builder`, `UInt8Builder`, `UInt64Builder`.
  - Nullable scalars: same builders; `append_null()` on `None`.
  - `Utf8` columns: `StringBuilder`.
  - `extra`: serialize with `serde_json::to_string(&record.extra).unwrap_or_else(|_| "{}".to_string())`.
  Run:
  ```
  cargo test -p logthing forwarding::ipfix_s3::tests::schema_has_correct_fields_and_types 2>&1
  ```
  Expected: green. Also run `cargo clippy -p logthing -- -D warnings`. Commit: `feat(ipfix-s3):
  implement FlowRecord Arrow schema and column builders`.

- [ ] **1.3 — Failing test: row mapping round-trip**
  Add test `append_and_finish_produces_correct_columns`. Build a `FlowRecord` with all curated
  fields populated (use concrete values: `src_addr = Some("10.0.0.1".parse().unwrap())`,
  `octet_delta_count = Some(1234)`, `extra = serde_json::json!({"ie200": "0xdeadbeef"})`, etc.).
  Call `append_flow_record` twice (two distinct records), call `finish_batch`, then assert:
  - `batch.num_rows() == 2`
  - Column `src_addr` at row 0 matches `"10.0.0.1"`
  - Column `octet_delta_count` at row 0 matches `1234u64`
  - Column `extra` at row 0 contains `"ie200"`
  - Column `src_addr` at row 1 is null (second record has `src_addr: None`)
  Run:
  ```
  cargo test -p logthing forwarding::ipfix_s3::tests::append_and_finish_produces_correct_columns 2>&1
  ```
  Expected: compile or assertion failure. Commit: `test(ipfix-s3): add failing row-mapping
  round-trip test`.

- [ ] **1.4 — Fix row mapping until green**
  Iterate on `append_flow_record` and `finish_batch` until the test passes. Typical fix: ensure
  nullable builders use `append_option()` / `append_null()` correctly; confirm `finish()` on each
  builder is called in the same order as the schema fields. Run:
  ```
  cargo test -p logthing forwarding::ipfix_s3::tests:: 2>&1
  ```
  Expected: all tests in the module green. Commit: `feat(ipfix-s3): fix nullable column handling in
  row mapper`.

- [ ] **1.5 — Test: `extra` round-trips arbitrary JSON**
  Add `extra_json_round_trips`. Build a `FlowRecord` with
  `extra = serde_json::json!({"ie300": "0xabcd", "nested": {"k": 1}})`. After `finish_batch`,
  parse the `extra` string column at row 0 back with `serde_json::from_str` and assert the parsed
  value equals the original. Run all tests; expect green. Commit: `test(ipfix-s3): verify extra JSON
  column round-trips`.

---

## Task 2 — IpfixS3Writer: Buffer, Flush, Encode to Parquet

**Files:**
- Extend: `src/forwarding/ipfix_s3.rs`

**Interfaces:**

Produces:
```rust
pub struct IpfixS3Writer {
    // private
}

impl IpfixS3Writer {
    /// Construct writer. Spawns a background flush task immediately.
    /// `channel_capacity`: max number of FlowRecord batches in the bounded channel.
    /// `flush_threshold_bytes`: approximate buffer size (sum of estimated record sizes)
    ///   above which a flush is triggered eagerly.
    /// `flush_interval_secs`: maximum age of buffered records before a time-triggered flush.
    pub fn new(
        sink: Arc<S3Sink>,
        config: IpfixS3Config,
    ) -> Self;

    /// Send a batch of flow records to the writer. Returns Err if the channel is full
    /// (caller should increment the drop metric and discard).
    pub fn try_send(&self, flows: Vec<FlowRecord>) -> Result<(), Vec<FlowRecord>>;

    /// Graceful shutdown: flush remaining buffer and close.
    pub async fn shutdown(self) -> anyhow::Result<()>;
}
```

Internal (not pub, used within the file):
```rust
struct WriterState {
    builders: FlowRecordBuilders,
    buffered_bytes: usize,   // estimated; updated on each append
    last_flush: Instant,
}

impl WriterState {
    fn append(&mut self, record: &FlowRecord);
    fn should_flush(&self, threshold_bytes: usize, interval: Duration) -> bool;
    async fn flush_to_s3(
        &mut self,
        schema: Arc<Schema>,
        sink: &S3Sink,
        prefix: &str,
    ) -> anyhow::Result<()>;
}
```

`flush_to_s3` flow:
1. Call `finish_batch` on current builders, replace with fresh `FlowRecordBuilders::new()`.
2. Encode the `RecordBatch` to Parquet bytes in-memory (no temp file) using:
   ```rust
   let mut buf = Vec::<u8>::new();
   let mut writer = ArrowWriter::try_new(&mut buf, schema.clone(), Some(props))?;
   writer.write(&batch)?;
   writer.close()?;
   // buf now contains the complete Parquet file
   ```
   Writer properties: ZSTD level 3 (matching existing `parquet_s3.rs`).
3. Key: `{prefix}/year={Y}/month={M:02}/day={D:02}/{uuid}.parquet` where Y/M/D are from `Utc::now()`.
4. Call `sink.upload(&key, buf).await?`.
5. Increment `ipfix_s3_uploads` counter on success; `ipfix_s3_upload_errors` on error.
6. Increment `ipfix_s3_records_written` by row count.

Estimated record size: `128 + extra_json_str_len` bytes (cheap approximation; no actual
serialization in the hot path).

**TDD Steps:**

- [ ] **2.1 — Failing test: encode single batch to readable Parquet**
  Add `#[tokio::test]` `encode_batch_to_parquet_is_readable`. Create a `WriterState` directly (or
  test the internal `flush_to_s3` helper by calling it with a stub `S3Sink`). Build two
  `FlowRecord`s, append them, call `flush_to_s3` with a mock/stub sink that captures the `Vec<u8>`
  body. Then read the captured bytes back with `parquet::arrow::arrow_reader::ParquetRecordBatchReader`
  and assert `num_rows == 2` and the `exporter` column at row 0 matches the expected value.
  
  For the stub S3Sink, define a local `struct CaptureSink(Arc<Mutex<Vec<u8>>>)` with the same
  `upload` signature (the test does not need the real `S3Sink`; this isolates I/O). If `S3Sink` is
  a concrete struct (not a trait), wrap it behind a trait for testability or use `cargo test` with
  a local server — see Task 4 for the integration test that exercises real `S3Sink`.
  
  Run:
  ```
  cargo test -p logthing forwarding::ipfix_s3::tests::encode_batch_to_parquet_is_readable 2>&1
  ```
  Expected: compile error (types not defined yet). Commit: `test(ipfix-s3): add failing
  encode-to-parquet round-trip test`.

- [ ] **2.2 — Implement `WriterState`**
  Add `WriterState`, `append`, `should_flush`, and `flush_to_s3` (accepting a sink trait or an
  `S3Sink` reference; if `S3Sink` is concrete, introduce a local `trait UploadSink` with
  `async fn upload(&self, key: &str, body: Vec<u8>) -> anyhow::Result<()>` and implement it for
  both `S3Sink` and `CaptureSink`). Run:
  ```
  cargo test -p logthing forwarding::ipfix_s3::tests::encode_batch_to_parquet_is_readable 2>&1
  ```
  Expected: green. Run clippy. Commit: `feat(ipfix-s3): implement WriterState with in-memory
  Parquet encoding`.

- [ ] **2.3 — Test: `should_flush` triggers on size threshold**
  Add `should_flush_triggers_on_size`. Create `WriterState::new()`, manually set `buffered_bytes`
  above threshold, assert `should_flush(threshold, long_interval)` is `true`. Set `buffered_bytes`
  below, assert false. Run all tests; expect green. Commit: `test(ipfix-s3): verify size-based flush
  trigger`.

- [ ] **2.4 — Test: `should_flush` triggers on time threshold**
  Add `should_flush_triggers_on_time`. Use `last_flush = Instant::now() - Duration::from_secs(999)`
  and assert flush triggers. Run all tests; expect green. Commit: `test(ipfix-s3): verify
  time-based flush trigger`.

- [ ] **2.5 — Test: S3 key has expected prefix and partition layout**
  Add `s3_key_has_correct_structure`. In `flush_to_s3` (or a helper `build_s3_key(prefix, now)`),
  assert that the generated key starts with `"{prefix}/year="` and contains
  `/month=` and `/day=` and ends with `.parquet`. Extract the key-building logic into a pure
  function `fn build_s3_key(prefix: &str, now: DateTime<Utc>) -> String` so the test does not
  require a real upload. Run all tests; expect green. Commit: `test(ipfix-s3): verify S3 key
  structure`.

- [ ] **2.6 — Failing test: IpfixS3Writer channels and background task**
  Add `#[tokio::test]` `writer_accepts_flows_and_flushes`. Construct an `IpfixS3Writer` with a
  very low `flush_threshold_bytes` (e.g. 1 byte) and a short `flush_interval_secs` (e.g. 1s) so
  that the flush fires quickly. Send two batches via `try_send`. Sleep 200 ms. Assert the capture
  sink received at least one `upload` call with non-empty body. Run:
  ```
  cargo test -p logthing forwarding::ipfix_s3::tests::writer_accepts_flows_and_flushes 2>&1
  ```
  Expected: compile or runtime failure. Commit: `test(ipfix-s3): add failing writer
  channel+flush test`.

- [ ] **2.7 — Implement `IpfixS3Writer`**
  Add the `IpfixS3Writer` struct: holds a `mpsc::Sender<Vec<FlowRecord>>` and a
  `JoinHandle` for the background task. The background task loop:
  ```
  loop {
      tokio::select! {
          msg = rx.recv() => match msg {
              Some(flows) => { state.append_batch(&flows); metrics... }
              None => { state.flush_final(...).await; break; }
          },
          _ = flush_ticker.tick() => {
              if state.should_flush(...) { state.flush_to_s3(...).await.log_err(); }
          }
      }
  }
  ```
  `try_send` does `self.tx.try_send(flows).map_err(|e| e.into_inner())`.
  `shutdown` drops `self.tx` (closes channel) and `.await`s the join handle.
  Run:
  ```
  cargo test -p logthing forwarding::ipfix_s3::tests::writer_accepts_flows_and_flushes 2>&1
  ```
  Expected: green. Run full test suite: `cargo test -p logthing 2>&1 | tail -20`. Commit:
  `feat(ipfix-s3): implement IpfixS3Writer with bounded channel and background flush task`.

---

## Task 3 — IpfixS3Handler: Channel + Drop-on-Overflow + Metrics

**Files:**
- Extend: `src/forwarding/ipfix_s3.rs`

**Interfaces:**

Produces:
```rust
/// S3-persisting IpfixHandler. Wraps IpfixS3Writer.
pub struct IpfixS3Handler {
    writer: IpfixS3Writer,
}

impl IpfixS3Handler {
    pub fn new(writer: IpfixS3Writer) -> Self;
}

#[async_trait::async_trait]
impl IpfixHandler for IpfixS3Handler {
    async fn handle_flows(&self, flows: Vec<FlowRecord>, source: SocketAddr);
}
```

`handle_flows` implementation:
```rust
async fn handle_flows(&self, flows: Vec<FlowRecord>, source: SocketAddr) {
    let count = flows.len() as u64;
    match self.writer.try_send(flows) {
        Ok(()) => {
            metrics::counter!("ipfix_s3_records_written").increment(count);
        }
        Err(_dropped) => {
            metrics::counter!("ipfix_s3_dropped").increment(count);
            warn!("IPFIX S3 channel full; dropped {} flows from {}", count, source);
        }
    }
}
```

Note: `ipfix_s3_records_written` is incremented here (at enqueue time) and also by the writer on
upload; the spec says "records written" — keep the upload-side counter as `ipfix_s3_uploads` and
`ipfix_s3_upload_errors`, and use the handler-side counter for records successfully queued.
Reconcile naming with the spec's `<source>_s3_records_written` table if the Phase 3 syslog
equivalent uses a different convention.

**TDD Steps:**

- [ ] **3.1 — Failing test: handler drop-on-overflow**
  Add `#[tokio::test]` `handler_drops_on_overflow`. Construct an `IpfixS3Writer` with
  `channel_capacity = 1`. Send one batch via `handle_flows` (fills the channel). Send a second
  batch. Assert the second batch does not block (completes immediately) and that
  `ipfix_s3_dropped` counter was incremented. For metric assertion, use
  `metrics_util::recorder::DebuggingRecorder` or a local counter cell if the `metrics` test
  utilities are awkward to set up — alternatively, assert via a `Arc<AtomicU64>` injected through
  a test-only constructor.
  
  If `metrics_util` is not in `[dev-dependencies]`, add it: `metrics-util = "0.15"`.
  Run:
  ```
  cargo test -p logthing forwarding::ipfix_s3::tests::handler_drops_on_overflow 2>&1
  ```
  Expected: compile error. Commit: `test(ipfix-s3): add failing overflow drop test`.

- [ ] **3.2 — Implement `IpfixS3Handler`**
  Add the struct and the `IpfixHandler` impl as shown above. Run:
  ```
  cargo test -p logthing forwarding::ipfix_s3::tests::handler_drops_on_overflow 2>&1
  ```
  Expected: green. Run `cargo clippy`. Commit: `feat(ipfix-s3): implement IpfixS3Handler with
  drop-on-overflow`.

- [ ] **3.3 — Test: successful send increments enqueue counter**
  Add `handler_increments_enqueue_counter_on_success`. Use a capacity-100 writer, send one batch of
  5 records, assert `ipfix_s3_records_written` counter == 5. Run all tests; expect green. Commit:
  `test(ipfix-s3): verify enqueue metric on successful send`.

---

## Task 4 — Config Additions and Defaults

**Files:**
- Extend: `src/config/mod.rs`
- Extend: `src/forwarding/ipfix_s3.rs` (add `IpfixS3Config` struct)

**Interfaces:**

New config structs (in `src/forwarding/ipfix_s3.rs`):
```rust
/// Per-source S3 config for IPFIX persistence. Absent = no persistence.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct IpfixS3Config {
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    pub access_key: String,
    pub secret_key: String,
    /// S3 key prefix for IPFIX objects (default: "ipfix")
    #[serde(default = "default_ipfix_s3_prefix")]
    pub prefix: String,
    /// Max buffer size in bytes before an eager flush (default: 100 MiB)
    #[serde(default = "default_ipfix_flush_bytes")]
    pub flush_threshold_bytes: usize,
    /// Max age of buffered records in seconds before a time-triggered flush (default: 900)
    #[serde(default = "default_ipfix_flush_secs")]
    pub flush_interval_secs: u64,
    /// Bounded channel capacity (number of batches; default: 256)
    #[serde(default = "default_ipfix_channel_capacity")]
    pub channel_capacity: usize,
}
```

Changes in `src/config/mod.rs`:
```rust
// Add to Config struct:
#[serde(default)]
pub ipfix: IpfixConfig,

// New struct:
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IpfixConfig {
    #[serde(default = "default_ipfix_enabled")]
    pub enabled: bool,
    #[serde(default = "default_ipfix_udp_port")]
    pub udp_port: u16,
    #[serde(default = "default_ipfix_bind_address")]
    pub bind_address: String,
    /// If present, enable S3 persistence for IPFIX flows.
    pub s3: Option<IpfixS3Config>,
}

impl Default for IpfixConfig { ... }
```

Add `IpfixS3Config` to config re-export: `use crate::forwarding::ipfix_s3::IpfixS3Config;` in
`src/config/mod.rs` (or define it directly in config and re-export from `ipfix_s3.rs` — prefer
defining in config alongside the syslog equivalent for consistency).

Default functions:
- `default_ipfix_enabled() -> bool { false }`
- `default_ipfix_udp_port() -> u16 { 4739 }`
- `default_ipfix_bind_address() -> String { "0.0.0.0".to_string() }`
- `default_ipfix_s3_prefix() -> String { "ipfix".to_string() }`
- `default_ipfix_flush_bytes() -> usize { 100 * 1024 * 1024 }`
- `default_ipfix_flush_secs() -> u64 { 900 }`
- `default_ipfix_channel_capacity() -> usize { 256 }`

**TDD Steps:**

- [ ] **4.1 — Failing test: IpfixConfig defaults**
  Add to `src/config/mod.rs` `#[cfg(test)]` block:
  ```rust
  #[test]
  fn ipfix_config_defaults() {
      let cfg = Config::default();
      assert!(!cfg.ipfix.enabled);
      assert_eq!(cfg.ipfix.udp_port, 4739);
      assert_eq!(cfg.ipfix.bind_address, "0.0.0.0");
      assert!(cfg.ipfix.s3.is_none());
  }
  ```
  Run:
  ```
  cargo test -p logthing config::tests::ipfix_config_defaults 2>&1
  ```
  Expected: compile error (`ipfix` field missing). Commit: `test(config): add failing IPFIX config
  defaults test`.

- [ ] **4.2 — Add IpfixConfig to Config**
  Add `IpfixConfig` struct, `Default` impl, and `ipfix` field to `Config` (and `Config::default()`
  and the `load()` builder). Run:
  ```
  cargo test -p logthing config::tests::ipfix_config_defaults 2>&1
  ```
  Expected: green. Run `cargo test -p logthing config::tests::` to confirm no regressions.
  Commit: `feat(config): add IpfixConfig with disabled-by-default and port 4739`.

- [ ] **4.3 — Failing test: IpfixS3Config TOML round-trip**
  Add to `src/config/mod.rs` tests:
  ```rust
  #[test]
  fn ipfix_s3_config_deserializes_from_toml() {
      let toml_str = r#"
          [ipfix]
          enabled = true
          udp_port = 4739
          [ipfix.s3]
          endpoint = "http://minio:9000"
          bucket = "ipfix-flows"
          region = "us-east-1"
          access_key = "key"
          secret_key = "secret"
      "#;
      let cfg: Config = toml::from_str(toml_str).expect("parse");
      assert!(cfg.ipfix.enabled);
      let s3 = cfg.ipfix.s3.expect("s3 present");
      assert_eq!(s3.bucket, "ipfix-flows");
      assert_eq!(s3.prefix, "ipfix");      // default
      assert_eq!(s3.flush_interval_secs, 900);  // default
  }
  ```
  Run:
  ```
  cargo test -p logthing config::tests::ipfix_s3_config_deserializes_from_toml 2>&1
  ```
  Expected: compile error (type not wired). Commit: `test(config): add failing TOML round-trip for
  IpfixS3Config`.

- [ ] **4.4 — Add IpfixS3Config and wire to IpfixConfig.s3**
  Define `IpfixS3Config` (either in `src/config/mod.rs` alongside syslog config equivalents, or in
  `src/forwarding/ipfix_s3.rs` with a `pub use` re-export in config). Add `s3: Option<IpfixS3Config>`
  field to `IpfixConfig`. Run:
  ```
  cargo test -p logthing config::tests:: 2>&1
  ```
  Expected: all green. Run `cargo test -p logthing 2>&1 | tail -20`. Commit: `feat(config): add
  IpfixS3Config with defaults for prefix, flush thresholds, and channel capacity`.

- [ ] **4.5 — Test: absent [ipfix.s3] means no persistence (backward compat)**
  Add test `ipfix_s3_absent_means_no_persistence`:
  ```rust
  let toml_str = r#"[ipfix]\nenabled = true\n"#;
  let cfg: Config = toml::from_str(toml_str).expect("parse");
  assert!(cfg.ipfix.s3.is_none());
  ```
  Run all config tests; expect green. Commit: `test(config): verify absent ipfix.s3 is backward
  compatible`.

---

## Task 5 — Listener Wiring in main.rs

**Files:**
- Extend: `src/main.rs`
- Extend: `src/forwarding/mod.rs` (add `pub mod ipfix_s3;`)

**Interfaces:**

Wiring logic in `async_main()`:
```rust
mod ipfix;  // already added in Phase 1

// After syslog spawn block:
if config.ipfix.enabled {
    let ipfix_config = ipfix::listener::IpfixListenerConfig {
        udp_port: config.ipfix.udp_port,
        bind_address: config.ipfix.bind_address.clone(),
    };
    let handler: Arc<dyn ipfix::listener::IpfixHandler> =
        if let Some(s3_cfg) = config.ipfix.s3.clone() {
            let sink = Arc::new(
                forwarding::s3_sink::S3Sink::from_config(&s3_cfg.as_parquet_s3_config())
                    .await?,
            );
            let writer = forwarding::ipfix_s3::IpfixS3Writer::new(sink, s3_cfg);
            Arc::new(forwarding::ipfix_s3::IpfixS3Handler::new(writer))
        } else {
            Arc::new(ipfix::listener::DefaultIpfixHandler)
        };
    let config_clone = config.clone();
    tokio::spawn(async move {
        let listener = ipfix::listener::IpfixListener::new(ipfix_config, handler);
        if let Err(e) = listener.start().await {
            error!("IPFIX listener error: {}", e);
        }
    });
    info!("IPFIX listener started on UDP:{}", config.ipfix.udp_port);
}
```

Note: `IpfixS3Config::as_parquet_s3_config()` converts the IPFIX S3 config into a
`ParquetS3Config` to reuse the `S3Sink::from_config` constructor — OR, if `S3Sink::from_config`
accepts a more general config type (TBD in Phase 2), call it with appropriate fields directly.
Reconcile against actual Phase 2 signature.

**TDD Steps:**

- [ ] **5.1 — Add `pub mod ipfix_s3;` to `src/forwarding/mod.rs`**
  Run:
  ```
  cargo build -p logthing 2>&1 | head -30
  ```
  Expected: builds (or shows only IPFIX-related missing module errors from Phase 1 — stub the
  missing `crate::ipfix` types as empty modules if Phase 1 is not yet merged). Commit:
  `chore(forwarding): expose ipfix_s3 module`.

- [ ] **5.2 — Add `mod ipfix;` declaration in `main.rs` (if not added in Phase 1)**
  Conditional on Phase 1 being merged. If not merged, stub with
  `pub mod listener { ... }` minimally. This step is a no-op if Phase 1 is already in tree.

- [ ] **5.3 — Add IPFIX spawn block to `async_main`**
  Add the wiring block above. Run:
  ```
  cargo build -p logthing 2>&1 | head -40
  ```
  Expected: clean build (resolve any type mismatches against real Phase 1/2 output). Run
  `cargo clippy -- -D warnings`. Commit: `feat(main): wire IPFIX listener with optional S3
  persistence`.

- [ ] **5.4 — Test: IPFIX disabled by default does not spawn listener**
  This is implicitly covered by the existing `config::tests::default_config_values_match_expectations`
  (which already asserts syslog is enabled but does not test IPFIX). Add:
  ```rust
  #[test]
  fn ipfix_disabled_by_default() {
      let cfg = Config::default();
      assert!(!cfg.ipfix.enabled, "IPFIX must be opt-in");
  }
  ```
  Run:
  ```
  cargo test -p logthing config::tests::ipfix_disabled_by_default 2>&1
  ```
  Expected: green (already covered by defaults from Task 4). Commit: `test(config): assert IPFIX
  disabled by default`.

---

## Task 6 — Integration Test: FlowRecord → Parquet Object in S3

**Files:**
- Extend: `src/forwarding/ipfix_s3.rs` (integration test section)

**Goal:** Feed `FlowRecord`s through `IpfixS3Handler` → `IpfixS3Writer` → real (local) S3 upload
path, and assert a Parquet object appears in the bucket with the expected schema.

**Local S3 approach:** Mirror the existing `parquet_s3` tests. The existing tests (see
`parquet_s3.rs` test section) use a `DestinationConfig` pointing at `http://minio:9000`. For the
integration test, do the same: either:
  - Run against a locally reachable MinIO instance (integration tests gated by
    `IPFIX_S3_INTEGRATION_TEST=1` env var — skip with `eprintln!("skipping; set IPFIX_S3_INTEGRATION_TEST=1")` + `return`).
  - OR use `aws-sdk-s3`'s in-process mock if the SDK provides one.

Prefer the env-var gate pattern; it matches how the existing S3 tests are structured.

**TDD Steps:**

- [ ] **6.1 — Failing test skeleton: integration test with local S3**
  Add `#[tokio::test]` `integration_flows_produce_parquet_in_s3` inside a `#[cfg(test)]` block.
  Gate on `std::env::var("IPFIX_S3_INTEGRATION_TEST").is_ok()`. Build an `IpfixS3Config` pointing
  at `http://localhost:9000` (MinIO). Construct `S3Sink::from_config(...)`. Construct writer and
  handler. Call `handle_flows` with 10 `FlowRecord`s. Sleep 2s (or call `writer.shutdown().await`
  to force flush). Use `aws-sdk-s3` client to `list_objects_v2` on the bucket; assert ≥ 1 object
  whose key starts with `"ipfix/"`. Download the object, read back as Parquet with
  `ParquetRecordBatchReader`, assert `num_rows == 10` and the schema contains `"src_addr"`.
  Run (without the env var — should be skipped):
  ```
  cargo test -p logthing forwarding::ipfix_s3::tests::integration_flows_produce_parquet_in_s3 2>&1
  ```
  Expected: test runs and prints "skipping; set IPFIX_S3_INTEGRATION_TEST=1". Commit:
  `test(ipfix-s3): add integration test skeleton (gated on IPFIX_S3_INTEGRATION_TEST)`.

- [ ] **6.2 — Run integration test against local MinIO**
  Start MinIO locally (`docker run -p 9000:9000 minio/minio server /data`), create bucket
  `ipfix-test`, then:
  ```
  IPFIX_S3_INTEGRATION_TEST=1 IPFIX_S3_BUCKET=ipfix-test \
    cargo test -p logthing forwarding::ipfix_s3::tests::integration_flows_produce_parquet_in_s3 -- --nocapture 2>&1
  ```
  Expected: green with "Found Parquet object at ipfix/..." log line. Fix any issues (key prefix,
  bucket creation, credential mismatch). Commit: `test(ipfix-s3): integration test passes against
  local MinIO`.

- [ ] **6.3 — Integration test: `IpfixS3Writer::shutdown` flushes partial buffer**
  Add `integration_shutdown_flushes_partial_buffer`. Send 3 records (below size threshold). Call
  `shutdown().await`. Assert object appears in S3 with 3 rows. Run under the env gate. Commit:
  `test(ipfix-s3): verify shutdown flushes partial buffer`.

---

## Task 7 — E2E Harness Extension (Docker)

**Files:**
- Extend: `tests/e2e/simulation-environment/docker-compose.yml`
- Extend: `tests/e2e/simulation-environment/config/logthing.toml`
- Create: `tests/e2e/simulation-environment/ipfix-generator/Dockerfile`
- Create: `tests/e2e/simulation-environment/ipfix-generator/entrypoint.py`
- Extend: `tests/e2e/simulation-environment/s3-verifier/entrypoint.py` (or create a new
  `ipfix-s3-verifier` service)

**Goal:** Run the full datagram→S3 E2E path: an `ipfix-generator` container sends a IPFIX v10
template set + data set datagram sequence to the logthing container; the `s3-verifier` (or a
dedicated `ipfix-s3-verifier`) polls MinIO and asserts a Parquet object appears under the
`ipfix/` prefix with the correct schema.

**TDD Steps:**

- [ ] **7.1 — Add `[ipfix]` and `[ipfix.s3]` to the E2E logthing config**
  Edit `tests/e2e/simulation-environment/config/logthing.toml`:
  ```toml
  [ipfix]
  enabled = true
  udp_port = 4739

  [ipfix.s3]
  endpoint = "http://minio:9000"
  bucket = "ipfix-flows"
  region = "us-east-1"
  access_key = "miniouser"
  secret_key = "miniopassword"
  prefix = "ipfix"
  flush_threshold_bytes = 1   # immediate flush for E2E test speed
  flush_interval_secs = 5
  ```
  Also add `mc mb --ignore-existing local/ipfix-flows` to the `minio-setup` command block.

- [ ] **7.2 — Create `ipfix-generator` container**
  `tests/e2e/simulation-environment/ipfix-generator/entrypoint.py`: Python script that sends a
  real IPFIX v10 message (template set id=2 for template 256 with fields 8/src IPv4, 12/dst IPv4,
  7/src port, 11/dst port, 4/protocol, 1/octetDeltaCount, 2/packetDeltaCount, followed by a data
  set id=256 with 5 flow records with concrete values) to `IPFIX_HOST:IPFIX_PORT` via UDP, then
  exits. Use Python's `socket` module; no external dependencies.
  
  `tests/e2e/simulation-environment/ipfix-generator/Dockerfile`:
  ```dockerfile
  FROM python:3.12-slim
  COPY entrypoint.py /entrypoint.py
  CMD ["python3", "/entrypoint.py"]
  ```

- [ ] **7.3 — Add `ipfix-generator` and `ipfix-s3-verifier` services to docker-compose.yml**
  Add:
  ```yaml
  ipfix-generator:
    build:
      context: .
      dockerfile: ipfix-generator/Dockerfile
    environment:
      - IPFIX_HOST=logthing
      - IPFIX_PORT=4739
    depends_on:
      - logthing
    networks:
      - e2e

  ipfix-s3-verifier:
    build:
      context: .
      dockerfile: s3-verifier/Dockerfile
    environment:
      - MINIO_ENDPOINT=http://minio:9000
      - MINIO_BUCKET=ipfix-flows
      - AWS_ACCESS_KEY_ID=miniouser
      - AWS_SECRET_ACCESS_KEY=miniopassword
      - IPFIX_S3_PREFIX=ipfix/
      - EXPECTED_EVENT_TOTAL=5
      - E2E_TIMEOUT_SECS=60
    depends_on:
      - ipfix-generator
      - logthing
    networks:
      - e2e
  ```
  Update `s3-verifier/entrypoint.py` to also check for a prefix-filtered key (or create a
  separate `ipfix-s3-verifier` entry point that verifies the IPFIX Parquet schema columns).

- [ ] **7.4 — Run E2E harness and assert green**
  ```
  cd tests/e2e/simulation-environment && bash run.sh 2>&1 | tail -40
  ```
  Expected: all services exit 0; `ipfix-s3-verifier` prints "Found IPFIX Parquet object" and exits
  0. Fix any issues (port, config path, bucket name). Commit: `test(e2e): add IPFIX datagram→S3
  Parquet E2E test`.

---

## Self-Review

### Spec Coverage Checklist

| Spec requirement | Covered? | Where |
|---|---|---|
| `IpfixS3Writer` with fixed Arrow schema | Yes | Task 1, 2 |
| 17 typed columns + `extra` JSON string | Yes | Task 1 column table |
| Buffer on size or time threshold | Yes | Task 2, `should_flush` |
| Encode to Parquet bytes in memory (no temp file) | Yes | Task 2.2, `flush_to_s3` |
| `S3Sink::upload` with IPFIX key prefix | Yes | Task 2.5, key format |
| `IpfixS3Handler` implementing `IpfixHandler` | Yes | Task 3 |
| Bounded channel; overflow → drop + `ipfix_s3_dropped` | Yes | Task 3 |
| Per-source S3 config (`[ipfix.s3]`) | Yes | Task 4 |
| Backward compatible (absent = no persistence) | Yes | Task 4.5 |
| `main.rs` wiring (conditional spawn) | Yes | Task 5 |
| Metrics: `ipfix_s3_records_written`, `ipfix_s3_uploads`, `ipfix_s3_upload_errors`, `ipfix_s3_dropped` | Yes | Task 2 (`flush_to_s3`), Task 3 |
| Unit tests at all levels | Yes | Tasks 1–4 |
| Integration test (S3 round-trip) | Yes | Task 6 |
| E2E (Docker, datagram→S3) | Yes | Task 7 |
| Fixed schema (no per-template dynamic schemas) | Yes | Task 1; enforced by single `flow_record_schema()` |
| Error handling: S3 failure isolated, logged | Yes | Task 2.2 (`log_err()` in background task) |

### Placeholder Audit

No placeholders remain. All function signatures include concrete parameter and return types. All
test assertions use concrete values. Arrow builder types are specified per column.

### Type Consistency

- `FlowRecord::exporter: IpAddr` → `Utf8` column via `IpAddr::to_string()`.
- `FlowRecord::export_time: DateTime<Utc>` → `Utf8` via `to_rfc3339()`. (Alternatively `Int64`
  timestamp millis for query efficiency — but `Utf8` matches the WEF schema convention in
  `parquet_s3.rs` and avoids Arrow timezone complexity; document this choice in a code comment.)
- `Option<IpAddr>` → nullable `Utf8`; `Option<u16>` → nullable `UInt16`; etc. — all handled by
  builder `append_option` / `append_null`.
- `serde_json::Value` (extra) → `Utf8` via `serde_json::to_string`; failure fallback to `"{}"`.

### Fixed Schema Check

`flow_record_schema()` is a single function returning one `Arc<Schema>`. It is called once in
`IpfixS3Writer::new` and the result is stored. The background task always writes against this
schema. No code path allows per-template or per-exporter schema variation. This is explicitly
enforced by the test `schema_has_correct_fields_and_types` (Task 1.1) which compiles in the same
binary as the production code and would fail if the schema were changed dynamically.

### Risks and Assumptions

| Risk / Assumption | Mitigation |
|---|---|
| Phase 1 `FlowRecord` field names may differ slightly from the spec (e.g. `input_interface` vs `ingress_interface`) | Task 1.1 test will catch mismatches at compile time; implementer must reconcile against real Phase 1 output before starting. |
| Phase 2 `S3Sink::from_config` signature may not accept `IpfixS3Config` directly | `IpfixS3Config::as_parquet_s3_config()` conversion method bridges this; update if Phase 2 introduces a more general config type. |
| `S3Sink` is a concrete struct (not a trait) | Introduce a local `UploadSink` trait in `ipfix_s3.rs` for testability (Task 2.2); `S3Sink` implements it. |
| In-memory Parquet encoding may OOM for very large batches | Documented: `flush_threshold_bytes` default (100 MiB) limits buffer size; implementer should add a comment noting the memory amplification factor (~2–3× for Arrow → Parquet encode). |
| `metrics_util` dev-dependency for counter assertions | Add `metrics-util = "0.15"` to `[dev-dependencies]` in `Cargo.toml`; task 3.1 notes this. |
| E2E Docker test (Task 7) requires Docker and MinIO; may be skipped in CI without Docker | Mirrors the existing E2E pattern (`run.sh` is Docker-gated); no action required beyond noting the skip condition. |
| `UInt16` arrow type for ports — check `arrow` 53.x builder availability | `arrow-array` 53.x provides `UInt16Array` and `UInt16Builder`; confirmed in Cargo.toml dependencies. |

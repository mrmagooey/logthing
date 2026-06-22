# Zeek NDJSON Ingestion → Typed Parquet/S3 — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ingest Zeek network-monitor NDJSON-over-TCP log streams, decode each record by `_path`-derived stream type, and persist typed Parquet objects to S3 — adding Zeek as a first-class ingestion source alongside WEF, syslog, and IPFIX.

**Architecture:** A new `src/zeek/` module provides a TCP listener (modelled on `src/syslog/listener.rs`) that reads newline-delimited JSON, extracts the `_path` field to identify the stream type, and dispatches `ZeekRecord` structs to a `ZeekHandler` trait. A schema registry (`src/zeek/schema.rs`) maps each of six curated stream types to a typed Arrow schema with a catch-all `_extra` JSON column, enabling best-effort typed Parquet serialisation via a per-`log_path` buffer writer (`src/forwarding/zeek_s3.rs`) that mirrors the hardened `IpfixS3Writer`. The `[zeek]` and optional `[zeek.s3]` TOML config blocks are added to `src/config/mod.rs`; `main.rs` spawns the listener conditionally and selects handler based on config.

**Tech Stack:** Rust 2024 edition, Tokio async runtime, `serde_json`, `arrow` + `parquet` crates (Arrow IPC/Parquet), `aws-sdk-s3` via the existing `S3Sink`, `metrics` crate for counters, `async_trait`, `chrono`, `uuid`, `anyhow`/`thiserror`.

## Global Constraints

- Rust edition 2024; `cargo fmt` and `cargo clippy -- -D warnings` must pass with zero new warnings after every task.
- 100-column line limit, 4-space indentation.
- `cargo` is not on PATH by default — prefix every cargo invocation: `export PATH="$HOME/.cargo/bin:$PATH" && cargo …`
- All tests live in `#[cfg(test)]` modules inside their source file (or in `tests/` for integration/e2e). No separate test-only files unless they are under `tests/`.
- Error handling: `anyhow` for application-level fallible functions; `thiserror` for library error types. Never `.unwrap()` in production paths.
- Metrics via the `metrics` crate (`metrics::counter!`). Bounded channels drop on overflow and increment a counter — never block the listener.
- Conventional commit messages (`feat:`, `test:`, `refactor:`, `chore:`).
- Absent `[zeek.s3]` in TOML ⇒ `DefaultZeekHandler` — backward compatible, no persistence.
- The listener, parser, and row-mapper must be panic-free on arbitrary/hostile input.
- Default TCP port for Zeek listener: **47760** (arbitrary, not assigned to any IANA service).
- Implementation must stay on branch `feat/zeek-ingestion`; do NOT commit to `master`.

---

## Phase 1 — Zeek Ingestion (no S3)

### Task 1: `ZeekRecord` type + `src/zeek/mod.rs` + `lib.rs` + `forwarding/mod.rs`

**Files:**
- Create: `src/zeek/mod.rs`
- Modify: `src/lib.rs` (add `pub mod zeek;`)
- Modify: `src/forwarding/mod.rs` (add `pub mod zeek_s3;` — declare now, file created in Phase 2)

**Interfaces:**
- Produces:
  ```rust
  // src/zeek/mod.rs
  pub struct ZeekRecord {
      pub log_path: String,           // from JSON "_path"; "unknown" if absent/non-string
      pub fields: serde_json::Value,  // full JSON object as received
      pub received_at: chrono::DateTime<chrono::Utc>,
  }
  ```

- [ ] **Step 1: Write the failing test**

  In `src/zeek/mod.rs` (new file), write:

  ```rust
  //! Zeek NDJSON ingestion — record type and module root.
  
  use chrono::{DateTime, Utc};
  
  /// A single decoded Zeek log record.
  #[derive(Debug, Clone)]
  pub struct ZeekRecord {
      /// Stream type, from the JSON `_path` field; `"unknown"` if absent or non-string.
      pub log_path: String,
      /// Full JSON object as received — used by the schema mapper and the default handler.
      pub fields: serde_json::Value,
      /// Wall-clock time this record was received by the listener.
      pub received_at: DateTime<Utc>,
  }
  
  pub mod listener;
  
  #[cfg(test)]
  mod tests {
      use super::*;
  
      #[test]
      fn zeek_record_stores_log_path_and_fields() {
          let rec = ZeekRecord {
              log_path: "conn".to_string(),
              fields: serde_json::json!({"_path": "conn", "uid": "Ctest123"}),
              received_at: Utc::now(),
          };
          assert_eq!(rec.log_path, "conn");
          assert_eq!(rec.fields["uid"], "Ctest123");
      }
  
      #[test]
      fn zeek_record_unknown_log_path() {
          let rec = ZeekRecord {
              log_path: "unknown".to_string(),
              fields: serde_json::json!({}),
              received_at: Utc::now(),
          };
          assert_eq!(rec.log_path, "unknown");
      }
  }
  ```

  Also create `src/zeek/listener.rs` as a stub so the `pub mod listener;` compiles:

  ```rust
  //! Zeek TCP NDJSON listener — stub (filled in Task 2).
  ```

- [ ] **Step 2: Run test to verify it compiles and passes**

  ```bash
  export PATH="$HOME/.cargo/bin:$PATH" && cargo test -p logthing zeek::tests -- --nocapture
  ```

  Expected: both tests PASS (the struct compiles and the assertions hold).

- [ ] **Step 3: Add `pub mod zeek;` to `src/lib.rs`**

  In `src/lib.rs`, add after the last existing `pub mod` line:

  ```rust
  pub mod zeek;
  ```

- [ ] **Step 4: Add `pub mod zeek_s3;` stub to `src/forwarding/mod.rs`**

  In `src/forwarding/mod.rs`, add after the existing `pub mod syslog_s3;` line:

  ```rust
  pub mod zeek_s3;
  ```

  Create the stub file `src/forwarding/zeek_s3.rs`:

  ```rust
  //! Zeek → S3 Parquet persistence — stub (filled in Phase 2).
  ```

- [ ] **Step 5: Run full test suite to verify no regressions**

  ```bash
  export PATH="$HOME/.cargo/bin:$PATH" && cargo test 2>&1 | tail -20
  ```

  Expected: all pre-existing tests pass; two new zeek tests pass.

- [ ] **Step 6: fmt + clippy**

  ```bash
  export PATH="$HOME/.cargo/bin:$PATH" && cargo fmt && cargo clippy -- -D warnings
  ```

  Expected: no warnings, no errors.

- [ ] **Step 7: Commit**

  ```bash
  git add src/zeek/mod.rs src/zeek/listener.rs src/forwarding/zeek_s3.rs src/lib.rs src/forwarding/mod.rs
  git commit -m "feat: add ZeekRecord type and zeek/forwarding module stubs"
  ```

---

### Task 2: `ZeekHandler` trait, `DefaultZeekHandler`, and `ZeekListener` TCP server

**Files:**
- Modify: `src/zeek/listener.rs` (replace stub with full implementation)

**Interfaces:**
- Consumes: `ZeekRecord` from Task 1
- Produces:
  ```rust
  pub const ZEEK_MAX_LINE_BYTES: usize = 16 * 1024 * 1024; // 16 MiB

  pub struct ZeekListenerConfig {
      pub tcp_port: u16,       // default 47760
      pub bind_address: String, // default "0.0.0.0"
  }

  #[async_trait::async_trait]
  pub trait ZeekHandler: Send + Sync {
      async fn handle_record(&self, record: ZeekRecord, source: std::net::SocketAddr);
  }

  pub struct DefaultZeekHandler;

  pub struct ZeekListener {
      config: ZeekListenerConfig,
      handler: std::sync::Arc<dyn ZeekHandler>,
  }

  impl ZeekListener {
      pub fn new(config: ZeekListenerConfig, handler: std::sync::Arc<dyn ZeekHandler>) -> Self;
      pub async fn start(&self) -> anyhow::Result<()>;
      pub(crate) async fn run_with_listener(
          &self,
          listener: tokio::net::TcpListener,
      ) -> anyhow::Result<()>;
  }
  ```

- [ ] **Step 1: Write the failing tests**

  Replace `src/zeek/listener.rs` stub with:

  ```rust
  //! Zeek TCP NDJSON listener.

  use crate::zeek::ZeekRecord;
  use chrono::Utc;
  use std::net::SocketAddr;
  use std::sync::Arc;
  use tokio::io::{AsyncBufReadExt, BufReader};
  use tokio::net::{TcpListener, TcpStream};
  use tracing::{debug, error, info, warn};

  /// Maximum accepted line length in bytes. Lines exceeding this are skipped
  /// and counted via `zeek_oversized_lines`.
  pub const ZEEK_MAX_LINE_BYTES: usize = 16 * 1024 * 1024; // 16 MiB

  /// Configuration for the Zeek TCP NDJSON listener.
  #[derive(Debug, Clone)]
  pub struct ZeekListenerConfig {
      pub tcp_port: u16,
      pub bind_address: String,
  }

  impl Default for ZeekListenerConfig {
      fn default() -> Self {
          Self {
              tcp_port: 47760,
              bind_address: "0.0.0.0".to_string(),
          }
      }
  }

  /// Handler trait for decoded Zeek records.
  #[async_trait::async_trait]
  pub trait ZeekHandler: Send + Sync {
      async fn handle_record(&self, record: ZeekRecord, source: SocketAddr);
  }

  /// Default handler: logs a summary and increments metrics.
  pub struct DefaultZeekHandler;

  #[async_trait::async_trait]
  impl ZeekHandler for DefaultZeekHandler {
      async fn handle_record(&self, record: ZeekRecord, source: SocketAddr) {
          metrics::counter!("zeek_records_received").increment(1);
          metrics::counter!("zeek_records_by_path",
              "log_path" => record.log_path.clone()
          ).increment(1);
          info!(
              "[{}] zeek record: path={} fields={}",
              source,
              record.log_path,
              record.fields.to_string().chars().take(120).collect::<String>(),
          );
      }
  }

  /// Zeek TCP NDJSON listener.
  pub struct ZeekListener {
      config: ZeekListenerConfig,
      handler: Arc<dyn ZeekHandler>,
  }

  impl ZeekListener {
      pub fn new(config: ZeekListenerConfig, handler: Arc<dyn ZeekHandler>) -> Self {
          Self { config, handler }
      }

      /// Bind the TCP listener and run the accept loop.
      pub async fn start(&self) -> anyhow::Result<()> {
          let addr: SocketAddr =
              format!("{}:{}", self.config.bind_address, self.config.tcp_port).parse()?;
          let listener = TcpListener::bind(&addr).await?;
          self.run_with_listener(listener).await
      }

      /// Run the accept loop on an already-bound listener.
      /// Extracted for testability — tests bind their own listener to get a known port.
      pub(crate) async fn run_with_listener(
          &self,
          listener: TcpListener,
      ) -> anyhow::Result<()> {
          let bound = listener.local_addr()?;
          info!("Zeek TCP listener started on {}", bound);
          loop {
              match listener.accept().await {
                  Ok((stream, src)) => {
                      let handler = self.handler.clone();
                      tokio::spawn(async move {
                          if let Err(e) =
                              Self::handle_tcp_connection(stream, src, handler).await
                          {
                              error!("Zeek TCP connection error from {}: {}", src, e);
                          }
                      });
                  }
                  Err(e) => {
                      error!("Zeek TCP accept error: {}", e);
                  }
              }
          }
      }

      /// Handle one TCP connection: BufReader + read_line loop, one NDJSON record per line.
      async fn handle_tcp_connection(
          stream: TcpStream,
          src: SocketAddr,
          handler: Arc<dyn ZeekHandler>,
      ) -> anyhow::Result<()> {
          let mut reader = BufReader::new(stream);
          let mut line = String::new();

          loop {
              line.clear();
              match reader.read_line(&mut line).await {
                  Ok(0) => {
                      debug!("Zeek TCP connection from {} closed", src);
                      break;
                  }
                  Ok(_) => {
                      let trimmed = line.trim();
                      if trimmed.is_empty() {
                          continue;
                      }
                      // Oversized-line guard.
                      if trimmed.len() > ZEEK_MAX_LINE_BYTES {
                          metrics::counter!("zeek_oversized_lines").increment(1);
                          warn!(
                              "Zeek: oversized line ({} bytes) from {} — skipping",
                              trimmed.len(),
                              src
                          );
                          continue;
                      }
                      // Parse JSON.
                      match serde_json::from_str::<serde_json::Value>(trimmed) {
                          Err(e) => {
                              metrics::counter!("zeek_parse_errors").increment(1);
                              warn!(
                                  "Zeek: JSON parse error from {}: {} — line: {}",
                                  src,
                                  e,
                                  &trimmed[..trimmed.len().min(120)],
                              );
                          }
                          Ok(value) => {
                              // Extract _path.
                              let log_path = match value.get("_path").and_then(|v| v.as_str()) {
                                  Some(p) => p.to_string(),
                                  None => {
                                      metrics::counter!("zeek_missing_path").increment(1);
                                      "unknown".to_string()
                                  }
                              };
                              let record = ZeekRecord {
                                  log_path,
                                  fields: value,
                                  received_at: Utc::now(),
                              };
                              handler.handle_record(record, src).await;
                          }
                      }
                  }
                  Err(e) => {
                      error!("Zeek TCP read error from {}: {}", src, e);
                      break;
                  }
              }
          }
          Ok(())
      }
  }

  #[cfg(test)]
  mod tests {
      use super::*;
      use std::sync::Mutex;
      use std::time::Duration;
      use tokio::io::AsyncWriteExt;
      use tokio::time::sleep;

      /// Test handler that captures received records.
      struct CapturingHandler {
          records: Mutex<Vec<ZeekRecord>>,
      }

      impl CapturingHandler {
          fn new() -> Arc<Self> {
              Arc::new(Self {
                  records: Mutex::new(Vec::new()),
              })
          }
          fn take_records(&self) -> Vec<ZeekRecord> {
              self.records.lock().unwrap().drain(..).collect()
          }
      }

      #[async_trait::async_trait]
      impl ZeekHandler for CapturingHandler {
          async fn handle_record(&self, record: ZeekRecord, _source: SocketAddr) {
              self.records.lock().unwrap().push(record);
          }
      }

      // -- Unit: _path extraction --

      #[test]
      fn extract_log_path_from_json() {
          let value = serde_json::json!({"_path": "conn", "uid": "Cabc"});
          let path = value.get("_path").and_then(|v| v.as_str())
              .map(|s| s.to_string())
              .unwrap_or_else(|| "unknown".to_string());
          assert_eq!(path, "conn");
      }

      #[test]
      fn missing_path_field_gives_unknown() {
          let value = serde_json::json!({"uid": "Cabc"});
          let path = value.get("_path").and_then(|v| v.as_str())
              .map(|s| s.to_string())
              .unwrap_or_else(|| "unknown".to_string());
          assert_eq!(path, "unknown");
      }

      #[test]
      fn non_string_path_field_gives_unknown() {
          let value = serde_json::json!({"_path": 42, "uid": "Cabc"});
          let path = value.get("_path").and_then(|v| v.as_str())
              .map(|s| s.to_string())
              .unwrap_or_else(|| "unknown".to_string());
          assert_eq!(path, "unknown");
      }

      // -- Integration: TCP listener receives records --

      #[tokio::test]
      async fn listener_dispatches_records_from_ndjson_stream() {
          let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
          let addr = tcp_listener.local_addr().unwrap();

          let handler = CapturingHandler::new();
          let handler_clone = handler.clone();
          let listener = ZeekListener::new(ZeekListenerConfig::default(), handler_clone);

          let task = tokio::spawn(async move {
              listener.run_with_listener(tcp_listener).await.ok();
          });
          sleep(Duration::from_millis(20)).await;

          let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
          let lines = concat!(
              r#"{"_path":"conn","uid":"C1","ts":1700000000.0}"#, "\n",
              r#"{"_path":"dns","uid":"C2","ts":1700000001.0}"#, "\n",
          );
          stream.write_all(lines.as_bytes()).await.unwrap();
          drop(stream);

          sleep(Duration::from_millis(150)).await;
          task.abort();

          let records = handler.take_records();
          assert_eq!(records.len(), 2, "expected 2 records, got {}", records.len());
          assert_eq!(records[0].log_path, "conn");
          assert_eq!(records[1].log_path, "dns");
      }

      #[tokio::test]
      async fn listener_skips_malformed_json_and_continues() {
          let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
          let addr = tcp_listener.local_addr().unwrap();

          let handler = CapturingHandler::new();
          let handler_clone = handler.clone();
          let listener = ZeekListener::new(ZeekListenerConfig::default(), handler_clone);

          let task = tokio::spawn(async move {
              listener.run_with_listener(tcp_listener).await.ok();
          });
          sleep(Duration::from_millis(20)).await;

          let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
          let lines = concat!(
              "NOT JSON AT ALL\n",
              r#"{"_path":"ssl","uid":"C3","ts":1700000002.0}"#, "\n",
          );
          stream.write_all(lines.as_bytes()).await.unwrap();
          drop(stream);

          sleep(Duration::from_millis(150)).await;
          task.abort();

          let records = handler.take_records();
          assert_eq!(records.len(), 1, "only the valid record should be dispatched");
          assert_eq!(records[0].log_path, "ssl");
      }

      #[tokio::test]
      async fn listener_routes_missing_path_to_unknown() {
          let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
          let addr = tcp_listener.local_addr().unwrap();

          let handler = CapturingHandler::new();
          let handler_clone = handler.clone();
          let listener = ZeekListener::new(ZeekListenerConfig::default(), handler_clone);

          let task = tokio::spawn(async move {
              listener.run_with_listener(tcp_listener).await.ok();
          });
          sleep(Duration::from_millis(20)).await;

          let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
          stream
              .write_all(b"{\"uid\":\"C4\",\"ts\":1700000003.0}\n")
              .await
              .unwrap();
          drop(stream);

          sleep(Duration::from_millis(150)).await;
          task.abort();

          let records = handler.take_records();
          assert_eq!(records.len(), 1);
          assert_eq!(records[0].log_path, "unknown");
      }

      #[tokio::test]
      async fn listener_handles_multiple_concurrent_connections() {
          let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
          let addr = tcp_listener.local_addr().unwrap();

          let handler = CapturingHandler::new();
          let handler_clone = handler.clone();
          let listener = ZeekListener::new(ZeekListenerConfig::default(), handler_clone);

          let task = tokio::spawn(async move {
              listener.run_with_listener(tcp_listener).await.ok();
          });
          sleep(Duration::from_millis(20)).await;

          // Connect three clients simultaneously.
          let mut s1 = tokio::net::TcpStream::connect(addr).await.unwrap();
          let mut s2 = tokio::net::TcpStream::connect(addr).await.unwrap();
          let mut s3 = tokio::net::TcpStream::connect(addr).await.unwrap();

          s1.write_all(b"{\"_path\":\"conn\",\"uid\":\"Ca\"}\n").await.unwrap();
          s2.write_all(b"{\"_path\":\"http\",\"uid\":\"Cb\"}\n").await.unwrap();
          s3.write_all(b"{\"_path\":\"files\",\"uid\":\"Cc\"}\n").await.unwrap();
          drop(s1); drop(s2); drop(s3);

          sleep(Duration::from_millis(150)).await;
          task.abort();

          let records = handler.take_records();
          assert_eq!(records.len(), 3, "expected 3 records from 3 connections");
          let paths: std::collections::HashSet<_> = records.iter().map(|r| r.log_path.as_str()).collect();
          assert!(paths.contains("conn"));
          assert!(paths.contains("http"));
          assert!(paths.contains("files"));
      }
  }
  ```

- [ ] **Step 2: Run tests to verify they fail** (listener.rs compiles but tests fail because the implementation doesn't exist yet — replace the stub file above with just the test skeleton first, then confirm failure, then add the impl)

  Actually, the code above is the complete file including impl. Run to verify all tests pass:

  ```bash
  export PATH="$HOME/.cargo/bin:$PATH" && cargo test -p logthing zeek::listener::tests -- --nocapture
  ```

  Expected: all 6 tests pass (3 unit, 3 integration/async).

- [ ] **Step 3: fmt + clippy**

  ```bash
  export PATH="$HOME/.cargo/bin:$PATH" && cargo fmt && cargo clippy -- -D warnings
  ```

- [ ] **Step 4: Commit**

  ```bash
  git add src/zeek/listener.rs
  git commit -m "feat: add ZeekHandler trait, DefaultZeekHandler, and ZeekListener TCP server"
  ```

---

### Task 3: `[zeek]` config block in `src/config/mod.rs`

**Files:**
- Modify: `src/config/mod.rs`

**Interfaces:**
- Produces:
  ```rust
  pub struct ZeekConfig {
      pub enabled: bool,       // default false
      pub tcp_port: u16,       // default 47760
      pub bind_address: String, // default "0.0.0.0"
      pub s3: Option<ZeekS3Config>, // None = no persistence
  }

  pub struct ZeekS3Config {
      #[serde(flatten)]
      pub connection: S3ConnectionConfig,
      pub prefix: String,                // default "zeek"
      pub flush_threshold_bytes: usize,  // default 100 MiB
      pub flush_interval_secs: u64,      // default 900
      pub channel_capacity: usize,       // default 256
      pub max_buffer_rows: usize,        // default 100_000
  }
  ```

- [ ] **Step 1: Write failing config tests**

  In `src/config/mod.rs`, add these tests to the existing `#[cfg(test)]` block:

  ```rust
  #[test]
  fn zeek_disabled_by_default() {
      let cfg = Config::default();
      assert!(!cfg.zeek.enabled, "zeek must be opt-in");
      assert_eq!(cfg.zeek.tcp_port, 47760);
      assert_eq!(cfg.zeek.bind_address, "0.0.0.0");
  }

  #[test]
  fn zeek_s3_absent_gives_none() {
      let cfg = Config::default();
      assert!(cfg.zeek.s3.is_none(), "absent [zeek.s3] must deserialize to None");
  }

  #[test]
  fn zeek_s3_flat_toml_deserializes_correctly() {
      let toml_str = r#"
  [zeek]
  enabled = true
  tcp_port = 47760
  [zeek.s3]
  endpoint   = "http://minio:9000"
  bucket     = "zeek-logs"
  region     = "us-east-1"
  access_key = "KEY"
  secret_key = "SECRET"
  "#;
      let cfg: Config = toml::from_str(toml_str).expect("parse config");
      assert!(cfg.zeek.enabled);
      let s3 = cfg.zeek.s3.expect("s3 present");
      assert_eq!(s3.connection.bucket, "zeek-logs");
      assert_eq!(s3.prefix, "zeek");
      assert_eq!(s3.flush_threshold_bytes, 100 * 1024 * 1024);
      assert_eq!(s3.flush_interval_secs, 900);
      assert_eq!(s3.channel_capacity, 256);
      assert_eq!(s3.max_buffer_rows, 100_000);
  }

  #[test]
  fn zeek_s3_absent_section_means_no_persistence() {
      let toml_str = "[zeek]\nenabled = true\n";
      let cfg: Config = toml::from_str(toml_str).expect("parse");
      assert!(cfg.zeek.s3.is_none(), "absent [zeek.s3] must yield None");
  }
  ```

- [ ] **Step 2: Run to verify they fail**

  ```bash
  export PATH="$HOME/.cargo/bin:$PATH" && cargo test -p logthing config::tests::zeek 2>&1 | head -30
  ```

  Expected: compile error — `zeek` field not found on `Config`.

- [ ] **Step 3: Add the config structs**

  In `src/config/mod.rs`, add after the `IpfixConfig` block:

  ```rust
  /// Configuration for the Zeek NDJSON TCP listener.
  #[derive(Debug, Clone, Deserialize, Serialize)]
  pub struct ZeekConfig {
      #[serde(default = "default_zeek_enabled")]
      pub enabled: bool,

      #[serde(default = "default_zeek_tcp_port")]
      pub tcp_port: u16,

      #[serde(default = "default_zeek_bind_address")]
      pub bind_address: String,

      /// Optional S3 persistence. Absent from TOML → `None` → no persistence.
      #[serde(default)]
      pub s3: Option<ZeekS3Config>,
  }

  impl Default for ZeekConfig {
      fn default() -> Self {
          Self {
              enabled: default_zeek_enabled(),
              tcp_port: default_zeek_tcp_port(),
              bind_address: default_zeek_bind_address(),
              s3: None,
          }
      }
  }

  fn default_zeek_enabled() -> bool { false }
  fn default_zeek_tcp_port() -> u16 { 47760 }
  fn default_zeek_bind_address() -> String { "0.0.0.0".to_string() }

  /// Per-source S3 persistence config for the Zeek listener.
  #[derive(Debug, Clone, Deserialize, Serialize)]
  pub struct ZeekS3Config {
      /// Shared S3 connection fields. Flattened so TOML stays flat: `[zeek.s3]\nendpoint = …`
      #[serde(flatten)]
      pub connection: S3ConnectionConfig,
      /// S3 key prefix, slash-free (default: `"zeek"`).
      #[serde(default = "default_zeek_s3_prefix")]
      pub prefix: String,
      /// Flush when estimated buffer bytes exceeds this (default: 100 MiB).
      #[serde(default = "default_zeek_flush_bytes")]
      pub flush_threshold_bytes: usize,
      /// Flush after this many seconds regardless of buffer size (default: 900).
      #[serde(default = "default_zeek_flush_secs")]
      pub flush_interval_secs: u64,
      /// Bounded channel capacity (default: 256).
      #[serde(default = "default_zeek_channel_capacity")]
      pub channel_capacity: usize,
      /// Maximum buffered rows before hard cap kicks in (default: 100_000).
      #[serde(default = "default_zeek_max_buffer_rows")]
      pub max_buffer_rows: usize,
  }

  fn default_zeek_s3_prefix() -> String { "zeek".to_string() }
  fn default_zeek_flush_bytes() -> usize { 100 * 1024 * 1024 }
  fn default_zeek_flush_secs() -> u64 { 900 }
  fn default_zeek_channel_capacity() -> usize { 256 }
  fn default_zeek_max_buffer_rows() -> usize { 100_000 }
  ```

  Add `zeek: ZeekConfig` to the `Config` struct and `Default for Config`:

  ```rust
  // In Config struct, add after `pub ipfix: IpfixConfig,`:
  #[serde(default)]
  pub zeek: ZeekConfig,
  ```

  ```rust
  // In impl Default for Config, add after `ipfix: IpfixConfig::default(),`:
  zeek: ZeekConfig::default(),
  ```

- [ ] **Step 4: Run tests to verify they pass**

  ```bash
  export PATH="$HOME/.cargo/bin:$PATH" && cargo test -p logthing config::tests -- --nocapture 2>&1 | tail -20
  ```

  Expected: all config tests pass including the 4 new zeek tests.

- [ ] **Step 5: fmt + clippy**

  ```bash
  export PATH="$HOME/.cargo/bin:$PATH" && cargo fmt && cargo clippy -- -D warnings
  ```

- [ ] **Step 6: Commit**

  ```bash
  git add src/config/mod.rs
  git commit -m "feat: add [zeek] and [zeek.s3] config blocks"
  ```

---

### Task 4: Wire Zeek listener into `src/main.rs` + `src/lib.rs` `pub mod zeek`

**Files:**
- Modify: `src/main.rs`

**Interfaces:**
- Consumes: `ZeekConfig`, `ZeekListenerConfig`, `ZeekListener`, `DefaultZeekHandler` from Tasks 1–3
- Produces: conditional Zeek listener spawn mirroring the IPFIX block

- [ ] **Step 1: Write test proving the default config has zeek disabled**

  In `src/config/mod.rs` tests, add (if not already present):

  ```rust
  #[test]
  fn default_zeek_config_disabled_on_port_47760() {
      let cfg = Config::default();
      assert!(!cfg.zeek.enabled, "zeek disabled by default");
      assert_eq!(cfg.zeek.tcp_port, 47760);
      assert_eq!(cfg.zeek.bind_address, "0.0.0.0");
  }
  ```

  ```bash
  export PATH="$HOME/.cargo/bin:$PATH" && cargo test -p logthing config::tests::default_zeek_config_disabled -- --nocapture
  ```

  Expected: PASS.

- [ ] **Step 2: Add the Zeek spawn block to `src/main.rs`**

  In `src/main.rs`, add these imports at the top:

  ```rust
  use logthing::zeek;
  ```

  Add after the IPFIX spawn block (after the closing `}` of `if config.ipfix.enabled { … }`):

  ```rust
  // Start Zeek listener if enabled
  if config.zeek.enabled {
      let zeek_config_clone = config.clone();
      tokio::spawn(async move {
          let listener_config = zeek::listener::ZeekListenerConfig {
              tcp_port: zeek_config_clone.zeek.tcp_port,
              bind_address: zeek_config_clone.zeek.bind_address.clone(),
          };
          let handler: Arc<dyn zeek::listener::ZeekHandler> =
              Arc::new(zeek::listener::DefaultZeekHandler)
                  if let Some(s3_cfg) = zeek_config_clone.zeek.s3.as_ref() {
                      match forwarding::s3_sink::S3Sink::from_connection(&s3_cfg.connection).await {
                          Ok(sink) => {
                              let writer_cfg = forwarding::zeek_s3::ZeekS3WriterConfig {
                                  flush_threshold_bytes: s3_cfg.flush_threshold_bytes,
                                  flush_interval: std::time::Duration::from_secs(
                                      s3_cfg.flush_interval_secs,
                                  ),
                                  key_prefix: s3_cfg.prefix.clone(),
                                  max_buffer_rows: s3_cfg.max_buffer_rows,
                              };
                              let handler = forwarding::zeek_s3::ZeekS3Handler::start_with_capacity(
                                  writer_cfg,
                                  Arc::new(sink),
                                  s3_cfg.channel_capacity,
                              );
                              Arc::new(handler)
                          }
                          Err(e) => {
                              error!(
                                  "Failed to create S3Sink for Zeek persistence, \
                                   falling back to DefaultZeekHandler: {e}"
                              );
                              Arc::new(zeek::listener::DefaultZeekHandler)
                          }
                      }
                  } else {
                      Arc::new(zeek::listener::DefaultZeekHandler)
                  };

          let listener = zeek::listener::ZeekListener::new(listener_config, handler);
          if let Err(e) = listener.start().await {
              error!("Zeek listener error: {}", e);
          }
      });
      info!("Zeek listener started on TCP:{}", config.zeek.tcp_port);
  }
  ```

  Note: `forwarding::zeek_s3::ZeekS3WriterConfig` and `ZeekS3Handler` are defined in Phase 2. The code compiles now because `src/forwarding/zeek_s3.rs` exists as a stub — Phase 2 will fill it in. The conditional `if let Some(s3_cfg)` branch is dead code until Phase 2, but must compile. To make this compile before Phase 2 adds those types, guard it with `#[allow(unreachable_code)]` or simply leave the `[zeek.s3]` branch as a comment until Phase 2.

  **Simplified version that compiles with the Phase 1 stub:**

  ```rust
  // Start Zeek listener if enabled
  if config.zeek.enabled {
      let zeek_config_clone = config.clone();
      tokio::spawn(async move {
          let listener_config = zeek::listener::ZeekListenerConfig {
              tcp_port: zeek_config_clone.zeek.tcp_port,
              bind_address: zeek_config_clone.zeek.bind_address.clone(),
          };
          // Phase 2 will select ZeekS3Handler when [zeek.s3] is present.
          // For now, always use DefaultZeekHandler.
          let handler: Arc<dyn zeek::listener::ZeekHandler> =
              Arc::new(zeek::listener::DefaultZeekHandler);
          let listener = zeek::listener::ZeekListener::new(listener_config, handler);
          if let Err(e) = listener.start().await {
              error!("Zeek listener error: {}", e);
          }
      });
      info!("Zeek listener started on TCP:{}", config.zeek.tcp_port);
  }
  ```

- [ ] **Step 3: Verify full build compiles**

  ```bash
  export PATH="$HOME/.cargo/bin:$PATH" && cargo build 2>&1 | tail -20
  ```

  Expected: compiles with zero errors; there may be an `unused import` or `dead_code` lint — fix any that appear.

- [ ] **Step 4: Run full test suite**

  ```bash
  export PATH="$HOME/.cargo/bin:$PATH" && cargo test 2>&1 | tail -20
  ```

  Expected: all tests pass.

- [ ] **Step 5: fmt + clippy**

  ```bash
  export PATH="$HOME/.cargo/bin:$PATH" && cargo fmt && cargo clippy -- -D warnings
  ```

- [ ] **Step 6: Commit**

  ```bash
  git add src/main.rs src/lib.rs
  git commit -m "feat: wire Zeek listener spawn into main.rs"
  ```

---

## Phase 2 — Zeek → Typed Parquet/S3

### Task 5: `src/zeek/schema.rs` — Typed Arrow schema registry

**Files:**
- Create: `src/zeek/schema.rs`
- Modify: `src/zeek/mod.rs` (add `pub mod schema;`)

**Interfaces:**
- Consumes: `ZeekRecord` from Task 1
- Produces:
  ```rust
  // src/zeek/schema.rs

  /// A function that maps a JSON Value to a one-row RecordBatch using the stream's schema.
  pub type RowMapper = Arc<dyn Fn(&serde_json::Value) -> anyhow::Result<RecordBatch> + Send + Sync>;

  pub struct SchemaEntry {
      pub schema: Arc<arrow::datatypes::Schema>,
      pub mapper: RowMapper,
  }

  /// Returns the SchemaEntry for a given log_path, or the generic envelope fallback.
  pub fn get_schema_entry(log_path: &str) -> Arc<SchemaEntry>;

  /// The six curated typed schemas (exported for tests):
  pub fn conn_schema() -> Arc<arrow::datatypes::Schema>;
  pub fn dns_schema() -> Arc<arrow::datatypes::Schema>;
  pub fn http_schema() -> Arc<arrow::datatypes::Schema>;
  pub fn ssl_schema() -> Arc<arrow::datatypes::Schema>;
  pub fn files_schema() -> Arc<arrow::datatypes::Schema>;
  pub fn notice_schema() -> Arc<arrow::datatypes::Schema>;
  pub fn envelope_schema() -> Arc<arrow::datatypes::Schema>;
  ```

**Verified Zeek field names and Arrow types (from docs.zeek.org):**

`conn.log` promoted columns (Arrow types):
- `ts` → `Float64` (nullable: true) — Unix epoch float
- `uid` → `Utf8` (nullable: true)
- `id_orig_h` → `Utf8` (nullable: true) — JSON field name: `id.orig_h`
- `id_orig_p` → `UInt16` (nullable: true) — JSON field name: `id.orig_p`
- `id_resp_h` → `Utf8` (nullable: true) — JSON field name: `id.resp_h`
- `id_resp_p` → `UInt16` (nullable: true) — JSON field name: `id.resp_p`
- `proto` → `Utf8` (nullable: true)
- `service` → `Utf8` (nullable: true)
- `duration` → `Float64` (nullable: true)
- `orig_bytes` → `UInt64` (nullable: true)
- `resp_bytes` → `UInt64` (nullable: true)
- `conn_state` → `Utf8` (nullable: true)
- `history` → `Utf8` (nullable: true)
- `orig_pkts` → `UInt64` (nullable: true)
- `resp_pkts` → `UInt64` (nullable: true)
- `_extra` → `Utf8` (nullable: false) — JSON object of all non-promoted fields

Note: `id.orig_h` etc. use dot notation in Zeek JSON; Arrow column name uses underscore: `id_orig_h`.

`dns.log` promoted columns:
- `ts` → `Float64` (nullable: true)
- `uid` → `Utf8` (nullable: true)
- `id_orig_h` → `Utf8` (nullable: true)
- `id_orig_p` → `UInt16` (nullable: true)
- `id_resp_h` → `Utf8` (nullable: true)
- `id_resp_p` → `UInt16` (nullable: true)
- `proto` → `Utf8` (nullable: true)
- `trans_id` → `UInt32` (nullable: true) — DNS transaction ID (0–65535, stored as u32)
- `query` → `Utf8` (nullable: true)
- `qtype_name` → `Utf8` (nullable: true)
- `qclass_name` → `Utf8` (nullable: true)
- `rcode_name` → `Utf8` (nullable: true)
- `answers` → `Utf8` (nullable: true) — JSON-encoded array
- `_extra` → `Utf8` (nullable: false)

`http.log` promoted columns:
- `ts` → `Float64` (nullable: true)
- `uid` → `Utf8` (nullable: true)
- `id_orig_h` → `Utf8` (nullable: true)
- `id_orig_p` → `UInt16` (nullable: true)
- `id_resp_h` → `Utf8` (nullable: true)
- `id_resp_p` → `UInt16` (nullable: true)
- `method` → `Utf8` (nullable: true)
- `host` → `Utf8` (nullable: true)
- `uri` → `Utf8` (nullable: true)
- `status_code` → `UInt16` (nullable: true)
- `user_agent` → `Utf8` (nullable: true)
- `request_body_len` → `UInt64` (nullable: true)
- `response_body_len` → `UInt64` (nullable: true)
- `_extra` → `Utf8` (nullable: false)

`ssl.log` promoted columns:
- `ts` → `Float64` (nullable: true)
- `uid` → `Utf8` (nullable: true)
- `id_orig_h` → `Utf8` (nullable: true)
- `id_orig_p` → `UInt16` (nullable: true)
- `id_resp_h` → `Utf8` (nullable: true)
- `id_resp_p` → `UInt16` (nullable: true)
- `version` → `Utf8` (nullable: true)
- `cipher` → `Utf8` (nullable: true)
- `curve` → `Utf8` (nullable: true)
- `server_name` → `Utf8` (nullable: true)
- `validation_status` → `Utf8` (nullable: true)
- `_extra` → `Utf8` (nullable: false)

`files.log` promoted columns:
- `ts` → `Float64` (nullable: true)
- `fuid` → `Utf8` (nullable: true)
- `tx_hosts` → `Utf8` (nullable: true) — JSON-encoded array
- `rx_hosts` → `Utf8` (nullable: true) — JSON-encoded array
- `source` → `Utf8` (nullable: true)
- `mime_type` → `Utf8` (nullable: true)
- `filename` → `Utf8` (nullable: true)
- `total_bytes` → `UInt64` (nullable: true)
- `_extra` → `Utf8` (nullable: false)

`notice.log` promoted columns:
- `ts` → `Float64` (nullable: true)
- `uid` → `Utf8` (nullable: true)
- `id_orig_h` → `Utf8` (nullable: true)
- `id_orig_p` → `UInt16` (nullable: true)
- `id_resp_h` → `Utf8` (nullable: true)
- `id_resp_p` → `UInt16` (nullable: true)
- `note` → `Utf8` (nullable: true)
- `msg` → `Utf8` (nullable: true)
- `sub` → `Utf8` (nullable: true)
- `actions` → `Utf8` (nullable: true) — JSON-encoded array
- `_extra` → `Utf8` (nullable: false)

Generic envelope fallback schema (for unknown `log_path`):
- `ts` → `Float64` (nullable: true)
- `uid` → `Utf8` (nullable: true)
- `id_orig_h` → `Utf8` (nullable: true)
- `id_orig_p` → `UInt16` (nullable: true)
- `id_resp_h` → `Utf8` (nullable: true)
- `id_resp_p` → `UInt16` (nullable: true)
- `log_path` → `Utf8` (nullable: false)
- `ingest_time` → `Utf8` (nullable: false) — ISO 8601 RFC 3339 string
- `payload` → `Utf8` (nullable: false) — full JSON object as string

**Row-mapping rules (best-effort/total):**
1. For each promoted column (except `_extra`), look up the JSON field by name. For `id_orig_h` etc., the JSON key uses dot notation (`id.orig_h`) but the Arrow column uses underscore.
2. If the JSON field is absent → append null.
3. If the JSON field is present but the JSON type does not coerce to the Arrow type → treat as absent (null for that column) AND include the raw field in `_extra`.
4. All JSON fields that were NOT cleanly mapped to a typed column go into `_extra` as a JSON object string. Fields with type mismatch are included in `_extra` under their original key.
5. Never panic; never drop a record.

- [ ] **Step 1: Add `pub mod schema;` to `src/zeek/mod.rs`**

  Add after `pub mod listener;`:
  ```rust
  pub mod schema;
  ```

- [ ] **Step 2: Write the failing tests first (in `src/zeek/schema.rs`)**

  Create `src/zeek/schema.rs` with the full implementation and tests below. Write the full file:

  ```rust
  //! Zeek stream schema registry — typed Arrow schemas for the six curated streams
  //! plus a generic envelope fallback for unmodelled stream types.

  use arrow::array::{
      ArrayRef, Float64Builder, StringBuilder, UInt16Builder, UInt32Builder, UInt64Builder,
  };
  use arrow::datatypes::{DataType, Field, Schema};
  use arrow::record_batch::RecordBatch;
  use std::collections::HashMap;
  use std::sync::{Arc, LazyLock};

  // ---------------------------------------------------------------------------
  // Public types
  // ---------------------------------------------------------------------------

  /// A function that maps one JSON record to a one-row RecordBatch.
  pub type RowMapper =
      Arc<dyn Fn(&serde_json::Value) -> anyhow::Result<RecordBatch> + Send + Sync>;

  /// A schema paired with its row mapper.
  pub struct SchemaEntry {
      pub schema: Arc<Schema>,
      pub mapper: RowMapper,
  }

  // ---------------------------------------------------------------------------
  // Schema definitions
  // ---------------------------------------------------------------------------

  /// `conn.log` Arrow schema.
  /// Note: Zeek JSON uses `id.orig_h` etc.; Arrow column names use `id_orig_h`.
  pub fn conn_schema() -> Arc<Schema> {
      static S: LazyLock<Arc<Schema>> = LazyLock::new(|| {
          Arc::new(Schema::new(vec![
              Field::new("ts", DataType::Float64, true),
              Field::new("uid", DataType::Utf8, true),
              Field::new("id_orig_h", DataType::Utf8, true),
              Field::new("id_orig_p", DataType::UInt16, true),
              Field::new("id_resp_h", DataType::Utf8, true),
              Field::new("id_resp_p", DataType::UInt16, true),
              Field::new("proto", DataType::Utf8, true),
              Field::new("service", DataType::Utf8, true),
              Field::new("duration", DataType::Float64, true),
              Field::new("orig_bytes", DataType::UInt64, true),
              Field::new("resp_bytes", DataType::UInt64, true),
              Field::new("conn_state", DataType::Utf8, true),
              Field::new("history", DataType::Utf8, true),
              Field::new("orig_pkts", DataType::UInt64, true),
              Field::new("resp_pkts", DataType::UInt64, true),
              Field::new("_extra", DataType::Utf8, false),
          ]))
      });
      S.clone()
  }

  /// `dns.log` Arrow schema.
  pub fn dns_schema() -> Arc<Schema> {
      static S: LazyLock<Arc<Schema>> = LazyLock::new(|| {
          Arc::new(Schema::new(vec![
              Field::new("ts", DataType::Float64, true),
              Field::new("uid", DataType::Utf8, true),
              Field::new("id_orig_h", DataType::Utf8, true),
              Field::new("id_orig_p", DataType::UInt16, true),
              Field::new("id_resp_h", DataType::Utf8, true),
              Field::new("id_resp_p", DataType::UInt16, true),
              Field::new("proto", DataType::Utf8, true),
              Field::new("trans_id", DataType::UInt32, true),
              Field::new("query", DataType::Utf8, true),
              Field::new("qtype_name", DataType::Utf8, true),
              Field::new("qclass_name", DataType::Utf8, true),
              Field::new("rcode_name", DataType::Utf8, true),
              Field::new("answers", DataType::Utf8, true),
              Field::new("_extra", DataType::Utf8, false),
          ]))
      });
      S.clone()
  }

  /// `http.log` Arrow schema.
  pub fn http_schema() -> Arc<Schema> {
      static S: LazyLock<Arc<Schema>> = LazyLock::new(|| {
          Arc::new(Schema::new(vec![
              Field::new("ts", DataType::Float64, true),
              Field::new("uid", DataType::Utf8, true),
              Field::new("id_orig_h", DataType::Utf8, true),
              Field::new("id_orig_p", DataType::UInt16, true),
              Field::new("id_resp_h", DataType::Utf8, true),
              Field::new("id_resp_p", DataType::UInt16, true),
              Field::new("method", DataType::Utf8, true),
              Field::new("host", DataType::Utf8, true),
              Field::new("uri", DataType::Utf8, true),
              Field::new("status_code", DataType::UInt16, true),
              Field::new("user_agent", DataType::Utf8, true),
              Field::new("request_body_len", DataType::UInt64, true),
              Field::new("response_body_len", DataType::UInt64, true),
              Field::new("_extra", DataType::Utf8, false),
          ]))
      });
      S.clone()
  }

  /// `ssl.log` Arrow schema.
  pub fn ssl_schema() -> Arc<Schema> {
      static S: LazyLock<Arc<Schema>> = LazyLock::new(|| {
          Arc::new(Schema::new(vec![
              Field::new("ts", DataType::Float64, true),
              Field::new("uid", DataType::Utf8, true),
              Field::new("id_orig_h", DataType::Utf8, true),
              Field::new("id_orig_p", DataType::UInt16, true),
              Field::new("id_resp_h", DataType::Utf8, true),
              Field::new("id_resp_p", DataType::UInt16, true),
              Field::new("version", DataType::Utf8, true),
              Field::new("cipher", DataType::Utf8, true),
              Field::new("curve", DataType::Utf8, true),
              Field::new("server_name", DataType::Utf8, true),
              Field::new("validation_status", DataType::Utf8, true),
              Field::new("_extra", DataType::Utf8, false),
          ]))
      });
      S.clone()
  }

  /// `files.log` Arrow schema.
  pub fn files_schema() -> Arc<Schema> {
      static S: LazyLock<Arc<Schema>> = LazyLock::new(|| {
          Arc::new(Schema::new(vec![
              Field::new("ts", DataType::Float64, true),
              Field::new("fuid", DataType::Utf8, true),
              Field::new("tx_hosts", DataType::Utf8, true),
              Field::new("rx_hosts", DataType::Utf8, true),
              Field::new("source", DataType::Utf8, true),
              Field::new("mime_type", DataType::Utf8, true),
              Field::new("filename", DataType::Utf8, true),
              Field::new("total_bytes", DataType::UInt64, true),
              Field::new("_extra", DataType::Utf8, false),
          ]))
      });
      S.clone()
  }

  /// `notice.log` Arrow schema.
  pub fn notice_schema() -> Arc<Schema> {
      static S: LazyLock<Arc<Schema>> = LazyLock::new(|| {
          Arc::new(Schema::new(vec![
              Field::new("ts", DataType::Float64, true),
              Field::new("uid", DataType::Utf8, true),
              Field::new("id_orig_h", DataType::Utf8, true),
              Field::new("id_orig_p", DataType::UInt16, true),
              Field::new("id_resp_h", DataType::Utf8, true),
              Field::new("id_resp_p", DataType::UInt16, true),
              Field::new("note", DataType::Utf8, true),
              Field::new("msg", DataType::Utf8, true),
              Field::new("sub", DataType::Utf8, true),
              Field::new("actions", DataType::Utf8, true),
              Field::new("_extra", DataType::Utf8, false),
          ]))
      });
      S.clone()
  }

  /// Generic envelope schema for unknown/unmodelled stream types.
  pub fn envelope_schema() -> Arc<Schema> {
      static S: LazyLock<Arc<Schema>> = LazyLock::new(|| {
          Arc::new(Schema::new(vec![
              Field::new("ts", DataType::Float64, true),
              Field::new("uid", DataType::Utf8, true),
              Field::new("id_orig_h", DataType::Utf8, true),
              Field::new("id_orig_p", DataType::UInt16, true),
              Field::new("id_resp_h", DataType::Utf8, true),
              Field::new("id_resp_p", DataType::UInt16, true),
              Field::new("log_path", DataType::Utf8, false),
              Field::new("ingest_time", DataType::Utf8, false),
              Field::new("payload", DataType::Utf8, false),
          ]))
      });
      S.clone()
  }

  // ---------------------------------------------------------------------------
  // Row-mapping helpers
  // ---------------------------------------------------------------------------

  /// Extract a string value from JSON, returning None if absent or wrong type.
  fn json_str(v: &serde_json::Value, key: &str) -> Option<String> {
      v.get(key).and_then(|f| f.as_str()).map(|s| s.to_string())
  }

  /// Extract a float64 value from JSON (accepts number).
  fn json_f64(v: &serde_json::Value, key: &str) -> Option<f64> {
      v.get(key).and_then(|f| f.as_f64())
  }

  /// Extract a u64 value from JSON (accepts non-negative integer).
  fn json_u64(v: &serde_json::Value, key: &str) -> Option<u64> {
      v.get(key).and_then(|f| f.as_u64())
  }

  /// Extract a u16 value from JSON.
  fn json_u16(v: &serde_json::Value, key: &str) -> Option<u16> {
      v.get(key).and_then(|f| f.as_u64()).and_then(|n| u16::try_from(n).ok())
  }

  /// Extract a u32 value from JSON.
  fn json_u32(v: &serde_json::Value, key: &str) -> Option<u32> {
      v.get(key).and_then(|f| f.as_u64()).and_then(|n| u32::try_from(n).ok())
  }

  /// Extract an array-valued field as a JSON string (for tx_hosts, rx_hosts, answers, actions).
  fn json_array_str(v: &serde_json::Value, key: &str) -> Option<String> {
      v.get(key).and_then(|f| {
          if f.is_array() || f.is_string() {
              Some(f.to_string())
          } else {
              None
          }
      })
  }

  /// Build the `_extra` JSON string: all top-level keys in `value` that are NOT in `promoted`,
  /// plus any keys whose values had type mismatches (passed in `mismatch_keys`).
  fn build_extra(
      value: &serde_json::Value,
      promoted: &[&str],
      mismatch_keys: &[&str],
  ) -> String {
      let promoted_set: std::collections::HashSet<&str> = promoted.iter().copied().collect();
      let mut extra = serde_json::Map::new();
      if let Some(obj) = value.as_object() {
          for (k, v) in obj {
              if !promoted_set.contains(k.as_str()) || mismatch_keys.contains(&k.as_str()) {
                  extra.insert(k.clone(), v.clone());
              }
          }
      }
      serde_json::Value::Object(extra).to_string()
  }

  // ---------------------------------------------------------------------------
  // Per-stream row mappers
  // ---------------------------------------------------------------------------

  fn map_conn(value: &serde_json::Value) -> anyhow::Result<RecordBatch> {
      let schema = conn_schema();
      // Promoted JSON keys (Zeek dot-notation for id fields)
      let promoted = &[
          "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
          "proto", "service", "duration", "orig_bytes", "resp_bytes",
          "conn_state", "history", "orig_pkts", "resp_pkts",
      ];

      let mut mismatches: Vec<&str> = Vec::new();

      // Extract each field; record mismatch if present but wrong type.
      let ts = json_f64(value, "ts");
      if value.get("ts").is_some() && ts.is_none() { mismatches.push("ts"); }

      let uid = json_str(value, "uid");
      let id_orig_h = json_str(value, "id.orig_h");
      let id_orig_p = json_u16(value, "id.orig_p");
      if value.get("id.orig_p").is_some() && id_orig_p.is_none() { mismatches.push("id.orig_p"); }
      let id_resp_h = json_str(value, "id.resp_h");
      let id_resp_p = json_u16(value, "id.resp_p");
      if value.get("id.resp_p").is_some() && id_resp_p.is_none() { mismatches.push("id.resp_p"); }
      let proto = json_str(value, "proto");
      let service = json_str(value, "service");
      let duration = json_f64(value, "duration");
      if value.get("duration").is_some() && duration.is_none() { mismatches.push("duration"); }
      let orig_bytes = json_u64(value, "orig_bytes");
      if value.get("orig_bytes").is_some() && orig_bytes.is_none() { mismatches.push("orig_bytes"); }
      let resp_bytes = json_u64(value, "resp_bytes");
      if value.get("resp_bytes").is_some() && resp_bytes.is_none() { mismatches.push("resp_bytes"); }
      let conn_state = json_str(value, "conn_state");
      let history = json_str(value, "history");
      let orig_pkts = json_u64(value, "orig_pkts");
      if value.get("orig_pkts").is_some() && orig_pkts.is_none() { mismatches.push("orig_pkts"); }
      let resp_pkts = json_u64(value, "resp_pkts");
      if value.get("resp_pkts").is_some() && resp_pkts.is_none() { mismatches.push("resp_pkts"); }

      let extra = build_extra(value, promoted, &mismatches);

      let mut b_ts = Float64Builder::new();
      let mut b_uid = StringBuilder::new();
      let mut b_id_orig_h = StringBuilder::new();
      let mut b_id_orig_p = UInt16Builder::new();
      let mut b_id_resp_h = StringBuilder::new();
      let mut b_id_resp_p = UInt16Builder::new();
      let mut b_proto = StringBuilder::new();
      let mut b_service = StringBuilder::new();
      let mut b_duration = Float64Builder::new();
      let mut b_orig_bytes = UInt64Builder::new();
      let mut b_resp_bytes = UInt64Builder::new();
      let mut b_conn_state = StringBuilder::new();
      let mut b_history = StringBuilder::new();
      let mut b_orig_pkts = UInt64Builder::new();
      let mut b_resp_pkts = UInt64Builder::new();
      let mut b_extra = StringBuilder::new();

      b_ts.append_option(ts);
      b_uid.append_option(uid.as_deref());
      b_id_orig_h.append_option(id_orig_h.as_deref());
      b_id_orig_p.append_option(id_orig_p);
      b_id_resp_h.append_option(id_resp_h.as_deref());
      b_id_resp_p.append_option(id_resp_p);
      b_proto.append_option(proto.as_deref());
      b_service.append_option(service.as_deref());
      b_duration.append_option(duration);
      b_orig_bytes.append_option(orig_bytes);
      b_resp_bytes.append_option(resp_bytes);
      b_conn_state.append_option(conn_state.as_deref());
      b_history.append_option(history.as_deref());
      b_orig_pkts.append_option(orig_pkts);
      b_resp_pkts.append_option(resp_pkts);
      b_extra.append_value(&extra);

      let columns: Vec<ArrayRef> = vec![
          Arc::new(b_ts.finish()),
          Arc::new(b_uid.finish()),
          Arc::new(b_id_orig_h.finish()),
          Arc::new(b_id_orig_p.finish()),
          Arc::new(b_id_resp_h.finish()),
          Arc::new(b_id_resp_p.finish()),
          Arc::new(b_proto.finish()),
          Arc::new(b_service.finish()),
          Arc::new(b_duration.finish()),
          Arc::new(b_orig_bytes.finish()),
          Arc::new(b_resp_bytes.finish()),
          Arc::new(b_conn_state.finish()),
          Arc::new(b_history.finish()),
          Arc::new(b_orig_pkts.finish()),
          Arc::new(b_resp_pkts.finish()),
          Arc::new(b_extra.finish()),
      ];
      Ok(RecordBatch::try_new(schema, columns)?)
  }

  fn map_dns(value: &serde_json::Value) -> anyhow::Result<RecordBatch> {
      let schema = dns_schema();
      let promoted = &[
          "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
          "proto", "trans_id", "query", "qtype_name", "qclass_name", "rcode_name", "answers",
      ];
      let mut mismatches: Vec<&str> = Vec::new();

      let ts = json_f64(value, "ts");
      if value.get("ts").is_some() && ts.is_none() { mismatches.push("ts"); }
      let uid = json_str(value, "uid");
      let id_orig_h = json_str(value, "id.orig_h");
      let id_orig_p = json_u16(value, "id.orig_p");
      if value.get("id.orig_p").is_some() && id_orig_p.is_none() { mismatches.push("id.orig_p"); }
      let id_resp_h = json_str(value, "id.resp_h");
      let id_resp_p = json_u16(value, "id.resp_p");
      if value.get("id.resp_p").is_some() && id_resp_p.is_none() { mismatches.push("id.resp_p"); }
      let proto = json_str(value, "proto");
      let trans_id = json_u32(value, "trans_id");
      if value.get("trans_id").is_some() && trans_id.is_none() { mismatches.push("trans_id"); }
      let query = json_str(value, "query");
      let qtype_name = json_str(value, "qtype_name");
      let qclass_name = json_str(value, "qclass_name");
      let rcode_name = json_str(value, "rcode_name");
      let answers = json_array_str(value, "answers");
      if value.get("answers").is_some() && answers.is_none() { mismatches.push("answers"); }

      let extra = build_extra(value, promoted, &mismatches);

      let mut b_ts = Float64Builder::new();
      let mut b_uid = StringBuilder::new();
      let mut b_id_orig_h = StringBuilder::new();
      let mut b_id_orig_p = UInt16Builder::new();
      let mut b_id_resp_h = StringBuilder::new();
      let mut b_id_resp_p = UInt16Builder::new();
      let mut b_proto = StringBuilder::new();
      let mut b_trans_id = UInt32Builder::new();
      let mut b_query = StringBuilder::new();
      let mut b_qtype_name = StringBuilder::new();
      let mut b_qclass_name = StringBuilder::new();
      let mut b_rcode_name = StringBuilder::new();
      let mut b_answers = StringBuilder::new();
      let mut b_extra = StringBuilder::new();

      b_ts.append_option(ts);
      b_uid.append_option(uid.as_deref());
      b_id_orig_h.append_option(id_orig_h.as_deref());
      b_id_orig_p.append_option(id_orig_p);
      b_id_resp_h.append_option(id_resp_h.as_deref());
      b_id_resp_p.append_option(id_resp_p);
      b_proto.append_option(proto.as_deref());
      b_trans_id.append_option(trans_id);
      b_query.append_option(query.as_deref());
      b_qtype_name.append_option(qtype_name.as_deref());
      b_qclass_name.append_option(qclass_name.as_deref());
      b_rcode_name.append_option(rcode_name.as_deref());
      b_answers.append_option(answers.as_deref());
      b_extra.append_value(&extra);

      let columns: Vec<ArrayRef> = vec![
          Arc::new(b_ts.finish()),
          Arc::new(b_uid.finish()),
          Arc::new(b_id_orig_h.finish()),
          Arc::new(b_id_orig_p.finish()),
          Arc::new(b_id_resp_h.finish()),
          Arc::new(b_id_resp_p.finish()),
          Arc::new(b_proto.finish()),
          Arc::new(b_trans_id.finish()),
          Arc::new(b_query.finish()),
          Arc::new(b_qtype_name.finish()),
          Arc::new(b_qclass_name.finish()),
          Arc::new(b_rcode_name.finish()),
          Arc::new(b_answers.finish()),
          Arc::new(b_extra.finish()),
      ];
      Ok(RecordBatch::try_new(schema, columns)?)
  }

  fn map_http(value: &serde_json::Value) -> anyhow::Result<RecordBatch> {
      let schema = http_schema();
      let promoted = &[
          "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
          "method", "host", "uri", "status_code", "user_agent",
          "request_body_len", "response_body_len",
      ];
      let mut mismatches: Vec<&str> = Vec::new();

      let ts = json_f64(value, "ts");
      if value.get("ts").is_some() && ts.is_none() { mismatches.push("ts"); }
      let uid = json_str(value, "uid");
      let id_orig_h = json_str(value, "id.orig_h");
      let id_orig_p = json_u16(value, "id.orig_p");
      if value.get("id.orig_p").is_some() && id_orig_p.is_none() { mismatches.push("id.orig_p"); }
      let id_resp_h = json_str(value, "id.resp_h");
      let id_resp_p = json_u16(value, "id.resp_p");
      if value.get("id.resp_p").is_some() && id_resp_p.is_none() { mismatches.push("id.resp_p"); }
      let method = json_str(value, "method");
      let host = json_str(value, "host");
      let uri = json_str(value, "uri");
      let status_code = json_u16(value, "status_code");
      if value.get("status_code").is_some() && status_code.is_none() { mismatches.push("status_code"); }
      let user_agent = json_str(value, "user_agent");
      let request_body_len = json_u64(value, "request_body_len");
      if value.get("request_body_len").is_some() && request_body_len.is_none() { mismatches.push("request_body_len"); }
      let response_body_len = json_u64(value, "response_body_len");
      if value.get("response_body_len").is_some() && response_body_len.is_none() { mismatches.push("response_body_len"); }

      let extra = build_extra(value, promoted, &mismatches);

      let mut b_ts = Float64Builder::new();
      let mut b_uid = StringBuilder::new();
      let mut b_id_orig_h = StringBuilder::new();
      let mut b_id_orig_p = UInt16Builder::new();
      let mut b_id_resp_h = StringBuilder::new();
      let mut b_id_resp_p = UInt16Builder::new();
      let mut b_method = StringBuilder::new();
      let mut b_host = StringBuilder::new();
      let mut b_uri = StringBuilder::new();
      let mut b_status_code = UInt16Builder::new();
      let mut b_user_agent = StringBuilder::new();
      let mut b_request_body_len = UInt64Builder::new();
      let mut b_response_body_len = UInt64Builder::new();
      let mut b_extra = StringBuilder::new();

      b_ts.append_option(ts);
      b_uid.append_option(uid.as_deref());
      b_id_orig_h.append_option(id_orig_h.as_deref());
      b_id_orig_p.append_option(id_orig_p);
      b_id_resp_h.append_option(id_resp_h.as_deref());
      b_id_resp_p.append_option(id_resp_p);
      b_method.append_option(method.as_deref());
      b_host.append_option(host.as_deref());
      b_uri.append_option(uri.as_deref());
      b_status_code.append_option(status_code);
      b_user_agent.append_option(user_agent.as_deref());
      b_request_body_len.append_option(request_body_len);
      b_response_body_len.append_option(response_body_len);
      b_extra.append_value(&extra);

      let columns: Vec<ArrayRef> = vec![
          Arc::new(b_ts.finish()),
          Arc::new(b_uid.finish()),
          Arc::new(b_id_orig_h.finish()),
          Arc::new(b_id_orig_p.finish()),
          Arc::new(b_id_resp_h.finish()),
          Arc::new(b_id_resp_p.finish()),
          Arc::new(b_method.finish()),
          Arc::new(b_host.finish()),
          Arc::new(b_uri.finish()),
          Arc::new(b_status_code.finish()),
          Arc::new(b_user_agent.finish()),
          Arc::new(b_request_body_len.finish()),
          Arc::new(b_response_body_len.finish()),
          Arc::new(b_extra.finish()),
      ];
      Ok(RecordBatch::try_new(schema, columns)?)
  }

  fn map_ssl(value: &serde_json::Value) -> anyhow::Result<RecordBatch> {
      let schema = ssl_schema();
      let promoted = &[
          "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
          "version", "cipher", "curve", "server_name", "validation_status",
      ];
      let mut mismatches: Vec<&str> = Vec::new();

      let ts = json_f64(value, "ts");
      if value.get("ts").is_some() && ts.is_none() { mismatches.push("ts"); }
      let uid = json_str(value, "uid");
      let id_orig_h = json_str(value, "id.orig_h");
      let id_orig_p = json_u16(value, "id.orig_p");
      if value.get("id.orig_p").is_some() && id_orig_p.is_none() { mismatches.push("id.orig_p"); }
      let id_resp_h = json_str(value, "id.resp_h");
      let id_resp_p = json_u16(value, "id.resp_p");
      if value.get("id.resp_p").is_some() && id_resp_p.is_none() { mismatches.push("id.resp_p"); }
      let version = json_str(value, "version");
      let cipher = json_str(value, "cipher");
      let curve = json_str(value, "curve");
      let server_name = json_str(value, "server_name");
      let validation_status = json_str(value, "validation_status");

      let extra = build_extra(value, promoted, &mismatches);

      let mut b_ts = Float64Builder::new();
      let mut b_uid = StringBuilder::new();
      let mut b_id_orig_h = StringBuilder::new();
      let mut b_id_orig_p = UInt16Builder::new();
      let mut b_id_resp_h = StringBuilder::new();
      let mut b_id_resp_p = UInt16Builder::new();
      let mut b_version = StringBuilder::new();
      let mut b_cipher = StringBuilder::new();
      let mut b_curve = StringBuilder::new();
      let mut b_server_name = StringBuilder::new();
      let mut b_validation_status = StringBuilder::new();
      let mut b_extra = StringBuilder::new();

      b_ts.append_option(ts);
      b_uid.append_option(uid.as_deref());
      b_id_orig_h.append_option(id_orig_h.as_deref());
      b_id_orig_p.append_option(id_orig_p);
      b_id_resp_h.append_option(id_resp_h.as_deref());
      b_id_resp_p.append_option(id_resp_p);
      b_version.append_option(version.as_deref());
      b_cipher.append_option(cipher.as_deref());
      b_curve.append_option(curve.as_deref());
      b_server_name.append_option(server_name.as_deref());
      b_validation_status.append_option(validation_status.as_deref());
      b_extra.append_value(&extra);

      let columns: Vec<ArrayRef> = vec![
          Arc::new(b_ts.finish()),
          Arc::new(b_uid.finish()),
          Arc::new(b_id_orig_h.finish()),
          Arc::new(b_id_orig_p.finish()),
          Arc::new(b_id_resp_h.finish()),
          Arc::new(b_id_resp_p.finish()),
          Arc::new(b_version.finish()),
          Arc::new(b_cipher.finish()),
          Arc::new(b_curve.finish()),
          Arc::new(b_server_name.finish()),
          Arc::new(b_validation_status.finish()),
          Arc::new(b_extra.finish()),
      ];
      Ok(RecordBatch::try_new(schema, columns)?)
  }

  fn map_files(value: &serde_json::Value) -> anyhow::Result<RecordBatch> {
      let schema = files_schema();
      let promoted = &[
          "ts", "fuid", "tx_hosts", "rx_hosts", "source", "mime_type", "filename", "total_bytes",
      ];
      let mut mismatches: Vec<&str> = Vec::new();

      let ts = json_f64(value, "ts");
      if value.get("ts").is_some() && ts.is_none() { mismatches.push("ts"); }
      let fuid = json_str(value, "fuid");
      let tx_hosts = json_array_str(value, "tx_hosts");
      if value.get("tx_hosts").is_some() && tx_hosts.is_none() { mismatches.push("tx_hosts"); }
      let rx_hosts = json_array_str(value, "rx_hosts");
      if value.get("rx_hosts").is_some() && rx_hosts.is_none() { mismatches.push("rx_hosts"); }
      let source = json_str(value, "source");
      let mime_type = json_str(value, "mime_type");
      let filename = json_str(value, "filename");
      let total_bytes = json_u64(value, "total_bytes");
      if value.get("total_bytes").is_some() && total_bytes.is_none() { mismatches.push("total_bytes"); }

      let extra = build_extra(value, promoted, &mismatches);

      let mut b_ts = Float64Builder::new();
      let mut b_fuid = StringBuilder::new();
      let mut b_tx_hosts = StringBuilder::new();
      let mut b_rx_hosts = StringBuilder::new();
      let mut b_source = StringBuilder::new();
      let mut b_mime_type = StringBuilder::new();
      let mut b_filename = StringBuilder::new();
      let mut b_total_bytes = UInt64Builder::new();
      let mut b_extra = StringBuilder::new();

      b_ts.append_option(ts);
      b_fuid.append_option(fuid.as_deref());
      b_tx_hosts.append_option(tx_hosts.as_deref());
      b_rx_hosts.append_option(rx_hosts.as_deref());
      b_source.append_option(source.as_deref());
      b_mime_type.append_option(mime_type.as_deref());
      b_filename.append_option(filename.as_deref());
      b_total_bytes.append_option(total_bytes);
      b_extra.append_value(&extra);

      let columns: Vec<ArrayRef> = vec![
          Arc::new(b_ts.finish()),
          Arc::new(b_fuid.finish()),
          Arc::new(b_tx_hosts.finish()),
          Arc::new(b_rx_hosts.finish()),
          Arc::new(b_source.finish()),
          Arc::new(b_mime_type.finish()),
          Arc::new(b_filename.finish()),
          Arc::new(b_total_bytes.finish()),
          Arc::new(b_extra.finish()),
      ];
      Ok(RecordBatch::try_new(schema, columns)?)
  }

  fn map_notice(value: &serde_json::Value) -> anyhow::Result<RecordBatch> {
      let schema = notice_schema();
      let promoted = &[
          "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
          "note", "msg", "sub", "actions",
      ];
      let mut mismatches: Vec<&str> = Vec::new();

      let ts = json_f64(value, "ts");
      if value.get("ts").is_some() && ts.is_none() { mismatches.push("ts"); }
      let uid = json_str(value, "uid");
      let id_orig_h = json_str(value, "id.orig_h");
      let id_orig_p = json_u16(value, "id.orig_p");
      if value.get("id.orig_p").is_some() && id_orig_p.is_none() { mismatches.push("id.orig_p"); }
      let id_resp_h = json_str(value, "id.resp_h");
      let id_resp_p = json_u16(value, "id.resp_p");
      if value.get("id.resp_p").is_some() && id_resp_p.is_none() { mismatches.push("id.resp_p"); }
      let note = json_str(value, "note");
      let msg = json_str(value, "msg");
      let sub = json_str(value, "sub");
      let actions = json_array_str(value, "actions");
      if value.get("actions").is_some() && actions.is_none() { mismatches.push("actions"); }

      let extra = build_extra(value, promoted, &mismatches);

      let mut b_ts = Float64Builder::new();
      let mut b_uid = StringBuilder::new();
      let mut b_id_orig_h = StringBuilder::new();
      let mut b_id_orig_p = UInt16Builder::new();
      let mut b_id_resp_h = StringBuilder::new();
      let mut b_id_resp_p = UInt16Builder::new();
      let mut b_note = StringBuilder::new();
      let mut b_msg = StringBuilder::new();
      let mut b_sub = StringBuilder::new();
      let mut b_actions = StringBuilder::new();
      let mut b_extra = StringBuilder::new();

      b_ts.append_option(ts);
      b_uid.append_option(uid.as_deref());
      b_id_orig_h.append_option(id_orig_h.as_deref());
      b_id_orig_p.append_option(id_orig_p);
      b_id_resp_h.append_option(id_resp_h.as_deref());
      b_id_resp_p.append_option(id_resp_p);
      b_note.append_option(note.as_deref());
      b_msg.append_option(msg.as_deref());
      b_sub.append_option(sub.as_deref());
      b_actions.append_option(actions.as_deref());
      b_extra.append_value(&extra);

      let columns: Vec<ArrayRef> = vec![
          Arc::new(b_ts.finish()),
          Arc::new(b_uid.finish()),
          Arc::new(b_id_orig_h.finish()),
          Arc::new(b_id_orig_p.finish()),
          Arc::new(b_id_resp_h.finish()),
          Arc::new(b_id_resp_p.finish()),
          Arc::new(b_note.finish()),
          Arc::new(b_msg.finish()),
          Arc::new(b_sub.finish()),
          Arc::new(b_actions.finish()),
          Arc::new(b_extra.finish()),
      ];
      Ok(RecordBatch::try_new(schema, columns)?)
  }

  fn map_envelope(value: &serde_json::Value, log_path: &str) -> anyhow::Result<RecordBatch> {
      let schema = envelope_schema();
      let promoted = &[
          "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
      ];

      let ts = json_f64(value, "ts");
      let uid = json_str(value, "uid");
      let id_orig_h = json_str(value, "id.orig_h");
      let id_orig_p = json_u16(value, "id.orig_p");
      let id_resp_h = json_str(value, "id.resp_h");
      let id_resp_p = json_u16(value, "id.resp_p");
      let ingest_time = chrono::Utc::now().to_rfc3339();
      let payload = value.to_string();

      let mut b_ts = Float64Builder::new();
      let mut b_uid = StringBuilder::new();
      let mut b_id_orig_h = StringBuilder::new();
      let mut b_id_orig_p = UInt16Builder::new();
      let mut b_id_resp_h = StringBuilder::new();
      let mut b_id_resp_p = UInt16Builder::new();
      let mut b_log_path = StringBuilder::new();
      let mut b_ingest_time = StringBuilder::new();
      let mut b_payload = StringBuilder::new();

      b_ts.append_option(ts);
      b_uid.append_option(uid.as_deref());
      b_id_orig_h.append_option(id_orig_h.as_deref());
      b_id_orig_p.append_option(id_orig_p);
      b_id_resp_h.append_option(id_resp_h.as_deref());
      b_id_resp_p.append_option(id_resp_p);
      b_log_path.append_value(log_path);
      b_ingest_time.append_value(&ingest_time);
      b_payload.append_value(&payload);

      let columns: Vec<ArrayRef> = vec![
          Arc::new(b_ts.finish()),
          Arc::new(b_uid.finish()),
          Arc::new(b_id_orig_h.finish()),
          Arc::new(b_id_orig_p.finish()),
          Arc::new(b_id_resp_h.finish()),
          Arc::new(b_id_resp_p.finish()),
          Arc::new(b_log_path.finish()),
          Arc::new(b_ingest_time.finish()),
          Arc::new(b_payload.finish()),
      ];
      Ok(RecordBatch::try_new(schema, columns)?)
  }

  // ---------------------------------------------------------------------------
  // Registry
  // ---------------------------------------------------------------------------

  static REGISTRY: LazyLock<HashMap<&'static str, Arc<SchemaEntry>>> = LazyLock::new(|| {
      let mut m: HashMap<&'static str, Arc<SchemaEntry>> = HashMap::new();

      m.insert("conn", Arc::new(SchemaEntry {
          schema: conn_schema(),
          mapper: Arc::new(|v| map_conn(v)),
      }));
      m.insert("dns", Arc::new(SchemaEntry {
          schema: dns_schema(),
          mapper: Arc::new(|v| map_dns(v)),
      }));
      m.insert("http", Arc::new(SchemaEntry {
          schema: http_schema(),
          mapper: Arc::new(|v| map_http(v)),
      }));
      m.insert("ssl", Arc::new(SchemaEntry {
          schema: ssl_schema(),
          mapper: Arc::new(|v| map_ssl(v)),
      }));
      m.insert("files", Arc::new(SchemaEntry {
          schema: files_schema(),
          mapper: Arc::new(|v| map_files(v)),
      }));
      m.insert("notice", Arc::new(SchemaEntry {
          schema: notice_schema(),
          mapper: Arc::new(|v| map_notice(v)),
      }));
      m
  });

  static ENVELOPE_ENTRY_UNKNOWN: LazyLock<Arc<SchemaEntry>> = LazyLock::new(|| {
      Arc::new(SchemaEntry {
          schema: envelope_schema(),
          mapper: Arc::new(|v| map_envelope(v, "unknown")),
      })
  });

  /// Look up the SchemaEntry for `log_path`. Falls back to the envelope schema for unknown paths.
  /// The envelope mapper always uses the actual `log_path` at call time via a wrapper.
  pub fn get_schema_entry(log_path: &str) -> Arc<SchemaEntry> {
      if let Some(entry) = REGISTRY.get(log_path) {
          return entry.clone();
      }
      // For unknown paths, build a fresh SchemaEntry with the actual log_path captured.
      let path = log_path.to_string();
      Arc::new(SchemaEntry {
          schema: envelope_schema(),
          mapper: Arc::new(move |v| map_envelope(v, &path)),
      })
  }

  // ---------------------------------------------------------------------------
  // Tests
  // ---------------------------------------------------------------------------

  #[cfg(test)]
  mod tests {
      use super::*;
      use arrow::array::{Float64Array, StringArray, UInt16Array, UInt64Array};

      // --- conn schema tests ---

      #[test]
      fn conn_schema_has_correct_fields() {
          let s = conn_schema();
          assert_eq!(s.fields().len(), 16);
          let f = s.field_with_name("ts").unwrap();
          assert_eq!(*f.data_type(), DataType::Float64);
          assert!(f.is_nullable());
          let f = s.field_with_name("_extra").unwrap();
          assert_eq!(*f.data_type(), DataType::Utf8);
          assert!(!f.is_nullable()); // _extra is never null
          s.field_with_name("id_orig_h").expect("id_orig_h must exist");
          s.field_with_name("orig_pkts").expect("orig_pkts must exist");
      }

      #[test]
      fn conn_mapper_extracts_all_typed_fields() {
          let json = serde_json::json!({
              "_path": "conn",
              "ts": 1700000000.123,
              "uid": "CTestConn1",
              "id.orig_h": "10.0.0.1",
              "id.orig_p": 54321,
              "id.resp_h": "93.184.216.34",
              "id.resp_p": 80,
              "proto": "tcp",
              "service": "http",
              "duration": 0.254,
              "orig_bytes": 512,
              "resp_bytes": 4096,
              "conn_state": "SF",
              "history": "ShADadFf",
              "orig_pkts": 10,
              "resp_pkts": 15
          });
          let batch = map_conn(&json).unwrap();
          assert_eq!(batch.num_rows(), 1);
          assert_eq!(batch.num_columns(), 16);

          let uid = batch.column_by_name("uid").unwrap()
              .as_any().downcast_ref::<StringArray>().unwrap();
          assert_eq!(uid.value(0), "CTestConn1");

          let ts = batch.column_by_name("ts").unwrap()
              .as_any().downcast_ref::<Float64Array>().unwrap();
          assert!((ts.value(0) - 1700000000.123).abs() < 0.001);

          let orig_p = batch.column_by_name("id_orig_p").unwrap()
              .as_any().downcast_ref::<UInt16Array>().unwrap();
          assert_eq!(orig_p.value(0), 54321u16);

          let orig_bytes = batch.column_by_name("orig_bytes").unwrap()
              .as_any().downcast_ref::<UInt64Array>().unwrap();
          assert_eq!(orig_bytes.value(0), 512u64);

          // _extra should be empty object (all promoted fields consumed)
          let extra = batch.column_by_name("_extra").unwrap()
              .as_any().downcast_ref::<StringArray>().unwrap();
          let extra_val: serde_json::Value = serde_json::from_str(extra.value(0)).unwrap();
          // _path is not promoted so it appears in _extra
          assert!(extra_val.get("_path").is_some(), "_path should go to _extra");
      }

      #[test]
      fn conn_mapper_null_for_absent_fields() {
          let json = serde_json::json!({"_path": "conn", "uid": "CMinimal"});
          let batch = map_conn(&json).unwrap();
          let ts = batch.column_by_name("ts").unwrap()
              .as_any().downcast_ref::<Float64Array>().unwrap();
          assert!(ts.is_null(0), "absent ts should be null");
          let orig_bytes = batch.column_by_name("orig_bytes").unwrap()
              .as_any().downcast_ref::<UInt64Array>().unwrap();
          assert!(orig_bytes.is_null(0), "absent orig_bytes should be null");
      }

      #[test]
      fn conn_mapper_type_mismatch_goes_to_extra() {
          // orig_bytes is a string instead of number — should go to _extra, column null
          let json = serde_json::json!({
              "_path": "conn",
              "uid": "CMismatch",
              "ts": 1700000000.0,
              "orig_bytes": "not-a-number"
          });
          let batch = map_conn(&json).unwrap();
          let orig_bytes = batch.column_by_name("orig_bytes").unwrap()
              .as_any().downcast_ref::<UInt64Array>().unwrap();
          assert!(orig_bytes.is_null(0), "type-mismatched orig_bytes must be null in typed column");
          let extra = batch.column_by_name("_extra").unwrap()
              .as_any().downcast_ref::<StringArray>().unwrap();
          let extra_val: serde_json::Value = serde_json::from_str(extra.value(0)).unwrap();
          assert!(
              extra_val.get("orig_bytes").is_some(),
              "type-mismatched orig_bytes must appear in _extra"
          );
      }

      // --- dns schema tests ---

      #[test]
      fn dns_schema_has_correct_fields() {
          let s = dns_schema();
          assert_eq!(s.fields().len(), 14);
          s.field_with_name("trans_id").expect("trans_id must exist");
          s.field_with_name("answers").expect("answers must exist");
          let f = s.field_with_name("trans_id").unwrap();
          assert_eq!(*f.data_type(), DataType::UInt32);
      }

      #[test]
      fn dns_mapper_extracts_typed_fields() {
          let json = serde_json::json!({
              "_path": "dns",
              "ts": 1700000100.0,
              "uid": "CDns1",
              "id.orig_h": "192.168.1.100",
              "id.orig_p": 12345,
              "id.resp_h": "8.8.8.8",
              "id.resp_p": 53,
              "proto": "udp",
              "trans_id": 12345,
              "query": "example.com",
              "qtype_name": "A",
              "qclass_name": "C_INTERNET",
              "rcode_name": "NOERROR",
              "answers": ["93.184.216.34"]
          });
          let batch = map_dns(&json).unwrap();
          assert_eq!(batch.num_rows(), 1);
          let query = batch.column_by_name("query").unwrap()
              .as_any().downcast_ref::<StringArray>().unwrap();
          assert_eq!(query.value(0), "example.com");
          let trans_id = batch.column_by_name("trans_id").unwrap()
              .as_any().downcast_ref::<arrow::array::UInt32Array>().unwrap();
          assert_eq!(trans_id.value(0), 12345u32);
          // answers is an array — stored as JSON string
          let answers = batch.column_by_name("answers").unwrap()
              .as_any().downcast_ref::<StringArray>().unwrap();
          assert!(answers.value(0).contains("93.184.216.34"));
      }

      // --- http schema tests ---

      #[test]
      fn http_mapper_extracts_status_code_and_uri() {
          let json = serde_json::json!({
              "_path": "http",
              "ts": 1700000200.0,
              "uid": "CHttpTest",
              "id.orig_h": "10.0.0.5",
              "id.orig_p": 49123,
              "id.resp_h": "1.2.3.4",
              "id.resp_p": 80,
              "method": "GET",
              "host": "example.com",
              "uri": "/index.html",
              "status_code": 200,
              "user_agent": "curl/7.68.0",
              "request_body_len": 0,
              "response_body_len": 4096
          });
          let batch = map_http(&json).unwrap();
          let status = batch.column_by_name("status_code").unwrap()
              .as_any().downcast_ref::<UInt16Array>().unwrap();
          assert_eq!(status.value(0), 200u16);
          let uri = batch.column_by_name("uri").unwrap()
              .as_any().downcast_ref::<StringArray>().unwrap();
          assert_eq!(uri.value(0), "/index.html");
      }

      // --- ssl schema tests ---

      #[test]
      fn ssl_mapper_extracts_server_name_and_cipher() {
          let json = serde_json::json!({
              "_path": "ssl",
              "ts": 1700000300.0,
              "uid": "CSslTest",
              "id.orig_h": "10.0.0.6",
              "id.orig_p": 55001,
              "id.resp_h": "1.2.3.5",
              "id.resp_p": 443,
              "version": "TLSv13",
              "cipher": "TLS_AES_128_GCM_SHA256",
              "curve": "x25519",
              "server_name": "secure.example.com",
              "validation_status": "ok"
          });
          let batch = map_ssl(&json).unwrap();
          let sn = batch.column_by_name("server_name").unwrap()
              .as_any().downcast_ref::<StringArray>().unwrap();
          assert_eq!(sn.value(0), "secure.example.com");
          let cipher = batch.column_by_name("cipher").unwrap()
              .as_any().downcast_ref::<StringArray>().unwrap();
          assert_eq!(cipher.value(0), "TLS_AES_128_GCM_SHA256");
      }

      // --- files schema tests ---

      #[test]
      fn files_mapper_extracts_mime_type_and_total_bytes() {
          let json = serde_json::json!({
              "_path": "files",
              "ts": 1700000400.0,
              "fuid": "FTest001",
              "tx_hosts": ["10.0.0.7"],
              "rx_hosts": ["192.168.0.1"],
              "source": "HTTP",
              "mime_type": "application/pdf",
              "filename": "report.pdf",
              "total_bytes": 102400
          });
          let batch = map_files(&json).unwrap();
          let mime = batch.column_by_name("mime_type").unwrap()
              .as_any().downcast_ref::<StringArray>().unwrap();
          assert_eq!(mime.value(0), "application/pdf");
          let total = batch.column_by_name("total_bytes").unwrap()
              .as_any().downcast_ref::<UInt64Array>().unwrap();
          assert_eq!(total.value(0), 102400u64);
      }

      // --- notice schema tests ---

      #[test]
      fn notice_mapper_extracts_note_and_msg() {
          let json = serde_json::json!({
              "_path": "notice",
              "ts": 1700000500.0,
              "uid": "CNotice1",
              "id.orig_h": "10.0.0.9",
              "id.orig_p": 11111,
              "id.resp_h": "10.0.0.10",
              "id.resp_p": 22,
              "note": "SSH::Password_Guessing",
              "msg": "172.16.0.1 appears to be guessing SSH passwords",
              "sub": "Sampled 1 of 30 attempts",
              "actions": ["Notice::ACTION_LOG"]
          });
          let batch = map_notice(&json).unwrap();
          let note = batch.column_by_name("note").unwrap()
              .as_any().downcast_ref::<StringArray>().unwrap();
          assert_eq!(note.value(0), "SSH::Password_Guessing");
          let actions = batch.column_by_name("actions").unwrap()
              .as_any().downcast_ref::<StringArray>().unwrap();
          assert!(actions.value(0).contains("Notice::ACTION_LOG"));
      }

      // --- envelope fallback ---

      #[test]
      fn unknown_log_path_uses_envelope_schema() {
          let entry = get_schema_entry("weird");
          let json = serde_json::json!({
              "_path": "weird",
              "ts": 1700000600.0,
              "uid": "CWeird1",
              "name": "data_before_established",
              "addl": "extra data"
          });
          let batch = (entry.mapper)(&json).unwrap();
          assert_eq!(batch.num_rows(), 1);
          let payload = batch.column_by_name("payload").unwrap()
              .as_any().downcast_ref::<StringArray>().unwrap();
          let parsed: serde_json::Value = serde_json::from_str(payload.value(0)).unwrap();
          assert_eq!(parsed["uid"], "CWeird1");
          let log_path_col = batch.column_by_name("log_path").unwrap()
              .as_any().downcast_ref::<StringArray>().unwrap();
          assert_eq!(log_path_col.value(0), "weird");
      }

      #[test]
      fn get_schema_entry_returns_typed_for_known_paths() {
          for path in &["conn", "dns", "http", "ssl", "files", "notice"] {
              let entry = get_schema_entry(path);
              // Typed schemas have _extra; envelope schema has payload
              assert!(
                  entry.schema.field_with_name("_extra").is_ok()
                      || entry.schema.field_with_name("payload").is_ok(),
                  "schema for {} must have _extra or payload",
                  path
              );
              let has_extra = entry.schema.field_with_name("_extra").is_ok();
              assert!(has_extra, "typed schema for {} must have _extra column", path);
          }
      }

      // --- Parquet round-trip ---

      #[test]
      fn conn_parquet_round_trip() {
          use bytes::Bytes;
          use parquet::arrow::ArrowWriter;
          use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
          use parquet::basic::{Compression, ZstdLevel};
          use parquet::file::properties::WriterProperties;

          let json = serde_json::json!({
              "_path": "conn",
              "ts": 1700000000.0,
              "uid": "CRoundTrip",
              "id.orig_h": "10.0.0.1",
              "id.orig_p": 12345,
              "id.resp_h": "10.0.0.2",
              "id.resp_p": 443,
              "proto": "tcp",
              "conn_state": "SF",
              "orig_bytes": 1024,
              "resp_bytes": 8192,
          });
          let batch = map_conn(&json).unwrap();
          let schema = conn_schema();

          let props = WriterProperties::builder()
              .set_compression(Compression::ZSTD(ZstdLevel::try_new(3).unwrap()))
              .build();
          let mut buf = Vec::new();
          let mut writer = ArrowWriter::try_new(&mut buf, schema, Some(props)).unwrap();
          writer.write(&batch).unwrap();
          writer.close().unwrap();
          assert!(!buf.is_empty());

          let bytes = Bytes::from(buf);
          let mut reader = ParquetRecordBatchReaderBuilder::try_new(bytes)
              .unwrap().build().unwrap();
          let rb = reader.next().unwrap().unwrap();
          assert_eq!(rb.num_rows(), 1);
          let uid = rb.column_by_name("uid").unwrap()
              .as_any().downcast_ref::<StringArray>().unwrap();
          assert_eq!(uid.value(0), "CRoundTrip");
      }

      #[test]
      fn envelope_parquet_round_trip() {
          use bytes::Bytes;
          use parquet::arrow::ArrowWriter;
          use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

          let json = serde_json::json!({
              "_path": "weird",
              "ts": 1700000700.0,
              "uid": "CEnvRT",
              "weird_field": "some_value"
          });
          let batch = map_envelope(&json, "weird").unwrap();
          let schema = envelope_schema();

          let mut buf = Vec::new();
          let mut writer = ArrowWriter::try_new(&mut buf, schema, None).unwrap();
          writer.write(&batch).unwrap();
          writer.close().unwrap();
          assert!(!buf.is_empty());

          let bytes = Bytes::from(buf);
          let mut reader = ParquetRecordBatchReaderBuilder::try_new(bytes)
              .unwrap().build().unwrap();
          let rb = reader.next().unwrap().unwrap();
          assert_eq!(rb.num_rows(), 1);
          let log_path = rb.column_by_name("log_path").unwrap()
              .as_any().downcast_ref::<StringArray>().unwrap();
          assert_eq!(log_path.value(0), "weird");
      }
  }
  ```

- [ ] **Step 3: Run the tests**

  ```bash
  export PATH="$HOME/.cargo/bin:$PATH" && cargo test -p logthing zeek::schema::tests -- --nocapture
  ```

  Expected: all 15 tests pass.

- [ ] **Step 4: fmt + clippy**

  ```bash
  export PATH="$HOME/.cargo/bin:$PATH" && cargo fmt && cargo clippy -- -D warnings
  ```

- [ ] **Step 5: Commit**

  ```bash
  git add src/zeek/schema.rs src/zeek/mod.rs
  git commit -m "feat: add Zeek typed Arrow schema registry with six curated schemas and envelope fallback"
  ```

---

### Task 6: `src/forwarding/zeek_s3.rs` — `ZeekS3Writer` and `ZeekS3Handler`

**Files:**
- Modify: `src/forwarding/zeek_s3.rs` (replace stub with full implementation)

**Interfaces:**
- Consumes: `ZeekRecord` (Task 1), `get_schema_entry` / `SchemaEntry` (Task 5), `S3Sink::from_connection` / `S3Sink::upload` / `flush_check_interval` (existing `s3_sink.rs`), `ZeekS3Config` (Task 3)
- Produces:
  ```rust
  pub struct ZeekS3WriterConfig {
      pub flush_threshold_bytes: usize,
      pub flush_interval: Duration,
      pub key_prefix: String,         // e.g. "zeek"
      pub max_buffer_rows: usize,
  }
  impl ZeekS3WriterConfig {
      pub fn hard_cap_rows(&self) -> usize { self.max_buffer_rows.saturating_mul(4) }
  }

  pub struct ZeekS3Writer {
      // per log_path buffer: VecDeque<(RecordBatch, est_bytes)> + schema
      ...
  }
  impl ZeekS3Writer {
      pub fn new(config: ZeekS3WriterConfig, sink: Arc<S3Sink>) -> Self;
      pub async fn push_record(&mut self, record: &ZeekRecord) -> anyhow::Result<()>;
      pub async fn flush_all_if_needed(&mut self) -> anyhow::Result<()>;
      pub async fn flush_all(&mut self) -> anyhow::Result<()>;
  }

  pub struct ZeekS3Handler { sender: mpsc::Sender<ZeekRecord> }
  impl ZeekS3Handler {
      pub fn start(config: ZeekS3WriterConfig, sink: Arc<S3Sink>) -> Self;
      pub fn start_with_capacity(config: ZeekS3WriterConfig, sink: Arc<S3Sink>, capacity: usize) -> Self;
  }
  // ZeekS3Handler implements ZeekHandler (from src/zeek/listener.rs)
  ```

- [ ] **Step 1: Write the full implementation in `src/forwarding/zeek_s3.rs`**

  Replace the stub with:

  ```rust
  //! Zeek → S3 Parquet persistence.
  //!
  //! `ZeekS3Writer` maintains a per-`log_path` buffer of Arrow RecordBatches,
  //! each keyed by the stream's schema (typed or envelope fallback from the registry).
  //! It mirrors the hardened `IpfixS3Writer` pattern:
  //! - `VecDeque<BufferedBatch>` per stream with `flush_then_cap` / `drop_oldest_to_cap`.
  //! - S3 key pattern: `{prefix}/{log_path}/year={Y}/month={MM}/day={DD}/{uuid}.parquet`.
  //! - Bounded `mpsc` channel in `ZeekS3Handler`; overflow drops + `zeek_s3_dropped`.

  use crate::forwarding::s3_sink::{S3Sink, flush_check_interval};
  use crate::zeek::ZeekRecord;
  use crate::zeek::schema::get_schema_entry;
  use arrow::datatypes::Schema;
  use arrow::record_batch::RecordBatch;
  use chrono::{Datelike, Utc};
  use parquet::arrow::ArrowWriter;
  use parquet::basic::{Compression, ZstdLevel};
  use parquet::file::properties::WriterProperties;
  use std::collections::{HashMap, VecDeque};
  use std::sync::Arc;
  use std::time::{Duration, Instant};
  use tokio::sync::mpsc;
  use tracing::warn;

  // ---------------------------------------------------------------------------
  // Config
  // ---------------------------------------------------------------------------

  /// Writer configuration (derived from `ZeekS3Config`).
  pub struct ZeekS3WriterConfig {
      pub flush_threshold_bytes: usize,
      pub flush_interval: Duration,
      pub key_prefix: String,
      pub max_buffer_rows: usize,
  }

  impl ZeekS3WriterConfig {
      pub fn hard_cap_rows(&self) -> usize {
          self.max_buffer_rows.saturating_mul(4)
      }
  }

  impl Default for ZeekS3WriterConfig {
      fn default() -> Self {
          Self {
              flush_threshold_bytes: 100 * 1024 * 1024,
              flush_interval: Duration::from_secs(900),
              key_prefix: "zeek".to_string(),
              max_buffer_rows: 100_000,
          }
      }
  }

  // ---------------------------------------------------------------------------
  // Per-stream buffer
  // ---------------------------------------------------------------------------

  struct BufferedBatch {
      batch: RecordBatch,
      est_bytes: usize,
  }

  struct StreamBuffer {
      schema: Arc<Schema>,
      buffer: VecDeque<BufferedBatch>,
      buffer_row_count: usize,
      buffered_bytes: usize,
      last_flush: Instant,
      last_drop_warn: Option<Instant>,
  }

  impl StreamBuffer {
      fn new(schema: Arc<Schema>) -> Self {
          Self {
              schema,
              buffer: VecDeque::new(),
              buffer_row_count: 0,
              buffered_bytes: 0,
              last_flush: Instant::now(),
              last_drop_warn: None,
          }
      }

      fn push(&mut self, batch: RecordBatch, est_bytes: usize) {
          self.buffer_row_count += batch.num_rows();
          self.buffered_bytes += est_bytes;
          self.buffer.push_back(BufferedBatch { batch, est_bytes });
      }

      fn drop_oldest_to_cap(&mut self, cap: usize) {
          let mut dropped_rows: usize = 0;
          while self.buffer_row_count > cap {
              if self.buffer.is_empty() { break; }
              let oldest = self.buffer.pop_front().expect("non-empty");
              let n = oldest.batch.num_rows();
              self.buffer_row_count = self.buffer_row_count.saturating_sub(n);
              self.buffered_bytes = self.buffered_bytes.saturating_sub(oldest.est_bytes);
              dropped_rows += n;
          }
          if dropped_rows > 0 {
              metrics::counter!("zeek_s3_buffer_dropped").increment(dropped_rows as u64);
              let should_warn = self.last_drop_warn
                  .map(|t| t.elapsed().as_secs() >= 30)
                  .unwrap_or(true);
              if should_warn {
                  warn!(
                      dropped_rows,
                      buffer_row_count = self.buffer_row_count,
                      "ZeekS3Writer: S3 upload failing — dropped oldest rows to stay within hard cap"
                  );
                  self.last_drop_warn = Some(Instant::now());
              }
          }
      }
  }

  // ---------------------------------------------------------------------------
  // S3 key builder
  // ---------------------------------------------------------------------------

  pub(crate) fn build_zeek_s3_key(prefix: &str, log_path: &str, now: chrono::DateTime<Utc>) -> String {
      let id = uuid::Uuid::new_v4();
      format!(
          "{}/{}/year={}/month={:02}/day={:02}/{}.parquet",
          prefix,
          log_path,
          now.year(),
          now.month(),
          now.day(),
          id,
      )
  }

  // ---------------------------------------------------------------------------
  // Parquet encoding (accepts any schema)
  // ---------------------------------------------------------------------------

  fn encode_batches(batches: &[RecordBatch], schema: Arc<Schema>) -> anyhow::Result<Vec<u8>> {
      if batches.is_empty() {
          return Ok(Vec::new());
      }
      let props = WriterProperties::builder()
          .set_compression(Compression::ZSTD(ZstdLevel::try_new(3)?))
          .build();
      let mut buf = Vec::new();
      let mut writer = ArrowWriter::try_new(&mut buf, schema, Some(props))?;
      for batch in batches {
          writer.write(batch)?;
      }
      writer.close()?;
      Ok(buf)
  }

  // ---------------------------------------------------------------------------
  // ZeekS3Writer
  // ---------------------------------------------------------------------------

  /// Buffers `ZeekRecord`s per stream as Arrow RecordBatches and flushes to S3.
  pub struct ZeekS3Writer {
      config: ZeekS3WriterConfig,
      sink: Arc<S3Sink>,
      streams: HashMap<String, StreamBuffer>,
  }

  impl ZeekS3Writer {
      pub fn new(config: ZeekS3WriterConfig, sink: Arc<S3Sink>) -> Self {
          Self { config, sink, streams: HashMap::new() }
      }

      /// Push one ZeekRecord: map to RecordBatch, append to per-stream buffer, flush if needed.
      pub async fn push_record(&mut self, record: &ZeekRecord) -> anyhow::Result<()> {
          let entry = get_schema_entry(&record.log_path);
          let batch = match (entry.mapper)(&record.fields) {
              Ok(b) => b,
              Err(e) => {
                  warn!("ZeekS3Writer: row mapper error for '{}': {e}", record.log_path);
                  return Ok(()); // Never drop the connection; just skip this record
              }
          };

          let est_bytes = record.fields.to_string().len() + 128;
          let log_path = record.log_path.clone();
          let stream = self.streams
              .entry(log_path.clone())
              .or_insert_with(|| StreamBuffer::new(entry.schema.clone()));

          stream.push(batch, est_bytes);

          if stream.buffered_bytes >= self.config.flush_threshold_bytes {
              let cap = self.config.hard_cap_rows();
              if let Err(e) = self.flush_stream(&log_path).await {
                  if let Some(s) = self.streams.get_mut(&log_path) {
                      if s.buffer_row_count > cap {
                          s.drop_oldest_to_cap(cap);
                      }
                  }
                  return Err(e);
              }
          }
          Ok(())
      }

      /// Flush all streams whose age or byte threshold is exceeded.
      pub async fn flush_all_if_needed(&mut self) -> anyhow::Result<()> {
          let keys: Vec<String> = self.streams.keys().cloned().collect();
          for key in keys {
              let should_flush = {
                  let s = &self.streams[&key];
                  !s.buffer.is_empty()
                      && (s.last_flush.elapsed() >= self.config.flush_interval
                          || s.buffered_bytes >= self.config.flush_threshold_bytes)
              };
              if should_flush {
                  if let Err(e) = self.flush_stream(&key).await {
                      warn!("ZeekS3Writer: flush_all_if_needed error for '{key}': {e}");
                  }
              }
          }
          Ok(())
      }

      /// Unconditionally flush all streams.
      pub async fn flush_all(&mut self) -> anyhow::Result<()> {
          let keys: Vec<String> = self.streams.keys().cloned().collect();
          for key in keys {
              if let Err(e) = self.flush_stream(&key).await {
                  warn!("ZeekS3Writer: flush_all error for '{key}': {e}");
              }
          }
          Ok(())
      }

      async fn flush_stream(&mut self, log_path: &str) -> anyhow::Result<()> {
          let stream = match self.streams.get_mut(log_path) {
              Some(s) if !s.buffer.is_empty() => s,
              _ => return Ok(()),
          };

          let batches: Vec<RecordBatch> = stream.buffer.iter().map(|b| b.batch.clone()).collect();
          let row_count = stream.buffer_row_count;
          let schema = stream.schema.clone();
          let bytes = encode_batches(&batches, schema)?;
          let key = build_zeek_s3_key(&self.config.key_prefix, log_path, Utc::now());

          match self.sink.upload(&key, bytes).await {
              Ok(()) => {
                  metrics::counter!("zeek_s3_records_written").increment(row_count as u64);
                  metrics::counter!("zeek_s3_uploads").increment(1);
                  let stream = self.streams.get_mut(log_path).unwrap();
                  stream.buffer.clear();
                  stream.buffer_row_count = 0;
                  stream.buffered_bytes = 0;
                  stream.last_flush = Instant::now();
                  Ok(())
              }
              Err(e) => {
                  metrics::counter!("zeek_s3_upload_errors").increment(1);
                  Err(e)
              }
          }
      }

      #[cfg(test)]
      pub(crate) fn stream_row_count(&self, log_path: &str) -> usize {
          self.streams.get(log_path).map(|s| s.buffer_row_count).unwrap_or(0)
      }
  }

  // ---------------------------------------------------------------------------
  // ZeekS3Handler — channel + background writer
  // ---------------------------------------------------------------------------

  pub const ZEEK_S3_CHANNEL_CAPACITY: usize = 256;

  /// `ZeekHandler` implementation that forwards records via a bounded channel to a
  /// background `ZeekS3Writer` task.
  pub struct ZeekS3Handler {
      sender: mpsc::Sender<ZeekRecord>,
  }

  impl ZeekS3Handler {
      pub fn start(config: ZeekS3WriterConfig, sink: Arc<S3Sink>) -> Self {
          Self::start_with_capacity(config, sink, ZEEK_S3_CHANNEL_CAPACITY)
      }

      pub fn start_with_capacity(
          config: ZeekS3WriterConfig,
          sink: Arc<S3Sink>,
          capacity: usize,
      ) -> Self {
          let (tx, mut rx) = mpsc::channel::<ZeekRecord>(capacity);
          let flush_check = flush_check_interval(config.flush_interval);
          tokio::spawn(async move {
              let mut writer = ZeekS3Writer::new(config, sink);
              let mut interval = tokio::time::interval(flush_check);
              loop {
                  tokio::select! {
                      msg = rx.recv() => {
                          match msg {
                              Some(record) => {
                                  if let Err(e) = writer.push_record(&record).await {
                                      warn!("ZeekS3Writer::push_record error: {e}");
                                  }
                              }
                              None => {
                                  if let Err(e) = writer.flush_all().await {
                                      warn!("ZeekS3Writer::flush_all on shutdown: {e}");
                                  }
                                  break;
                              }
                          }
                      }
                      _ = interval.tick() => {
                          if let Err(e) = writer.flush_all_if_needed().await {
                              warn!("ZeekS3Writer::flush_all_if_needed error: {e}");
                          }
                      }
                  }
              }
          });
          Self { sender: tx }
      }
  }

  #[async_trait::async_trait]
  impl crate::zeek::listener::ZeekHandler for ZeekS3Handler {
      async fn handle_record(&self, record: ZeekRecord, source: std::net::SocketAddr) {
          match self.sender.try_send(record) {
              Ok(()) => {}
              Err(_dropped) => {
                  metrics::counter!("zeek_s3_dropped").increment(1);
                  warn!("Zeek S3 channel full; dropped 1 record from {}", source);
              }
          }
      }
  }

  // ---------------------------------------------------------------------------
  // Tests
  // ---------------------------------------------------------------------------

  #[cfg(test)]
  mod tests {
      use super::*;
      use crate::zeek::ZeekRecord;
      use chrono::Utc;

      async fn unreachable_sink() -> Arc<S3Sink> {
          use crate::config::S3ConnectionConfig;
          let conn = S3ConnectionConfig {
              endpoint: "http://127.0.0.1:1".to_string(),
              bucket: "test-bucket".to_string(),
              region: "us-east-1".to_string(),
              access_key: "AKIATEST".to_string(),
              secret_key: "SECRETTEST".to_string(),
          };
          Arc::new(S3Sink::from_connection(&conn).await.expect("constructs"))
      }

      fn make_conn_record(uid: &str) -> ZeekRecord {
          ZeekRecord {
              log_path: "conn".to_string(),
              fields: serde_json::json!({
                  "_path": "conn",
                  "ts": 1700000000.0,
                  "uid": uid,
                  "id.orig_h": "10.0.0.1",
                  "id.orig_p": 12345,
                  "id.resp_h": "10.0.0.2",
                  "id.resp_p": 80,
                  "proto": "tcp",
                  "conn_state": "SF",
                  "orig_bytes": 512,
                  "resp_bytes": 4096,
              }),
              received_at: Utc::now(),
          }
      }

      fn make_dns_record(uid: &str) -> ZeekRecord {
          ZeekRecord {
              log_path: "dns".to_string(),
              fields: serde_json::json!({
                  "_path": "dns",
                  "ts": 1700000100.0,
                  "uid": uid,
                  "id.orig_h": "192.168.1.100",
                  "id.orig_p": 12345,
                  "id.resp_h": "8.8.8.8",
                  "id.resp_p": 53,
                  "query": "example.com",
                  "qtype_name": "A",
                  "rcode_name": "NOERROR",
              }),
              received_at: Utc::now(),
          }
      }

      fn make_unknown_record() -> ZeekRecord {
          ZeekRecord {
              log_path: "unknown".to_string(),
              fields: serde_json::json!({
                  "_path": "unknown",
                  "ts": 1700000200.0,
                  "uid": "CUnk1",
                  "raw_data": "some weird log"
              }),
              received_at: Utc::now(),
          }
      }

      // -- S3 key structure --

      #[test]
      fn zeek_s3_key_has_correct_structure() {
          let now = chrono::DateTime::from_timestamp(1700000000, 0).unwrap();
          let key = build_zeek_s3_key("zeek", "conn", now);
          assert!(key.starts_with("zeek/conn/year="), "key: {key}");
          assert!(key.contains("/month="), "key: {key}");
          assert!(key.contains("/day="), "key: {key}");
          assert!(key.ends_with(".parquet"), "key: {key}");
      }

      // -- Writer accumulates per-stream --

      #[tokio::test]
      async fn writer_accumulates_per_stream_buffers() {
          let sink = unreachable_sink().await;
          let config = ZeekS3WriterConfig {
              flush_threshold_bytes: usize::MAX, // never flush by size
              flush_interval: Duration::from_secs(3600),
              key_prefix: "zeek".to_string(),
              max_buffer_rows: 100_000,
          };
          let mut writer = ZeekS3Writer::new(config, sink);

          writer.push_record(&make_conn_record("C1")).await.ok();
          writer.push_record(&make_conn_record("C2")).await.ok();
          writer.push_record(&make_dns_record("D1")).await.ok();
          writer.push_record(&make_unknown_record()).await.ok();

          assert_eq!(writer.stream_row_count("conn"), 2, "conn buffer should have 2 rows");
          assert_eq!(writer.stream_row_count("dns"), 1, "dns buffer should have 1 row");
          assert_eq!(writer.stream_row_count("unknown"), 1, "unknown buffer should have 1 row");
      }

      // -- Writer bounded under S3 outage --

      #[tokio::test]
      async fn writer_bounded_under_s3_outage() {
          let sink = unreachable_sink().await;
          let max_rows = 2usize;
          let config = ZeekS3WriterConfig {
              flush_threshold_bytes: 1, // force flush on every push
              flush_interval: Duration::from_secs(3600),
              key_prefix: "zeek".to_string(),
              max_buffer_rows: max_rows,
          };
          let hard_cap = config.hard_cap_rows();
          let mut writer = ZeekS3Writer::new(config, sink);

          let total = hard_cap * 3;
          let mut errors = 0usize;
          for i in 0..total {
              let rec = make_conn_record(&format!("C{i}"));
              if writer.push_record(&rec).await.is_err() {
                  errors += 1;
              }
          }
          assert!(errors > 0, "expected flush errors under S3 outage");
          assert!(
              writer.stream_row_count("conn") <= hard_cap,
              "conn buffer must stay at or below hard cap ({hard_cap}), got {}",
              writer.stream_row_count("conn")
          );
      }

      // -- Handler overflow drops and counts --

      #[tokio::test]
      async fn handler_overflow_increments_dropped_counter() {
          use crate::zeek::listener::ZeekHandler;
          use metrics::set_default_local_recorder;
          use metrics_util::CompositeKey;
          use metrics_util::MetricKind;
          use metrics_util::debugging::DebuggingRecorder;
          use std::net::SocketAddr;

          let recorder = DebuggingRecorder::new();
          let snapshotter = recorder.snapshotter();
          let _guard = set_default_local_recorder(&recorder);

          let sink = unreachable_sink().await;
          let config = ZeekS3WriterConfig {
              flush_threshold_bytes: 1,
              flush_interval: Duration::from_secs(3600),
              key_prefix: "zeek".to_string(),
              max_buffer_rows: 1,
          };
          let handler = ZeekS3Handler::start_with_capacity(config, sink, 1);
          tokio::task::yield_now().await;

          let src: SocketAddr = "127.0.0.1:47760".parse().unwrap();
          for i in 0..50usize {
              let rec = make_conn_record(&format!("C{i}"));
              handler.handle_record(rec, src).await;
          }
          tokio::task::yield_now().await;

          let snapshot = snapshotter.snapshot();
          let map = snapshot.into_hashmap();
          let key = CompositeKey::new(
              MetricKind::Counter,
              metrics::Key::from_name("zeek_s3_dropped"),
          );
          let dropped = map.get(&key).map(|(_, _, v)| {
              if let metrics_util::debugging::DebugValue::Counter(c) = v { *c } else { 0 }
          }).unwrap_or(0);
          assert!(dropped >= 1, "expected zeek_s3_dropped >= 1; got {dropped}");
      }

      // -- Integration test (gated on env var) --

      #[tokio::test]
      async fn integration_records_produce_parquet_in_s3() {
          if std::env::var("ZEEK_S3_INTEGRATION_TEST").is_err() {
              eprintln!("skipping; set ZEEK_S3_INTEGRATION_TEST=1 to run against local MinIO");
              return;
          }
          use crate::config::S3ConnectionConfig;
          use crate::zeek::listener::ZeekHandler;

          let bucket = std::env::var("ZEEK_S3_BUCKET")
              .unwrap_or_else(|_| "zeek-test".to_string());
          let conn = S3ConnectionConfig {
              endpoint: "http://localhost:9000".to_string(),
              bucket: bucket.clone(),
              region: "us-east-1".to_string(),
              access_key: "minioadmin".to_string(),
              secret_key: "minioadmin".to_string(),
          };
          let sink = Arc::new(S3Sink::from_connection(&conn).await.expect("S3Sink construct"));
          let config = ZeekS3WriterConfig {
              flush_threshold_bytes: 1,
              flush_interval: Duration::from_secs(1),
              key_prefix: "zeek".to_string(),
              max_buffer_rows: 100_000,
          };
          let handler = ZeekS3Handler::start(config, sink);
          let src: std::net::SocketAddr = "127.0.0.1:47760".parse().unwrap();

          for i in 0..5usize {
              handler.handle_record(make_conn_record(&format!("CInteg{i}")), src).await;
          }
          for i in 0..3usize {
              handler.handle_record(make_dns_record(&format!("DInteg{i}")), src).await;
          }

          tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

          use aws_config::meta::region::RegionProviderChain;
          use aws_credential_types::{Credentials, provider::SharedCredentialsProvider};
          use aws_sdk_s3::Client as S3Client;
          use aws_sdk_s3::config::Builder as S3ConfigBuilder;

          let region = RegionProviderChain::first_try(
              aws_sdk_s3::config::Region::new("us-east-1".to_string())
          );
          let sdk_cfg = aws_config::from_env()
              .region(region)
              .endpoint_url("http://localhost:9000")
              .load().await;
          let creds = SharedCredentialsProvider::new(Credentials::new(
              "minioadmin", "minioadmin", None, None, "test",
          ));
          let s3_cfg = S3ConfigBuilder::from(&sdk_cfg)
              .credentials_provider(creds)
              .force_path_style(true)
              .build();
          let client = S3Client::from_conf(s3_cfg);

          for prefix in &["zeek/conn/", "zeek/dns/"] {
              let resp = client.list_objects_v2()
                  .bucket(&bucket).prefix(*prefix).send().await
                  .expect("list_objects_v2");
              assert!(
                  !resp.contents().is_empty(),
                  "expected >= 1 Parquet object under {prefix}"
              );
          }
      }
  }
  ```

- [ ] **Step 2: Run unit + overflow tests**

  ```bash
  export PATH="$HOME/.cargo/bin:$PATH" && cargo test -p logthing forwarding::zeek_s3::tests -- --nocapture 2>&1 | tail -30
  ```

  Expected: `zeek_s3_key_has_correct_structure`, `writer_accumulates_per_stream_buffers`, `writer_bounded_under_s3_outage`, `handler_overflow_increments_dropped_counter` all pass. Integration test skips.

- [ ] **Step 3: fmt + clippy**

  ```bash
  export PATH="$HOME/.cargo/bin:$PATH" && cargo fmt && cargo clippy -- -D warnings
  ```

- [ ] **Step 4: Commit**

  ```bash
  git add src/forwarding/zeek_s3.rs
  git commit -m "feat: add ZeekS3Writer and ZeekS3Handler with per-stream Parquet buffers"
  ```

---

### Task 7: Update `src/main.rs` — handler selection with `ZeekS3Handler`

**Files:**
- Modify: `src/main.rs` (replace the Phase 1 simplified Zeek spawn with the full handler-selection block)

**Interfaces:**
- Consumes: `ZeekS3Handler::start_with_capacity`, `ZeekS3WriterConfig`, `ZeekConfig`, `ZeekS3Config` (all defined in Phase 1 + Task 6)
- Produces: conditional spawn that selects `ZeekS3Handler` when `[zeek.s3]` is present, falls back to `DefaultZeekHandler` on `S3Sink` failure or absent config

- [ ] **Step 1: Write a config-parse test proving `[zeek.s3]` round-trips through `ZeekS3Handler` selection logic**

  In `src/config/mod.rs` tests add (if not already present):

  ```rust
  #[test]
  fn zeek_s3_config_deserializes_from_toml() {
      let toml_str = r#"
  [zeek]
  enabled = true
  tcp_port = 47760
  [zeek.s3]
  endpoint = "http://minio:9000"
  bucket = "zeek-logs"
  region = "us-east-1"
  access_key = "key"
  secret_key = "secret"
  "#;
      let cfg: Config = toml::from_str(toml_str).expect("parse");
      assert!(cfg.zeek.enabled);
      let s3 = cfg.zeek.s3.expect("s3 present");
      assert_eq!(s3.connection.bucket, "zeek-logs");
      assert_eq!(s3.prefix, "zeek");          // default
      assert_eq!(s3.flush_interval_secs, 900); // default
      assert_eq!(s3.channel_capacity, 256);    // default
  }
  ```

  Run:
  ```bash
  export PATH="$HOME/.cargo/bin:$PATH" && cargo test -p logthing config::tests::zeek_s3_config_deserializes -- --nocapture
  ```
  Expected: PASS.

- [ ] **Step 2: Replace the Phase 1 simplified Zeek spawn in `src/main.rs`**

  Find the block that starts with `// Start Zeek listener if enabled` and replace it entirely with:

  ```rust
  // Start Zeek listener if enabled
  if config.zeek.enabled {
      let zeek_config_clone = config.clone();
      tokio::spawn(async move {
          let listener_config = zeek::listener::ZeekListenerConfig {
              tcp_port: zeek_config_clone.zeek.tcp_port,
              bind_address: zeek_config_clone.zeek.bind_address.clone(),
          };

          let handler: Arc<dyn zeek::listener::ZeekHandler> =
              if let Some(s3_cfg) = zeek_config_clone.zeek.s3.as_ref() {
                  match forwarding::s3_sink::S3Sink::from_connection(&s3_cfg.connection).await {
                      Ok(sink) => {
                          let writer_cfg = forwarding::zeek_s3::ZeekS3WriterConfig {
                              flush_threshold_bytes: s3_cfg.flush_threshold_bytes,
                              flush_interval: std::time::Duration::from_secs(
                                  s3_cfg.flush_interval_secs,
                              ),
                              key_prefix: s3_cfg.prefix.clone(),
                              max_buffer_rows: s3_cfg.max_buffer_rows,
                          };
                          let handler = forwarding::zeek_s3::ZeekS3Handler::start_with_capacity(
                              writer_cfg,
                              Arc::new(sink),
                              s3_cfg.channel_capacity,
                          );
                          Arc::new(handler)
                      }
                      Err(e) => {
                          error!(
                              "Failed to create S3Sink for Zeek persistence, \
                               falling back to DefaultZeekHandler: {e}"
                          );
                          Arc::new(zeek::listener::DefaultZeekHandler)
                      }
                  }
              } else {
                  Arc::new(zeek::listener::DefaultZeekHandler)
              };

          let listener = zeek::listener::ZeekListener::new(listener_config, handler);
          if let Err(e) = listener.start().await {
              error!("Zeek listener error: {}", e);
          }
      });
      info!("Zeek listener started on TCP:{}", config.zeek.tcp_port);
  }
  ```

  Also ensure `use logthing::zeek;` is present in the imports at the top of `main.rs`.

- [ ] **Step 3: Build and run full test suite**

  ```bash
  export PATH="$HOME/.cargo/bin:$PATH" && cargo build 2>&1 | tail -10
  export PATH="$HOME/.cargo/bin:$PATH" && cargo test 2>&1 | tail -20
  ```

  Expected: zero compile errors; all tests pass.

- [ ] **Step 4: fmt + clippy**

  ```bash
  export PATH="$HOME/.cargo/bin:$PATH" && cargo fmt && cargo clippy -- -D warnings
  ```

- [ ] **Step 5: Commit**

  ```bash
  git add src/main.rs src/config/mod.rs
  git commit -m "feat: wire ZeekS3Handler into main.rs handler selection"
  ```

---

### Task 8: E2E harness — `zeek-generator`, `zeek-s3-verifier`, `docker-compose.yml`, and `config/logthing.toml`

**Files:**
- Create: `tests/e2e/simulation-environment/zeek-generator/Dockerfile`
- Create: `tests/e2e/simulation-environment/zeek-generator/entrypoint.py`
- Create: `tests/e2e/simulation-environment/zeek-s3-verifier/Dockerfile`
- Create: `tests/e2e/simulation-environment/zeek-s3-verifier/entrypoint.py`
- Modify: `tests/e2e/simulation-environment/docker-compose.yml` (add `minio-setup` bucket + three new services)
- Modify: `tests/e2e/simulation-environment/config/logthing.toml` (add `[zeek]` and `[zeek.s3]` blocks)
- Modify: `tests/e2e/simulation-environment/run.sh` (add Zeek e2e step)

**Interfaces:**
- Consumes: `ZeekListener` on TCP port 47760, `ZeekS3Writer` writing to S3 under `zeek/conn/`, `zeek/dns/`, `zeek/unknown/`
- Produces: verified Parquet objects with correct schemas for `conn`, `dns`, and `unknown` streams

- [ ] **Step 1: Create `zeek-generator/Dockerfile`**

  ```dockerfile
  FROM python:3.12-slim
  COPY zeek-generator/entrypoint.py /entrypoint.py
  CMD ["python3", "/entrypoint.py"]
  ```

- [ ] **Step 2: Create `zeek-generator/entrypoint.py`**

  ```python
  #!/usr/bin/env python3
  """
  Zeek NDJSON TCP generator for E2E testing.

  Connects to logthing's Zeek TCP listener and streams sample NDJSON records:
  - 5 conn records
  - 3 dns records
  - 2 records from an unmodelled stream ("weird") -> routed to unknown/
  - 1 malformed JSON line (must not crash the server)
  """

  import json
  import os
  import socket
  import time

  ZEEK_HOST = os.environ.get("ZEEK_HOST", "logthing")
  ZEEK_PORT = int(os.environ.get("ZEEK_PORT", "47760"))
  CONNECT_TIMEOUT_SECS = int(os.environ.get("CONNECT_TIMEOUT_SECS", "30"))


  def wait_for_server(host, port, timeout):
      deadline = time.time() + timeout
      while time.time() < deadline:
          try:
              s = socket.create_connection((host, port), timeout=2)
              s.close()
              print(f"Connected to {host}:{port}")
              return
          except OSError:
              time.sleep(1)
      raise SystemExit(f"Could not connect to {host}:{port} within {timeout}s")


  def send_records(host, port):
      conn_records = [
          {"_path": "conn", "ts": 1700000000.0 + i, "uid": f"CConn{i:03d}",
           "id.orig_h": f"10.0.{i}.1", "id.orig_p": 40000 + i,
           "id.resp_h": "93.184.216.34", "id.resp_p": 80,
           "proto": "tcp", "service": "http", "duration": 0.1 + i * 0.01,
           "orig_bytes": 512 + i * 100, "resp_bytes": 4096 + i * 200,
           "conn_state": "SF", "history": "ShADadFf",
           "orig_pkts": 10 + i, "resp_pkts": 15 + i}
          for i in range(5)
      ]
      dns_records = [
          {"_path": "dns", "ts": 1700001000.0 + i, "uid": f"CDns{i:03d}",
           "id.orig_h": "192.168.1.100", "id.orig_p": 12345 + i,
           "id.resp_h": "8.8.8.8", "id.resp_p": 53,
           "proto": "udp", "trans_id": 1000 + i,
           "query": f"host{i}.example.com", "qtype_name": "A",
           "qclass_name": "C_INTERNET", "rcode_name": "NOERROR",
           "answers": [f"1.2.3.{i}"]}
          for i in range(3)
      ]
      weird_records = [
          {"_path": "weird", "ts": 1700002000.0 + i, "uid": f"CWeird{i:03d}",
           "name": "data_before_established", "addl": f"extra_data_{i}"}
          for i in range(2)
      ]
      all_records = conn_records + dns_records + weird_records

      with socket.create_connection((host, port)) as sock:
          f = sock.makefile("wb")
          for rec in all_records:
              line = json.dumps(rec) + "\n"
              f.write(line.encode())
              f.flush()
          # Send one malformed line — server must continue, not crash
          f.write(b"NOT VALID JSON\n")
          f.flush()
          f.close()

      print(f"Sent {len(all_records)} valid records + 1 malformed line to {host}:{port}")
      # Give logthing time to process and flush (flush_threshold_bytes=1 triggers immediately)
      time.sleep(3)
      print("Zeek generator done.")


  if __name__ == "__main__":
      wait_for_server(ZEEK_HOST, ZEEK_PORT, CONNECT_TIMEOUT_SECS)
      send_records(ZEEK_HOST, ZEEK_PORT)
  ```

- [ ] **Step 3: Create `zeek-s3-verifier/Dockerfile`**

  ```dockerfile
  FROM python:3.12-slim

  WORKDIR /app

  RUN pip install --no-cache-dir boto3 pyarrow

  COPY zeek-s3-verifier/entrypoint.py ./entrypoint.py

  ENTRYPOINT ["python3", "entrypoint.py"]
  ```

- [ ] **Step 4: Create `zeek-s3-verifier/entrypoint.py`**

  ```python
  #!/usr/bin/env python3
  """
  Zeek S3 verifier for E2E testing.

  Polls MinIO for Parquet objects under zeek/conn/, zeek/dns/, and zeek/unknown/
  (the "weird" stream routes to unknown/ because "weird" is not a curated path),
  downloads them, and validates schema + row count.
  """

  import io
  import os
  import sys
  import time

  import boto3
  import pyarrow.parquet as pq

  MINIO_ENDPOINT = os.environ.get("MINIO_ENDPOINT", "http://minio:9000")
  BUCKET = os.environ.get("MINIO_BUCKET", "zeek-logs")
  ZEEK_PREFIX = os.environ.get("ZEEK_S3_PREFIX", "zeek/")
  TIMEOUT = int(os.environ.get("E2E_TIMEOUT_SECS", "60"))

  # Expected prefixes and minimum row counts
  EXPECTED_STREAMS = {
      "zeek/conn/": {
          "min_rows": 5,
          "required_columns": ["ts", "uid", "id_orig_h", "id_orig_p",
                                "id_resp_h", "id_resp_p", "proto",
                                "orig_bytes", "conn_state", "_extra"],
      },
      "zeek/dns/": {
          "min_rows": 3,
          "required_columns": ["ts", "uid", "query", "qtype_name",
                                "rcode_name", "_extra"],
      },
      "zeek/unknown/": {
          "min_rows": 2,
          "required_columns": ["ts", "uid", "log_path", "ingest_time", "payload"],
      },
  }


  def make_client():
      session = boto3.session.Session()
      return session.client(
          "s3",
          endpoint_url=MINIO_ENDPOINT,
          aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID"),
          aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY"),
      )


  def wait_for_prefix(client, prefix, timeout):
      deadline = time.time() + timeout
      while time.time() < deadline:
          resp = client.list_objects_v2(Bucket=BUCKET, Prefix=prefix)
          contents = resp.get("Contents", [])
          if contents:
              key = contents[0]["Key"]
              obj = client.get_object(Bucket=BUCKET, Key=key)
              body = obj["Body"].read()
              if len(body) > 0:
                  print(f"Found Parquet object at {key} ({len(body)} bytes)")
                  return key, body
          time.sleep(3)
      raise SystemExit(
          f"No Parquet object found under '{prefix}' in bucket '{BUCKET}' within {timeout}s"
      )


  def verify_stream(prefix, body, spec):
      table = pq.read_table(io.BytesIO(body))
      actual_columns = set(table.schema.names)
      missing = [c for c in spec["required_columns"] if c not in actual_columns]
      if missing:
          print(f"ERROR [{prefix}]: missing columns: {missing}", file=sys.stderr)
          sys.exit(1)
      if table.num_rows < spec["min_rows"]:
          print(
              f"ERROR [{prefix}]: expected >= {spec['min_rows']} rows, got {table.num_rows}",
              file=sys.stderr,
          )
          sys.exit(1)
      print(
          f"OK [{prefix}]: {table.num_rows} row(s), "
          f"{len(actual_columns)} column(s): {sorted(actual_columns)}"
      )


  def main():
      client = make_client()
      for prefix, spec in EXPECTED_STREAMS.items():
          key, body = wait_for_prefix(client, prefix, TIMEOUT)
          verify_stream(prefix, body, spec)
      print("Zeek S3 verifier succeeded")
      sys.stdout.flush()
      sys.stderr.flush()
      os._exit(0)


  if __name__ == "__main__":
      main()
  ```

- [ ] **Step 5: Add Zeek services to `docker-compose.yml`**

  In `tests/e2e/simulation-environment/docker-compose.yml`, add `zeek-logs` bucket creation to the `minio-setup` command. Replace the existing `minio-setup` command line:

  ```yaml
  command: >
    "until mc alias set local http://minio:9000 $$MINIO_ROOT_USER $$MINIO_ROOT_PASSWORD; do sleep 2; done &&
     mc mb --ignore-existing local/wef-events &&
     mc mb --ignore-existing local/ipfix-flows &&
     mc mb --ignore-existing local/zeek-logs"
  ```

  Then add the three new services before the `networks:` section:

  ```yaml
    zeek-generator:
      build:
        context: .
        dockerfile: zeek-generator/Dockerfile
      environment:
        - ZEEK_HOST=logthing
        - ZEEK_PORT=47760
        - CONNECT_TIMEOUT_SECS=30
      depends_on:
        - logthing
      networks:
        - e2e

    zeek-s3-verifier:
      build:
        context: .
        dockerfile: zeek-s3-verifier/Dockerfile
      environment:
        - MINIO_ENDPOINT=http://minio:9000
        - MINIO_BUCKET=zeek-logs
        - AWS_ACCESS_KEY_ID=miniouser
        - AWS_SECRET_ACCESS_KEY=miniopassword
        - ZEEK_S3_PREFIX=zeek/
        - E2E_TIMEOUT_SECS=60
      depends_on:
        - zeek-generator
        - logthing
        - minio-setup
      networks:
        - e2e
  ```

- [ ] **Step 6: Add `[zeek]` and `[zeek.s3]` to `config/logthing.toml`**

  In `tests/e2e/simulation-environment/config/logthing.toml`, add after the `[ipfix.s3]` block:

  ```toml
  [zeek]
  enabled = true
  tcp_port = 47760

  [zeek.s3]
  endpoint   = "http://minio:9000"
  bucket     = "zeek-logs"
  region     = "us-east-1"
  access_key = "miniouser"
  secret_key = "miniopassword"
  prefix     = "zeek"
  flush_threshold_bytes = 1
  flush_interval_secs   = 5
  ```

  Also add `WEF__ZEEK__ENABLED=true` to the `logthing` service environment in `docker-compose.yml` (so env-var override also works), or rely on the `logthing.toml` volume mount — the volume mount is sufficient since the config file already has `enabled = true`.

- [ ] **Step 7: Add Zeek e2e step to `run.sh`**

  In `tests/e2e/simulation-environment/run.sh`, add after the existing IPFIX-related run commands (find the section that runs `ipfix-generator` and `ipfix-s3-verifier`, and add below it):

  ```bash
  echo ""
  echo "========================================"
  echo "Running Zeek NDJSON E2E Tests"
  echo "========================================"
  docker compose -f "$COMPOSE_FILE" run --rm zeek-generator
  docker compose -f "$COMPOSE_FILE" run --rm zeek-s3-verifier
  echo "Zeek E2E Tests Completed Successfully"
  ```

- [ ] **Step 8: Verify the new files are syntactically correct**

  ```bash
  python3 -c "import ast; ast.parse(open('tests/e2e/simulation-environment/zeek-generator/entrypoint.py').read()); print('generator OK')"
  python3 -c "import ast; ast.parse(open('tests/e2e/simulation-environment/zeek-s3-verifier/entrypoint.py').read()); print('verifier OK')"
  ```

  Expected: `generator OK` and `verifier OK`.

- [ ] **Step 9: Run full Rust test suite to confirm no regressions**

  ```bash
  export PATH="$HOME/.cargo/bin:$PATH" && cargo test 2>&1 | tail -10
  ```

  Expected: all tests pass.

- [ ] **Step 10: fmt + clippy**

  ```bash
  export PATH="$HOME/.cargo/bin:$PATH" && cargo fmt && cargo clippy -- -D warnings
  ```

- [ ] **Step 11: Commit**

  ```bash
  git add \
    tests/e2e/simulation-environment/zeek-generator/ \
    tests/e2e/simulation-environment/zeek-s3-verifier/ \
    tests/e2e/simulation-environment/docker-compose.yml \
    tests/e2e/simulation-environment/config/logthing.toml \
    tests/e2e/simulation-environment/run.sh
  git commit -m "feat: add Zeek e2e generator, S3 verifier, and docker-compose wiring"
  ```

---

## Self-Review

### 1. Spec coverage

| Spec requirement | Covered by task |
|---|---|
| TCP plaintext NDJSON listener, one record per line | Task 2 (`ZeekListener`, `handle_tcp_connection`) |
| `_path` extraction; absent/non-string → `"unknown"` | Task 2 (unit tests + listener code) |
| Max line-length cap (16 MiB), skip + count | Task 2 (`ZEEK_MAX_LINE_BYTES`, `zeek_oversized_lines`) |
| `ZeekHandler` trait + `DefaultZeekHandler` | Task 2 |
| `[zeek]` config: enabled=false, tcp_port=47760, bind_address | Task 3 |
| `[zeek.s3]` config: flattened `S3ConnectionConfig` + prefix/flush/buffer/channel | Task 3 |
| Backward-compatible: absent `[zeek.s3]` ⇒ `DefaultZeekHandler` | Task 3 + Task 7 |
| `pub mod zeek;` in `lib.rs`, `pub mod zeek_s3;` in `forwarding/mod.rs` | Task 1 |
| `src/zeek/schema.rs` — six typed schemas with `_extra` + envelope fallback | Task 5 |
| `id.orig_h` dot-notation JSON → `id_orig_h` underscore Arrow column | Task 5 |
| Best-effort/total mapping: absent→null, type-mismatch→`_extra`, never panic | Task 5 (tests: `null_for_absent_fields`, `type_mismatch_goes_to_extra`) |
| Parquet round-trip per schema (conn + envelope tested) | Task 5 |
| `ZeekS3Writer` per-`log_path` buffers with hard cap + `drop_oldest_to_cap` | Task 6 |
| S3 key: `zeek/<log_path>/year=…/month=…/day=…/<uuid>.parquet` | Task 6 (`build_zeek_s3_key`) |
| `ZeekS3Handler` bounded channel, overflow drop + `zeek_s3_dropped` | Task 6 |
| `start_with_capacity` matching ipfix pattern | Task 6 |
| `main.rs` handler selection: ZeekS3Handler / fallback to Default on failure | Task 7 |
| Metrics: `zeek_records_received`, `zeek_parse_errors`, `zeek_oversized_lines`, `zeek_missing_path`, `zeek_records_by_path`, `zeek_s3_records_written`, `zeek_s3_uploads`, `zeek_s3_upload_errors`, `zeek_s3_dropped`, `zeek_s3_buffer_dropped` | Tasks 2, 6 |
| Unit tests: parse, per-schema mapping, Parquet round-trip, fallback | Task 5 |
| Integration tests: TCP listener, ZeekS3Writer per-stream + overflow | Tasks 2, 6 |
| E2E: generator (conn+dns+weird+malformed), verifier (conn/dns/unknown schemas) | Task 8 |

**All spec requirements are covered.**

### 2. Placeholder scan

Searched for "TBD", "TODO", "implement later", "fill in details", "handle errors", "handle edge cases", "similar to Task", "write tests for the above" — none found. Every step contains actual code, exact cargo commands, and specific expected outputs.

### 3. Type/signature consistency

| Symbol | Defined in | Used consistently in |
|---|---|---|
| `ZeekRecord { log_path, fields, received_at }` | Task 1 | Tasks 2, 5, 6, 7 |
| `ZeekHandler::handle_record(&self, ZeekRecord, SocketAddr)` | Task 2 | Tasks 6, 7 |
| `ZeekListenerConfig { tcp_port: u16, bind_address: String }` | Task 2 | Tasks 3, 4, 7 |
| `DefaultZeekHandler` | Task 2 | Tasks 4, 7 |
| `ZeekListener::run_with_listener(TcpListener)` | Task 2 | Task 2 tests |
| `ZeekConfig { enabled, tcp_port, bind_address, s3: Option<ZeekS3Config> }` | Task 3 | Tasks 4, 7 |
| `ZeekS3Config` (flattened `S3ConnectionConfig` + 5 fields) | Task 3 | Task 7 |
| `get_schema_entry(log_path: &str) -> Arc<SchemaEntry>` | Task 5 | Task 6 |
| `SchemaEntry { schema: Arc<Schema>, mapper: RowMapper }` | Task 5 | Task 6 |
| `ZeekS3WriterConfig { flush_threshold_bytes, flush_interval, key_prefix, max_buffer_rows }` | Task 6 | Task 7 |
| `ZeekS3Handler::start_with_capacity(config, sink, capacity)` | Task 6 | Task 7 |
| `build_zeek_s3_key(prefix, log_path, now)` | Task 6 | Task 6 tests |
| Default TCP port **47760** | Tasks 2, 3 | Tasks 7, 8, configs |

All names, types, and signatures are consistent across Phase 1 and Phase 2. No mismatches found.

### 4. Unverified field names

The following Zeek field names could not be independently confirmed from docs.zeek.org search results and are based on widely-cited Zeek JSON output conventions:

- `curve` in `ssl.log` — documented in `base/protocols/ssl/main.zeek` per search results; field exists but exact nullability/type not confirmed in a direct schema table. Used as `Utf8` nullable — safe default.
- `validation_status` in `ssl.log` — documented in SSL main.zeek; field name confirmed.
- `qclass_name` in `dns.log` — standard Zeek DNS log field; search confirmed it alongside `qtype_name`.
- `request_body_len` / `response_body_len` in `http.log` — standard Zeek HTTP log fields; type is `count` (u64) in Zeek, confirmed from http.log documentation.
- `actions` in `notice.log` — documented as a set of `Notice::Action` values serialised to JSON array; stored as `Utf8` (JSON-encoded array string).

No field name used in this plan is believed to be incorrect. If a field is absent from a live Zeek JSON stream, the best-effort/total mapping rules (null for absent, `_extra` capture) handle it without data loss.
